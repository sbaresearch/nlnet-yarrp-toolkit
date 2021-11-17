pub mod loop_storage {
    use crate::structs::{Route, YarrpError, SimpleLoopOutput, ShadowedPreceding, MapSetString};
    use crate::structs::CountingFile;
    use crate::read_lines;
    use std::collections::{HashSet, HashMap};
    use log::{error, info, trace, warn};
    use md5::{Md5, Digest};
    use std::fmt::{Error, Display};
    use itertools::sorted;
    use std::process::exit;
    use std::path::{Path, PathBuf};
    use std::fs::{OpenOptions, File};
    use std::io::Write;
    use itertools::Itertools;
    use std::hash::Hash;
    use crate::traits::IpAddrExt;
    use std::str::FromStr;
    use csv::{Writer, WriterBuilder};

    pub const IDENTIFIERS: &str = "identifiers.id";
    pub const ROUTERS: &str = "routers.id";
    pub const STATS: &str = "stats.csv";
    pub const LOOPS: &str = "loops";
    pub const IMPERILED: &str = "imperiled";
    pub const LOOPS_CSV: &str = "loops.csv";
    pub const SHADOWED_PRECEDING_INFO: &str = "shadowed_preceding.csv";

    pub enum LoopStorageError {
        NothingToHashError,
        ByteWriteError,
    }

    impl LoopStorageError {
        pub fn to_string(&self) -> &str {
            match self {
                LoopStorageError::NothingToHashError => { "NothingToHashError" }
                LoopStorageError::ByteWriteError => { "ByteWriteError" }
            }
        }
    }

    pub struct LoopStorage<T> {
        pub(crate) loop_members: HashMap<String, HashSet<T>>,
        pub(crate) router_identifiers: HashMap<T, HashSet<String>>,
        pub(crate) loop_destination_files: HashMap<String, CountingFile>,
        pub(crate) loop_information: HashMap<(String, String), SimpleLoopOutput>,
        pub(crate) only_full_loops: bool,
        pub(crate) storage_path: String,
        pub(crate) shadowed_storage: Option<Writer<File>>
    }

    impl From<std::fmt::Error> for LoopStorageError {
        fn from(_: Error) -> Self {
            LoopStorageError::ByteWriteError
        }
    }

    fn u8_slice_to_string(slice: &[u8]) -> Result<String, LoopStorageError> {
        let return_string = format!("{:02x}", slice.iter().format(""));
        Ok(return_string)
    }

    impl<T: Display + FromStr + Ord + Copy + Clone + Hash + IpAddrExt> LoopStorage<T> {
        pub fn new(only_full_loops: bool, storage_path: String) -> LoopStorage<T> {
            let mut storage = LoopStorage {
                loop_members: HashMap::new(),                   // loop_identifier -> HashSet of routers
                router_identifiers: HashMap::new(),             // router ip -> HashSet of loop identifiers
                loop_destination_files: HashMap::new(),         // loop_identifier -> File to write to
                loop_information: Default::default(),
                only_full_loops,
                storage_path,
                shadowed_storage: None
            };

            if let Err(_) = storage.read_loop_info_if_available(){
                warn!("Could not read existing loop info file!");
            }

            return storage;
        }

        pub fn create_loop_identifier(routers: &HashSet<T>) -> Result<String, LoopStorageError> {
            if routers.len() == 0 {
                return Err(LoopStorageError::NothingToHashError);
            }

            let sorted_routers = sorted(routers);

            let mut hasher = Md5::new();
            for router in sorted_routers {
                trace!("Got router to hash: {}", router);
                hasher.update(router.ls_octets());
            }

            let result = hasher.finalize();
            let result = u8_slice_to_string(&result)?;
            trace!("Got MD5 {}", result);
            Ok(result)
        }

        pub(crate) fn create_shadowed_preceding_file_if_exists(&mut self) -> Result<(), YarrpError> {
            if self.shadowed_storage.is_none() {
                let writer_path = self.get_storage_file(SHADOWED_PRECEDING_INFO)?;
                let write_header = ! writer_path.exists();

                let file = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(writer_path)?;

                let writer = WriterBuilder::new()
                    .has_headers(write_header)
                    .from_writer(file);

                self.shadowed_storage =  Some(writer);
            }
            Ok(())
        }

        pub fn add_route_information(&mut self, route: &Route<T>) -> Result<(), YarrpError> {
            // if route is not looping, or we are filtering on full loops only return
            if !route.is_looping || (self.only_full_loops && !route.has_full_loop) {
                return Ok(());
            }

            self.create_shadowed_preceding_file_if_exists()?;

            // create identifier
            let identifier;
            let loop_members = route.get_loop_routers();
            let (preceding_router, _preceding_ttl) = route.get_preceding_router_named();

            match LoopStorage::create_loop_identifier(&loop_members) {
                Ok(temp_identifier) => {
                    identifier = temp_identifier;
                }
                Err(x) => {
                    error!("{}", x.to_string());
                    error!("Len of loop_members: {}", loop_members.len());
                    error!("Is Looping: {} ; full loop: {}", route.is_looping, route.has_full_loop);
                    error!("Start: {} ; End: {} ; Len: {}", route.loop_start, route.loop_end, route.loop_len());
                    error!("Could not grab identifier for route to {}", route.destination);
                    return Err(YarrpError::CouldNotParseError);
                }
            }

            let info_key = (identifier.clone(), preceding_router.clone());

            // store loop_identifier -> HashSet of routers
            if !self.loop_members.contains_key(&identifier) {
                self.loop_members.insert(identifier.clone(), loop_members.clone());
            }

            if !self.loop_information.contains_key(&info_key) {
                let loop_info = SimpleLoopOutput::from_route(&identifier, &route)?;
                self.loop_information.insert(info_key.clone(), loop_info);
            }

            if let Some(loop_info) = self.loop_information.get_mut(&info_key) {
                loop_info.shadowed_nets += 1;
            }

            // store router ip -> HashSet of loop identifiers
            for router in loop_members {
                if !self.router_identifiers.contains_key(&router) {
                    self.router_identifiers.insert(router, HashSet::new());
                }

                let router_set;
                if let Some(temp_router_set) = self.router_identifiers.get_mut(&router) {
                    router_set = temp_router_set;
                } else {
                    error!("Could not grab router_set!");
                    continue;
                }
                router_set.insert(identifier.clone());
            }

            // store loop_identifier -> number of destinations stored
            if !self.loop_destination_files.contains_key(&identifier) {
                // grab subpath from storage dir
                let sub_path = self.get_storage_sub_dir("loops")?;
                let sub_path = sub_path.join(format!("{}.dest", identifier));

                if let Some(counting_file) = CountingFile::new(&sub_path) {
                    self.loop_destination_files.insert(identifier.clone(), counting_file);
                } else {
                    exit(1);
                }
            }

            if let Some(counting_file) = self.loop_destination_files.get_mut(&identifier) {
                counting_file.write_ip_line(&route.destination);
            } else {
                error!("Could not write to File for {}", route.destination);
                exit(1);
            }

            if let Some(writer) = self.shadowed_storage.as_mut() {
                let record = ShadowedPreceding{
                    shadowed_net: route.destination.to_string(),
                    preceding_router: preceding_router.clone(),
                    preceding_ttl: _preceding_ttl.clone(),
                    loop_id: identifier.clone()
                };
                writer.serialize(record)?;

            } else {
                error!("Could not write record for shadowed preceding")
            }

            Ok(())
        }

        // read and update the statistics file in the loop output dir
        pub fn update_statistics(&mut self) {
            if let Err(_) = self.update_identifiers() {
                error!("Could not update identifiers");
                exit(1);
            }
            if let Err(_) = self.update_router_hops() {
                error!("Could not update router hops");
                exit(1);
            }

            if let Err(_) = self.store_loop_info() {
                error!("Could not write loop information file!");
                exit(3);
            }
        }

        fn update_identifiers(&self) -> Result<(), YarrpError> {
            info!("Loop Members: {}", self.loop_members.len());
            info!("Loop Destinations: {}", self.loop_destination_files.len());

            let identifiers_file = self.get_storage_file("identifiers.id")?;

            let previous_identifiers = LoopStorage::<T>::read_id_file(&identifiers_file)?;
            let mut total_identifiers = previous_identifiers.len();

            // Only add new loop identifiers, ignore all already found ones
            let mut write_file = OpenOptions::new().append(true).create(true).open(&identifiers_file)?;
            info!("Writing new set of loop identifiers!");

            for (identifier, routers) in &self.loop_members {
                let mut routers_string = String::new();
                if !previous_identifiers.contains_key(identifier) {
                    for hop in routers {
                        routers_string.push_str(&hop.to_string());
                        routers_string.push_str(";");
                    }
                    let formatted_line = format!("{}={}\n", identifier, routers_string);
                    if let Err(_) = write_file.write(formatted_line.as_bytes()) {
                        error!("Error writing file!");
                        exit(1);
                    }
                    total_identifiers += 1;
                }
            }

            info!("Total identifiers after merge: {}", total_identifiers);
            Ok(())
        }

        /// static method to read information from a id file
        pub fn read_id_file(path: &PathBuf) -> Result<MapSetString, YarrpError> {
            let mut return_map: MapSetString = HashMap::new();

            if path.exists() {
                info!("Reading existing identifier file!");
                if let Ok(lines) = read_lines(&path) {
                    for line in lines {
                        if let Ok(str_line) = line {
                            // each line is MD5=router,router,router
                            let split = str_line.split("=").collect::<Vec<&str>>();
                            let identifier = split.get(0).unwrap().to_string();
                            if let Some(values) = split.get(1) {
                                let mut return_values = HashSet::new();

                                for item in values.split(";") {
                                    if item.len() > 0 {
                                        return_values.insert(item.to_owned());
                                    }
                                }
                                return_map.insert(identifier, return_values);
                            } else {
                                error!("Failed reading {}", path.to_str().unwrap());
                                error!("Failed at line {}", str_line);
                                exit(5);
                            }

                        }
                    }
                }
            }
            Ok(return_map)
        }

        /// reads a detail file (e.g. loops destination or imperiled) and returns a T (Ipv4Addr / Ipv6Addr) vector
        pub fn read_details_file_as_t(path: &PathBuf) -> Result<Vec<T>, YarrpError> {
            let mut destinations: Vec<T> = Vec::new();

            let lines = read_lines(path)?;
            for line in lines {
                let addr = line?;
                if let Ok(ip_addr) = T::from_str(&addr) {
                    destinations.push(ip_addr);
                } else {
                    error!("Failed to parse ip address!");
                    return Err(YarrpError::CouldNotParseError);
                }
            }

            Ok(destinations)
        }

        /// reads a detail file (e.g. loops destination or imperiled) and returns a T (Ipv4Addr / Ipv6Addr) vector
        pub fn read_details_file_as_t_ret_set(path: &PathBuf) -> Result<HashSet<T>, YarrpError> {
            let mut destinations: HashSet<T> = HashSet::new();

            let lines = read_lines(path)?;
            for line in lines {
                let addr = line?;
                if let Ok(ip_addr) = T::from_str(&addr) {
                    destinations.insert(ip_addr);
                } else {
                    error!("Failed to parse ip address!");
                    return Err(YarrpError::CouldNotParseError);
                }
            }
            Ok(destinations)
        }

        /// reads a detail file (e.g. loops destination or imperiled) and returns a string vector
        pub fn read_details_file_as_string(path: &PathBuf) -> Result<Vec<String>, YarrpError> {
            let mut destinations: Vec<String> = Vec::new();

            let lines = read_lines(path)?;
            for line in lines {
                let addr = line?;
                destinations.push(addr);
            }

            Ok(destinations)
        }

        pub fn write_id_file(path: &PathBuf, hashmap: &HashMap<String, HashSet<String>>) -> Result<(), YarrpError> {
            let mut write_file = File::create(path.clone())?;
            for (identifier, values) in hashmap {
                let mut identifiers_string = String::new();
                for value in values {
                    identifiers_string.push_str(&value);
                    identifiers_string.push_str(";");
                }

                let formatted_line = format!("{}={}\n", identifier, identifiers_string);
                if let Err(_) = write_file.write(formatted_line.as_bytes()) {
                    error!("Error writing file!");
                    exit(1);
                }
            }

            Ok(())
        }

        /// Merges to_merge into base, modifying base!
        pub fn merge_id_file(base: &mut HashMap<String, HashSet<String>>, to_merge: &HashMap<T, HashSet<String>>) -> Result<(), YarrpError> {
            for (router, identifiers) in to_merge {
                let router_string = router.to_string();
                LoopStorage::<T>::merge_record(base, &router_string, identifiers)?;
            }
            Ok(())
        }

        /// Merges to_merge into base, modifying base!
        pub fn merge_id_file_string(base: &mut HashMap<String, HashSet<String>>, to_merge: &HashMap<String, HashSet<String>>) -> Result<(), YarrpError> {
            for (router, identifiers) in to_merge {
                LoopStorage::<T>::merge_record(base, router, identifiers)?;
            }
            Ok(())
        }

        fn merge_record(base: &mut HashMap<String, HashSet<String>>, router: &String, identifiers: &HashSet<String>) -> Result<(), YarrpError> {
            if base.contains_key(router) {
                // part of it,
                if let Some(temp_identifiers) = base.get_mut(router) {
                    for identifier in identifiers {
                        if identifier.len() > 0 {
                            temp_identifiers.insert(identifier.to_owned());
                        }
                    }
                } else {
                    error!("Could not get writable hashmap!");
                    exit(1);
                }
            } else {
                // not yet part of it
                base.insert(router.to_string(), identifiers.to_owned());
            }

            Ok(())
        }

        pub fn get_storage_sub_dir(&self, path: &str) -> Result<PathBuf, YarrpError> {
            let output_path = self.get_storage_file(path)?;
            if !output_path.exists() {
                if let Some(print_str) = output_path.to_str() {
                    info!("Creating output subdirectory {}", print_str);
                }

                std::fs::create_dir_all(&output_path)?;
            }

            Ok(output_path)
        }

        pub fn get_storage_sub_file(&self, path: &str, file: &str) -> Result<PathBuf, YarrpError> {
            let output_path = self.get_storage_sub_dir(path)?;
            Ok(output_path.join(file))
        }

        pub fn get_storage_file(&self, path: &str) -> Result<PathBuf, YarrpError> {
            let storage_path = Path::new(&self.storage_path);
            if !storage_path.exists() {
                if let Some(print_str) = storage_path.to_str() {
                    info!("Creating output directory {}", print_str);
                }

                std::fs::create_dir_all(&storage_path)?;
            }

            let output_path = storage_path.join(path);
            Ok(output_path)
        }

        fn update_router_hops(&mut self) -> Result<(), YarrpError> {
            let routers_file = self.get_storage_file("routers.id")?;
            info!("Routers: {}", self.router_identifiers.len());

            // read old file
            let mut routers_hashmap = LoopStorage::<T>::read_id_file(&routers_file)?;

            // grab router -> loop identifiers
            // merge new data into
            info!("Merging new found routers with loops into old set!");
            LoopStorage::<T>::merge_id_file(&mut routers_hashmap, &self.router_identifiers)?;

            // overwrite old file
            info!("Writing new routers set!");
            LoopStorage::<T>::write_id_file(&routers_file, &routers_hashmap)?;
            info!("Routers after merge: {}", &routers_hashmap.len());
            Ok(())
        }

        fn read_loop_info_if_available(&mut self) -> Result<(), YarrpError> {
            let path = self.get_storage_file(LOOPS_CSV)?;
            self.loop_information = LoopStorage::<T>::read_loop_info(&path)?;
            info!("Read existing loops.csv file with {} entries!", self.loop_information.len());
            Ok(())
        }

        pub(crate) fn read_loop_info(path: &PathBuf) -> Result<HashMap<(String, String), SimpleLoopOutput>, YarrpError> {
            let mut loop_info = HashMap::new();

            if ! path.exists() {
                info!("No existing loops.csv file!");
            } else {
                let mut csv_reader = csv::Reader::from_path(path)?;
                trace!("csv file has headers: {}", csv_reader.has_headers());
                for record in csv_reader.deserialize() {
                    let record: SimpleLoopOutput = record?;
                    let record_key = (record.loop_id.clone(), record.preceding_router.clone());

                    loop_info.insert(record_key, record);
                }
            }
            return Ok(loop_info);
        }

        fn store_loop_info(&self) -> Result<(), YarrpError> {
            let path = self.get_storage_file(LOOPS_CSV)?;
            let mut csv_writer = csv::Writer::from_path(path)?;

            for (_record_key, record) in &self.loop_information {
                csv_writer.serialize(record)?;
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::net::{Ipv6Addr, Ipv4Addr};
    use log::{LevelFilter};
    use env_logger;
    use crate::analytics::LoopStorage;
    use std::str::FromStr;

    fn init() {
        let _ = env_logger::builder().is_test(true).filter_level(LevelFilter::Trace).try_init();
    }

    #[test]
    fn check_almost_exact_loop_different_id() {
        init();

        let first_id;

        let mut vec = HashSet::new();
        vec.insert(Ipv6Addr::from_str("2001:db8::2").unwrap());
        vec.insert(Ipv6Addr::from_str("2001:db8::1:99").unwrap());

        if let Ok(test) = LoopStorage::create_loop_identifier(&vec) {
            assert_eq!(test.len(), 32);
            first_id = test;
        } else {
            panic!("Should not panic!")
        }

        let mut vec = HashSet::new();
        vec.insert(Ipv6Addr::from_str("2001:db8::3").unwrap());
        vec.insert(Ipv6Addr::from_str("2001:db8::1:99").unwrap());

        if let Ok(test) = LoopStorage::create_loop_identifier(&vec) {
            assert_eq!(test.len(), 32);
            assert_ne!(&test, &first_id);
        } else {
            panic!("Should not panic!")
        }
    }

    #[test]
    fn get_new_loop_identifier() {
        init();
        let mut vec = HashSet::new();
        vec.insert(Ipv6Addr::from_str("2001:db8::2").unwrap());

        if let Ok(test) = LoopStorage::create_loop_identifier(&vec) {
            assert_eq!(test.len(), 32);
        } else {
            panic!("Should not panic!")
        }
    }

    #[test]
    fn get_error_on_empty() {
        init();
        let vec: HashSet<Ipv6Addr> = HashSet::new();

        if let Ok(_) = LoopStorage::create_loop_identifier(&vec) {
            panic!("Should not return a valid identifier");
        } else {}
    }

    #[test]
    fn get_existing_loop_identifier() {
        init();
        let mut vec = HashSet::new();
        vec.insert(Ipv6Addr::from_str("2001:db8::2").unwrap());

        let mut result_set = HashSet::new();

        for _ in 0..10 {
            if let Ok(test) = LoopStorage::create_loop_identifier(&vec) {
                result_set.insert(test);
            } else {
                panic!("Should not error!");
            }
        }
        assert_eq!(result_set.len(), 1, "Set should only contain one value!");
    }

    #[test]
    fn check_if_equals_hardcoded_hash() {
        init();
        let mut vec = HashSet::new();
        vec.insert(Ipv6Addr::from_str("2001:db8::2").unwrap());
        vec.insert(Ipv6Addr::from_str("2001:db8:1111::4").unwrap());
        vec.insert(Ipv6Addr::from_str("2001:db8:abcd:0202::2").unwrap());
        vec.insert(Ipv6Addr::from_str("2001:db8:f919::2").unwrap());

        if let Ok(temp_identifier) = LoopStorage::create_loop_identifier(&vec) {
            assert_eq!(temp_identifier.len(), 32);
            assert_eq!(temp_identifier, "0984a71f1b30970e2481ef5a7555b1b8");
        } else {
            panic!("Should not panic!")
        }
    }

    #[test]
    fn check_if_equals_hardcoded_hash_v4() {
        init();
        let mut vec = HashSet::new();
        vec.insert(Ipv4Addr::from_str("192.168.20.1").unwrap());
        vec.insert(Ipv4Addr::from_str("8.9.10.11").unwrap());
        vec.insert(Ipv4Addr::from_str("172.18.40.2").unwrap());
        vec.insert(Ipv4Addr::from_str("55.33.11.99").unwrap());

        if let Ok(temp_identifier) = LoopStorage::create_loop_identifier(&vec) {
            assert_eq!(temp_identifier.len(), 32);
            assert_eq!(temp_identifier, "c43ffda3e5fb17ec404d0c5af3dabe58");
        } else {
            panic!("Should not panic!")
        }
    }

    #[test]
    fn check_if_order_makes_no_difference() {
        init();
        let mut vec = HashSet::new();
        vec.insert(Ipv6Addr::from_str("2001:db8::2").unwrap());
        vec.insert(Ipv6Addr::from_str("2001:db8:1111::4").unwrap());
        vec.insert(Ipv6Addr::from_str("2001:db8:abcd:0202::2").unwrap());
        vec.insert(Ipv6Addr::from_str("2001:db8:f919::2").unwrap());

        let identifier;

        if let Ok(temp_identifier) = LoopStorage::create_loop_identifier(&vec) {
            assert_eq!(temp_identifier.len(), 32);
            identifier = temp_identifier;
        } else {
            panic!("Should not panic!")
        }

        let mut vec = HashSet::new();
        vec.insert(Ipv6Addr::from_str("2001:db8:f919::2").unwrap());
        vec.insert(Ipv6Addr::from_str("2001:db8:abcd:0202::2").unwrap());
        vec.insert(Ipv6Addr::from_str("2001:db8:1111::4").unwrap());
        vec.insert(Ipv6Addr::from_str("2001:db8::2").unwrap());

        if let Ok(temp_identifier) = LoopStorage::create_loop_identifier(&vec) {
            assert_eq!(temp_identifier.len(), 32);
            assert_eq!(temp_identifier, identifier, "Identifiers are not the same!");
        } else {
            panic!("Should not panic!")
        }
    }


    #[test]
    fn check_if_order_makes_no_difference_v4() {
        init();
        let mut vec = HashSet::new();
        vec.insert(Ipv4Addr::from_str("192.168.20.1").unwrap());
        vec.insert(Ipv4Addr::from_str("8.9.10.11").unwrap());
        vec.insert(Ipv4Addr::from_str("172.18.40.2").unwrap());
        vec.insert(Ipv4Addr::from_str("55.33.11.99").unwrap());

        let identifier;

        if let Ok(temp_identifier) = LoopStorage::create_loop_identifier(&vec) {
            assert_eq!(temp_identifier.len(), 32);
            identifier = temp_identifier;
        } else {
            panic!("Should not panic!")
        }

        let mut vec = HashSet::new();
        vec.insert(Ipv4Addr::from_str("8.9.10.11").unwrap());
        vec.insert(Ipv4Addr::from_str("192.168.20.1").unwrap());
        vec.insert(Ipv4Addr::from_str("55.33.11.99").unwrap());
        vec.insert(Ipv4Addr::from_str("172.18.40.2").unwrap());

        if let Ok(temp_identifier) = LoopStorage::create_loop_identifier(&vec) {
            assert_eq!(temp_identifier.len(), 32);
            assert_eq!(temp_identifier, identifier, "Identifiers are not the same!");
        } else {
            panic!("Should not panic!")
        }
    }

    #[test]
    fn check_full_octets_v6() {
        init();
        let mut vec1 = HashSet::new();
        vec1.insert(Ipv6Addr::from_str("2001:db8:0000:0000:0000:0000:0000:2").unwrap());
        vec1.insert(Ipv6Addr::from_str("2001:db8:1111:0000:0000:0000:0000:4").unwrap());
        vec1.insert(Ipv6Addr::from_str("2001:db8:abcd:0202:0000:0000:0000:2").unwrap());
        vec1.insert(Ipv6Addr::from_str("2001:db8:f919:0000:0000:0000:0000:2").unwrap());

        let mut vec2 = HashSet::new();
        vec2.insert(Ipv6Addr::from_str("2001:db8::2").unwrap());
        vec2.insert(Ipv6Addr::from_str("2001:db8:1111::4").unwrap());
        vec2.insert(Ipv6Addr::from_str("2001:db8:abcd:0202::2").unwrap());
        vec2.insert(Ipv6Addr::from_str("2001:db8:f919::2").unwrap());

        let identifier1;
        let identifier2;

        if let Ok(temp_identifier) = LoopStorage::create_loop_identifier(&vec1) {
            assert_eq!(temp_identifier.len(), 32);
            identifier1 = temp_identifier;
        } else {
            panic!("Should not panic!")
        }

        if let Ok(temp_identifier) = LoopStorage::create_loop_identifier(&vec2) {
            assert_eq!(temp_identifier.len(), 32);
            identifier2 = temp_identifier;
        } else {
            panic!("Should not panic!")
        }

        assert_eq!(identifier1, identifier2);
    }
}