pub mod post_loop_stats_mode {
    use clap::ArgMatches;
    use std::process::exit;
    use log::{error, info, trace, debug};
    use std::collections::{HashMap, HashSet};
    use itertools::{sorted};
    use std::fs::{File};
    use std::hash::Hash;
    use std::fmt::Display;
    use std::str::FromStr;
    use std::io::Write;
    use std::time::SystemTime;

    use crate::modes::{ModeTrait, ModeEnum};
    use crate::structs::{YarrpError, MapSetString, MapSetT, MapVecT, LoopDensityOutput, ASNShadowedResults};
    use crate::traits::IpAddrExt;
    use crate::analytics::{LoopStorage, STATS, LoopStatistics, ASNAttribution};
    use crate::analytics::{ROUTERS, IDENTIFIERS, IMPERILED, LOOPS};
    use std::path::{Path};

    pub struct PostLoopStatsMode<T> {
        pub mode: ModeEnum,
        pub loop_storage: LoopStorage<T>,
        target_file: String,
        target_number: u64,
        target_take_all: bool,
        target_destinations: HashSet<T>,
        loops_with_low_targets: HashMap<u64, u64>,
        print_all_output: bool,
        persistent_loops: HashSet<String>,
        persistent_routers: HashSet<String>,
        pub loop_members: MapSetString,
        pub loop_destinations: MapVecT<T>,
        // <T> needed for target generation, extract that to an additional module?
        pub unique_loop_lengths: HashMap<u8, u64>,
        pub router_loops: MapSetString,
        pub router_shadowed: HashMap<String, u64>,
        pub router_imperiled: MapSetT<T>,
        pub asn_attribution: ASNAttribution,
        asn_to_routers: MapSetString,
        routers_to_asn: MapSetString,
        asn_to_loops: MapSetString,
        loops_to_asn: MapSetString,
        shadowed_to_asn_numbers: ASNShadowedResults,
        num_imperiled: u64,
        skip_densities: bool
    }

    impl<T: 'static + Display + Ord + Copy + Eq + Clone + Hash + IpAddrExt + FromStr> PostLoopStatsMode<T> {
        pub fn new(matches: ArgMatches) -> PostLoopStatsMode<T> {
            let mode = ModeEnum::PostLoopStats;
            let mode_string = mode.to_string().to_lowercase();
            let sub_matches = matches.subcommand_matches(mode_string).unwrap();

            let loop_storage;
            let target_file;
            let target_number: u64;
            let target_take_all: bool;
            let print_all_output: bool;

            if let Some(line) = sub_matches.value_of("project_path") {
                let project_path = line.to_string();
                loop_storage = LoopStorage::new(true, project_path);
            } else {
                error!("Could not read routers parameter!");
                exit(1);
            }

            if let Some(temp_target_file) = sub_matches.value_of("target_list") {
                target_file = temp_target_file.to_string();
            } else {
                debug!("Probably no target_file given!");
                target_file = String::new();
            }

            if sub_matches.occurrences_of("target_take_all") > 0 {
                target_take_all = true;
            } else {
                target_take_all = false;
            }

            if sub_matches.occurrences_of("print_all") > 0 {
                print_all_output = true;
            } else {
                print_all_output = false;
            }

            let skip_densities;
            if sub_matches.occurrences_of("skip_densities") > 0 {
                skip_densities = true;
            } else {
                skip_densities = false;
            }

            if target_file.len() > 0 {
                info!("Target File creation enabled!");
                // if we got a target_file, check if we got a valid target_number, otherwise set it to default
                if let Some(temp_target_number) = sub_matches.value_of("target_number") {
                    if let Ok(temp_target_number) = temp_target_number.parse() {
                        target_number = temp_target_number;
                    } else {
                        error!("Could not parse target_number!");
                        error!("Make sure its a positive integer!");
                        exit(1);
                    }
                } else {
                    // set to default
                    debug!("Setting target_number to default of 5!");
                    target_number = 5;
                }
            } else {
                // no target_file given, using target_number = 0 as flag for do not store
                debug!("Neither a target_file nor target_number given, setting ");
                target_number = 0;
            }

            let routeviews_path;
            if let Some(path) = sub_matches.value_of("routeviews") {
                routeviews_path = path.to_string();
            } else {
                error!("Could not parse routeviews path!");
                exit(1);
            }

            let persistent_loops_path;
            if let Some(path) = sub_matches.value_of("persistent_loops") {
                persistent_loops_path = Path::new(path);
            } else {
                error!("Could not parse persistent_loops path!");
                exit(1);
            }

            let persistent_routers_path;
            if let Some(path) = sub_matches.value_of("persistent_routers") {
                persistent_routers_path = Path::new(path);
            } else {
                error!("Could not parse persistent_routers path!");
                exit(1);
            }

            let mut asn_attribution = ASNAttribution::new(&T::root_net());
            if let Err(_) = asn_attribution.load_routeviews_bgp(&routeviews_path) {
                error!("Could not load BGP data for asn attribution!");
                exit(1);
            }

            let persistent_loops;
            if let Ok(set) = PostLoopStatsMode::<T>::read_persistent_loops(persistent_loops_path) {
                persistent_loops = set;
            } else {
                error!("Could not load persistent loops!");
                exit(1);
            }

            let persistent_routers;
            if let Ok(set) = PostLoopStatsMode::<T>::read_persistent_loops(persistent_routers_path) {
                persistent_routers = set;
            } else {
                error!("Could not load persistent loops!");
                exit(1);
            }

            let shadowed_to_asn_numbers = ASNShadowedResults {
                shadowed_asn_is_with_loop: 0,
                shadowed_asn_is_not_with_loop: 0,
                shadowed_asn_is_unknown: 0,
                shadowed_asn_with_single_asn: 0,
                shadowed_asn_with_multiple_asn: 0
            };

            PostLoopStatsMode {
                mode,
                loop_storage,
                target_file,
                target_number,
                target_take_all,
                target_destinations: HashSet::new(),
                loops_with_low_targets: HashMap::new(),
                print_all_output,
                persistent_loops,
                persistent_routers,
                loop_members: HashMap::new(),
                loop_destinations: HashMap::new(),
                unique_loop_lengths: HashMap::new(),
                router_loops: HashMap::new(),
                router_shadowed: Default::default(),
                router_imperiled: Default::default(),
                asn_attribution,
                asn_to_routers: Default::default(),
                routers_to_asn: Default::default(),
                asn_to_loops: Default::default(),
                loops_to_asn: Default::default(),
                shadowed_to_asn_numbers,
                num_imperiled: 0,
                skip_densities
            }
        }

        fn read_loop_identifiers(&mut self) -> Result<(), YarrpError> {
            info!("Reading loop identifiers from file");
            let loop_file = self.loop_storage.get_storage_file(IDENTIFIERS)?;
            let loop_identifiers = LoopStorage::<T>::read_id_file(&loop_file)?;

            self.loop_members = loop_identifiers;
            for (_identifier, members) in &self.loop_members {
                if members.len() >= 255 {
                    error!("Loop length is above 254, input file might be corrupt or contains error!");
                    exit(1);
                }

                let loop_len = members.len() as u8;
                if !self.unique_loop_lengths.contains_key(&loop_len) {
                    self.unique_loop_lengths.insert(loop_len.clone(), 0);
                }

                if let Some(value) = self.unique_loop_lengths.get_mut(&loop_len) {
                    *value += 1;
                } else {
                    error!("Could not get loop length counter for key {} from hashmap!", loop_len);
                    exit(1);
                }
            }

            Ok(())
        }

        fn read_router_associations(&mut self) -> Result<(), YarrpError> {
            info!("Reading router associations from file");
            let router_file = self.loop_storage.get_storage_file(ROUTERS)?;
            let routers = LoopStorage::<T>::read_id_file(&router_file)?;
            self.router_loops = routers;
            Ok(())
        }

        fn read_loop_destinations(&mut self) -> Result<(), YarrpError> {
            info!("Reading loop destinations!");
            let mut read_files = 0;

            for key in self.loop_members.keys() {
                let filename = format!("{}.dest", key);
                let file_path = self.loop_storage.get_storage_sub_file(LOOPS, &filename)?;

                if !file_path.exists() {
                    error!("File does not exist!");
                    continue;
                }

                let file_path_str;
                if let Some(string) = file_path.to_str() {
                    file_path_str = string;
                } else {
                    file_path_str = "";
                }

                trace!("Trying to read from details file {}", file_path_str);

                if let Ok(lines) = LoopStorage::<T>::read_details_file_as_t(&file_path) {
                    self.loop_destinations.insert(key.clone(), lines);
                } else {
                    error!("Could not read file {}", file_path_str);
                }
                read_files += 1;
            }
            info!("Read {} files from {} directory", read_files, LOOPS);
            Ok(())
        }

        fn read_imperiled_by_router(&mut self) -> Result<(), YarrpError> {
            let mut read_files = 0;
            let mut total_hashset = HashSet::<T>::new();

            let dir_path = &self.loop_storage.get_storage_file(IMPERILED)?;
            if !dir_path.exists() {
                info!("Imperiled sub directory does not exist, skipping imperiled stats!");
            }

            info!("Reading amount of destinations imperiled by a router!");
            for router in self.router_loops.keys() {
                let filename = format!("{}.imp", router);
                let file_path = dir_path.join(&filename);

                if !file_path.exists() {
                    continue;
                }

                let file_path_str;
                if let Some(string) = file_path.to_str() {
                    file_path_str = string;
                } else {
                    file_path_str = "";
                }
                trace!("Trying to read from details file {}", file_path_str);

                if let Ok(lines) = LoopStorage::<T>::read_details_file_as_t_ret_set(&file_path) {
                    total_hashset.extend(&lines);
                    self.router_imperiled.insert(router.clone(), lines);
                } else {
                    error!("Could not read file {}", file_path_str);
                }

                read_files += 1;
            }
            self.num_imperiled = total_hashset.len() as u64;

            info!("Read {} files from {} directory", read_files, IMPERILED);
            info!("Found total number imperiled: {}", self.num_imperiled);
            Ok(())
        }

        fn read_persistent_loops(persistence_path: &Path) -> Result<HashSet<String>, YarrpError> {
            let persistence_path = persistence_path.to_path_buf();
            let persistent_loops = LoopStorage::<T>::read_id_file(&persistence_path)?;
            let mut persistent_loops_set: HashSet<String> = HashSet::new();
            for key in persistent_loops.keys() {
                persistent_loops_set.insert(key.clone());
            }
            Ok(persistent_loops_set)
        }

        fn build_router_shadowed(&mut self) {
            info!("Building Shadowed Routers!");
            for (key, loops) in &self.router_loops {
                let mut shadowed_ips: u64 = 0;

                for loop_id in loops {
                    if let Some(shadowed) = self.loop_destinations.get(loop_id) {
                        shadowed_ips += shadowed.len() as u64;
                    }
                }
                self.router_shadowed.insert(key.clone(), shadowed_ips);
            }
        }

        fn add_targets(&mut self) {
            info!("Starting target creation!");
            let mut prefix_map = HashSet::new();
            let upper_number = self.target_number + 1;
            let test_prefix = 32;

            if self.target_take_all {
                info!("Ignoring target count, selecting all!");
            }

            let mut duplicate_lower = 0;
            let mut duplicate_upper = 0;
            let mut not_added_enough = 0;

            for (_loopid, destinations) in &self.loop_destinations {
                let dest_number = destinations.len() as u64;

                if self.target_take_all {
                    for destination in destinations {

                        // add to prefix check
                        let ip_addr = destination.clone();
                        if let Ok(prefix) = ip_addr.to_network_with_prefix_length(test_prefix) {
                            prefix_map.insert(prefix);
                            self.target_destinations.insert(destination.clone());
                        } else {
                            error!("Could not unwrap IpNet!");
                            exit(1);
                        }
                    }
                } else if dest_number <= self.target_number {
                    if !self.loops_with_low_targets.contains_key(&dest_number) {
                        self.loops_with_low_targets.insert(dest_number.clone(), 0);
                    }

                    if let Some(number) = self.loops_with_low_targets.get_mut(&dest_number) {
                        *number += 1;
                    }

                    for destination in destinations {
                        // add to prefix check
                        let ip_addr = destination.clone();
                        if let Ok(prefix) = ip_addr.to_network_with_prefix_length(test_prefix) {
                            prefix_map.insert(prefix);
                            if !self.target_destinations.insert(destination.clone()) {
                                duplicate_lower += 1;
                            }
                        } else {
                            error!("Could not unwrap IpNet!");
                            exit(1);
                        }
                    }
                } else {
                    if !self.loops_with_low_targets.contains_key(&upper_number) {
                        self.loops_with_low_targets.insert(upper_number.clone(), 0);
                    }

                    if let Some(number) = self.loops_with_low_targets.get_mut(&upper_number) {
                        let mut added = 0;
                        *number += 1;

                        for destination in destinations {
                            let ip_addr = destination.clone();
                            if let Ok(prefix) = ip_addr.to_network_with_prefix_length(test_prefix) {
                                if prefix_map.contains(&prefix) {
                                    continue;
                                } else if added < self.target_number {
                                    added += 1;
                                    prefix_map.insert(prefix.clone());
                                    if !self.target_destinations.insert(destination.clone()) { duplicate_upper += 1; }
                                } else {
                                    break;
                                }
                            } else {
                                error!("Could not unwrap IpNet!");
                                exit(1);
                            }
                        }
                        if added < self.target_number {
                            // need more targets, just add first ones
                            for destination in destinations {
                                if self.target_destinations.insert(destination.clone()) {
                                    added += 1;
                                }

                                if added >= self.target_number {
                                    break;
                                }
                            }
                            if added < 5 {
                                not_added_enough += 1;
                            }
                        }
                    }
                }
            }

            info!("lower {}", duplicate_lower);
            info!("upper {}", duplicate_upper);
            info!("not enough {}", not_added_enough);
        }

        fn load_asn_attribution(&mut self) -> Result<(), YarrpError>{
            let (a2r, r2a) = self.asn_attribution.build_routers_to_asn(&self.router_loops)?;
            self.asn_to_routers = a2r;
            self.routers_to_asn = r2a;

            let (a2l, l2a) = self.asn_attribution.build_loops_to_asn(&self.loop_members, &self.routers_to_asn)?;
            self.asn_to_loops = a2l;
            self.loops_to_asn = l2a;

            let asn_path = self.loop_storage.get_storage_sub_file("asn", "shadowed_asn.csv")?;
            let results = self.asn_attribution.build_shadowed_asn_to_loop(&self.loop_destinations, &self.loops_to_asn, &asn_path)?;
            self.shadowed_to_asn_numbers = results;

            Ok(())
        }

        fn store_targets_to_file(&mut self) {
            if let Ok(mut output_file) = File::create(&self.target_file) {
                for line in &self.target_destinations {
                    let format_string = format!("{}\n", line);
                    if let Err(x) = output_file.write(format_string.as_bytes()) {
                        eprintln!("Could not write to output file!");
                        eprintln!("{}", x);
                        exit(1);
                    }
                }
            } else {
                error!("Could not open or create output file!");
            }
        }

        fn create_total_loops(&self) -> Result<(HashMap<u8, u64>, u64), YarrpError> {
            let mut len_map: HashMap<u8, u64> = HashMap::new();
            let mut total_loops: u64 = 0;

            for (id, destinations) in &self.loop_destinations {
                let num_values = destinations.len() as u64;
                let mut loop_len = 0;
                total_loops += num_values;

                if let Some(members) = self.loop_members.get(id) {
                    loop_len = members.len() as u8;
                } else {
                    error!("Could not retrieve loop members!");
                }

                if !len_map.contains_key(&loop_len) {
                    len_map.insert(loop_len.clone(), 0);
                }

                if let Some(mut_value) = len_map.get_mut(&loop_len) {
                    *mut_value += num_values;
                } else {
                    error!("Could not retrieve value for len map to edit value!");
                }
            }
            Ok((len_map, total_loops))
        }

        fn create_shadowed_density(&self, prefix_edge: u64, octets: usize) -> Result<(), YarrpError> {
            info!("Creating shadowed density!");
            let csv_output = self.loop_storage.get_storage_file("loop_shadowed_density.csv")?;
            let mut writer = csv::Writer::from_path(csv_output)?;

            for (loop_id, shadowed_nets) in &self.loop_destinations {
                let num_nets = shadowed_nets.len() as u64;
                let same_bits = PostLoopStatsMode::<T>::count_bit_overlap_vec(shadowed_nets, prefix_edge, octets)?;
                let storage = PostLoopStatsMode::<T>::create_loop_density_output(&self.persistent_loops, loop_id, num_nets, same_bits, prefix_edge)?;

                writer.serialize(storage)?;
            }
            Ok(())
        }

        fn create_imperiled_density(&self, prefix_edge: u64, octets: usize) -> Result<(), YarrpError> {
            info!("Creating imperiled density!");

            let csv_output = self.loop_storage.get_storage_file("loop_imperiled_density.csv")?;
            let mut writer = csv::Writer::from_path(csv_output)?;

            for (loop_id, routers) in &self.loop_members {
                debug!("Starting for loop {}", loop_id);
                let start = SystemTime::now();

                // grab largest imperiled packet and clone it
                let mut max_imp = 0;
                let mut max_router = "";
                for router in routers {
                    if let Some(router_imperiled) = self.router_imperiled.get(router) {
                        if router_imperiled.len() > max_imp {
                            max_imp = router_imperiled.len();
                            max_router = router;
                        }
                    }
                }

                let mut loop_imperiled;
                if max_router.len() > 0 {
                    if let Some(router_imperiled) = self.router_imperiled.get(max_router) {
                        loop_imperiled = router_imperiled.clone();
                    } else {
                        error!("Could not clone existing router imperiled set!");
                        loop_imperiled = HashSet::new();
                    }
                } else {
                    loop_imperiled = HashSet::new();
                }

                for router in routers {
                    if let Some(router_imperiled) = self.router_imperiled.get(router) {
                        loop_imperiled.extend(router_imperiled);
                    }
                }

                let set_done = SystemTime::now();
                let dur = set_done.duration_since(start)?.as_millis();
                debug!("Found unique imperiled {} for {} in {}", loop_imperiled.len(), loop_id, dur);

                let num_nets = loop_imperiled.len() as u64;
                let same_bits = PostLoopStatsMode::<T>::count_bit_overlap_set(&loop_imperiled, prefix_edge, octets)?;
                let storage = PostLoopStatsMode::<T>::create_loop_density_output(&self.persistent_loops, loop_id, num_nets, same_bits, prefix_edge)?;

                let dens_done = SystemTime::now();
                let dur = dens_done.duration_since(set_done)?.as_millis();
                debug!("Created same bits and density for {} in {}", loop_id, dur);

                writer.serialize(storage)?;
                let write_done = SystemTime::now();
                let dur = write_done.duration_since(dens_done)?.as_millis();
                debug!("Written to disk for loop {} in {}", loop_id, dur);
            }
            Ok(())
        }

        fn create_imperiled_density_by_router(&self, prefix_edge: u64, octets: usize) -> Result<(), YarrpError> {
            info!("Creating imperiled densities by router!");
            let csv_output = self.loop_storage.get_storage_file("router_imperiled_density.csv")?;
            let mut writer = csv::Writer::from_path(csv_output)?;

            for (router, imperiled) in &self.router_imperiled {
                let same_bits = PostLoopStatsMode::<T>::count_bit_overlap_set(imperiled, prefix_edge, octets)?;
                let num_nets = imperiled.len() as u64;

                let dif = prefix_edge - same_bits;
                let density = (num_nets as f64) / 2_i32.pow(dif as u32) as f64;

                let persistent = self.persistent_routers.contains(router);

                let storage = LoopDensityOutput {
                    loop_id: router.to_string(),
                    address_count: num_nets,
                    same_bits,
                    density,
                    persistent
                };
                writer.serialize(storage)?;
            }
            Ok(())
        }

        fn create_loop_density_output(persistent_loops: &HashSet<String>, loop_id: &str, num_nets: u64, same_bits: u64, prefix_edge: u64) -> Result<LoopDensityOutput, YarrpError> {
            let persistent = persistent_loops.contains(loop_id);
            let dif = prefix_edge - same_bits;
            let density = (num_nets as f64) / 2_i32.pow(dif as u32) as f64;

            Ok(LoopDensityOutput {
                loop_id: loop_id.to_string(),
                address_count: num_nets,
                same_bits,
                density,
                persistent,
            })
        }

        fn create_densities(&self) -> Result<(), YarrpError> {
            let prefix_edge;
            let octets;

            match T::is_v4() {
                true => {
                    octets = 4;
                    prefix_edge = 24;
                }
                false => {
                    octets = 16;
                    prefix_edge = 48;
                }
            };

            self.create_shadowed_density(prefix_edge, octets)?;
            self.create_imperiled_density_by_router(prefix_edge, octets)?;
            self.create_imperiled_density(prefix_edge, octets)?;
            Ok(())
        }

        fn count_bit_overlap_int<'a>(mut address_list: impl Iterator<Item=&'a T> + Clone, prefix_edge: u64, octets: usize) -> Result<u64, YarrpError> {
            let base_address;

            if let Some(value) = address_list.next() {
                base_address = value;
            } else {
                error!("Could not get base address!");
                return Err(YarrpError::CouldNotParseError);
            }

            for octet in 0..octets {
                trace!("{}", octet);
                for bit_mask in (0..=7).rev() {
                    trace!("{} / {}", octet, bit_mask);
                    let base_bit = base_address.ls_octets()[octet] & (0x01 << bit_mask);
                    let current_prefix = (octet * 8 + 8 - bit_mask - 1) as u64;

                    // return prefix edge if we are comparing bits above it
                    if current_prefix > prefix_edge {
                        return Ok(prefix_edge);
                    }

                    for address in address_list.clone() {
                        let address_bit = address.ls_octets()[octet] & (0x01 << bit_mask);
                        trace!("{}: Comparing bit {} to base bit {}", address.to_string(), address_bit, base_bit);
                        if address_bit != base_bit {
                            return Ok(current_prefix);
                        }
                    }
                }
            }
            trace!("Returning default!");
            Ok(prefix_edge)
        }

        pub fn count_bit_overlap_set(address_list: &HashSet<T>, prefix_edge: u64, octets: usize) -> Result<u64, YarrpError> {

            // return prefix_edge if the list is less or equal than 1 element
            if address_list.len() <= 1 {
                trace!("Returning du to insufficient elements!");
                return Ok(prefix_edge);
            }

            PostLoopStatsMode::<T>::count_bit_overlap_int(address_list.iter(), prefix_edge, octets)
        }

        pub fn count_bit_overlap_vec(address_list: &Vec<T>, prefix_edge: u64, octets: usize) -> Result<u64, YarrpError> {

            // return prefix_edge if the list is less or equal than 1 element
            if address_list.len() <= 1 {
                trace!("Returning du to insufficient elements!");
                return Ok(prefix_edge);
            }

            PostLoopStatsMode::<T>::count_bit_overlap_int(address_list.iter(), prefix_edge, octets)
        }

        fn print_total_loops(&self) {
            println!("Total Loop Lengths:");
            if let Ok((loops, total_loops)) = self.create_total_loops() {
                PostLoopStatsMode::<T>::print_loops(&loops, &total_loops);
            } else {
                error!("Could not create counting of total loops found!");
            }
        }

        fn print_unique_loops(&self) {
            println!("Unique Loop Lengths:");
            let total = self.loop_members.len() as u64;
            PostLoopStatsMode::<T>::print_loops(&self.unique_loop_lengths, &total);
        }

        fn write_post_loop_stats(&self) -> Result<(), YarrpError> {
            let input_path = self.loop_storage.get_storage_file(STATS)?;
            let input_stats = LoopStatistics::new(true, input_path);

            let path = self.loop_storage.get_storage_file("postloop_stats.csv")?;
            let mut csv_writer = csv::Writer::from_path(path)?;

            if let Err(_) = csv_writer.write_record(&["key", "value"]) {
                error!("Could not write header row for postloop_stats.csv!");
                return Err(YarrpError::CouldNotWriteError);
            }

            let mut routers_imperiled: u64 = 0;

            for (_router, imperiled) in &self.router_imperiled {
                let len_imperiled = imperiled.len();
                if len_imperiled > 0 {
                    routers_imperiled += 1;
                }
            }

            let router_asn = self.asn_to_routers.len() as u64;

            let _ = csv_writer.write_record(&["routes", &input_stats.number_of_routes.to_string()])?;
            let _ = csv_writer.write_record(&["loops", &input_stats.number_of_loops.to_string()])?;
            let _ = csv_writer.write_record(&["full_loops", &input_stats.number_of_full_loops.to_string()])?;
            let _ = csv_writer.write_record(&["unique_routers", &self.router_loops.len().to_string()])?;
            let _ = csv_writer.write_record(&["load_balancers", &input_stats.number_of_load_balancers.to_string()])?;
            let _ = csv_writer.write_record(&["spammers", &input_stats.number_of_spammers.to_string()])?;
            let _ = csv_writer.write_record(&["imperiled", &self.num_imperiled.to_string()])?;
            let _ = csv_writer.write_record(&["routers_imperiled", &routers_imperiled.to_string()])?;
            let _ = csv_writer.write_record(&["total_router_asn", &router_asn.to_string()])?;

            let (total_loop_stats, total_loops) = self.create_total_loops()?;
            for (loop_len, nr_loops) in &total_loop_stats {
                let key = format!("total_loop_len_{}", loop_len);
                let _ = csv_writer.write_record(&[&key, &nr_loops.to_string()])?;
            }
            csv_writer.write_record(&["total_loop_len_sum", &total_loops.to_string()])?;

            for (loop_len, nr_loops) in &self.unique_loop_lengths {
                let key = format!("unique_loop_len_{}", loop_len);
                let _ = csv_writer.write_record(&[&key, &nr_loops.to_string()])?;
            }
            let _ = csv_writer.write_record(&["unique_loop_len_sum", &self.loop_members.len().to_string()])?;

            let _ = csv_writer.write_record(&["shadowed_asn_is_with_loop", &self.shadowed_to_asn_numbers.shadowed_asn_is_with_loop.to_string()])?;
            let _ = csv_writer.write_record(&["shadowed_asn_is_not_with_loop", &self.shadowed_to_asn_numbers.shadowed_asn_is_not_with_loop.to_string()])?;
            let _ = csv_writer.write_record(&["shadowed_asn_with_single_asn", &self.shadowed_to_asn_numbers.shadowed_asn_with_single_asn.to_string()])?;
            let _ = csv_writer.write_record(&["shadowed_asn_with_multiple_asn", &self.shadowed_to_asn_numbers.shadowed_asn_with_multiple_asn.to_string()])?;
            let _ = csv_writer.write_record(&["shadowed_asn_is_unknown", &self.shadowed_to_asn_numbers.shadowed_asn_is_unknown.to_string()])?;

            Ok(())
        }

        fn print_loops(len_map: &HashMap<u8, u64>, total: &u64) {
            let keys = len_map.keys();
            let keys = sorted(keys);

            for key in keys {
                if let Some(value) = len_map.get(key) {
                    println!("{:4}, {:12}", key, value);
                }
            }

            println!("{:>4}, {:12}", "Sum", total);
            println!();
        }

        fn write_routers_csv(&self) -> Result<(), YarrpError> {
            // routers -> (nr loops involved, nr shadowed, nr imperiled)
            let path = self.loop_storage.get_storage_file("routers.csv")?;
            let mut csv_writer = csv::Writer::from_path(path)?;
            if let Err(_) = csv_writer.write_record(&["router", "loops", "shadowed", "imperiled", "asn"]) {
                error!("Could not write header row for routers.csv!");
                return Err(YarrpError::CouldNotWriteError);
            }

            let mut count_vec: Vec<(&String, &u64)> = self.router_shadowed.iter().collect();
            count_vec.sort_by(|a, b| b.1.cmp(a.1));

            for (router, shadowed) in count_vec {
                let loops: u8;
                let shadowed = *shadowed;
                let imperiled: u64;
                let asn: u8;

                if let Some(value) = self.router_imperiled.get(router) {
                    imperiled = value.len() as u64;
                } else {
                    imperiled = 0;
                }

                if let Some(value) = self.router_loops.get(router) {
                    loops = value.len() as u8;
                } else {
                    loops = 0;
                }

                if let Some(value) = self.routers_to_asn.get(router) {
                    asn = value.len() as u8;
                } else {
                    asn = 0;
                }

                let loops = loops.to_string();
                let shadowed = shadowed.to_string();
                let imperiled = imperiled.to_string();
                let asn = asn.to_string();

                if let Err(_e) = csv_writer.write_record(&[router, &loops, &shadowed, &imperiled, &asn]) {
                    error!("Could not write csv line for router {}!", router);
                    return Err(YarrpError::CouldNotWriteError);
                }
            }
            Ok(())
        }

        fn write_loops_csv(&self) -> Result<(), YarrpError> {
            let path = self.loop_storage.get_storage_file("loops.csv")?;
            let mut csv_writer = csv::Writer::from_path(path)?;
            if let Err(_) = csv_writer.write_record(&["loop", "length", "shadowed", "imperiled", "asn"]) {
                error!("Could not write header row for loops.csv!");
                return Err(YarrpError::CouldNotWriteError);
            }

            let mut count_vec: Vec<(&String, &Vec<T>)> = self.loop_destinations.iter().collect();
            count_vec.sort_by(|a, b| b.1.len().cmp(&a.1.len()));

            for (loop_id, value) in count_vec {
                let members: u64;
                let shadowed = value.len() as u64;
                let mut imperiled: u64 = 0;
                let asn: u8;


                if let Some(value) = self.loop_members.get(loop_id) {
                    members = value.len() as u64;

                    for member in value {
                        if let Some(value) = self.router_imperiled.get(member) {
                            imperiled += value.len() as u64;
                        }
                    }
                } else {
                    members = 0;
                }

                if let Some(value) = self.loops_to_asn.get(loop_id) {
                    asn = value.len() as u8;
                } else {
                    asn = 0;
                }

                let members = members.to_string();
                let shadowed = shadowed.to_string();
                let imperiled = imperiled.to_string();
                let asn = asn.to_string();

                if let Err(_e) = csv_writer.write_record(&[loop_id, &members, &shadowed, &imperiled, &asn]) {
                    error!("Could not write csv line for loop {}!", loop_id);
                    return Err(YarrpError::CouldNotWriteError);
                }
            }

            Ok(())
        }

        fn write_asn_files(&self) -> Result<(), YarrpError> {
            let asn_path = self.loop_storage.get_storage_sub_file("asn", "asn.csv")?;
            if let Err(_e) = self.asn_attribution.write_asn_csv(&asn_path, &self.asn_to_routers, &self.asn_to_loops) {
                error!("Could not write asn.csv");
                return Err(_e);
            }

            let asn_path = self.loop_storage.get_storage_sub_file("asn", "asn_loops")?;
            if let Err(_e) = self.asn_attribution.write_item_to_asn_csv(&asn_path, &self.loops_to_asn) {
                error!("Could not write asn_loops");
                return Err(_e);
            }

            let asn_path = self.loop_storage.get_storage_sub_file("asn", "asn_routers")?;
            if let Err(_e) = self.asn_attribution.write_item_to_asn_csv(&asn_path, &self.routers_to_asn) {
                error!("Could not write asn_router");
                return Err(_e);
            }

            let asn_path = self.loop_storage.get_storage_sub_file("asn", "router_asn.csv")?;
            if let Err(_e) = self.asn_attribution.write_asn_router_entries(&asn_path, &self.routers_to_asn, &self.persistent_routers) {
                error!("Could not write router_asn.csv");
                return Err(_e);
            }

            let asn_path = self.loop_storage.get_storage_sub_file("asn", "loop_asn.csv")?;
            if let Err(_e) = self.asn_attribution.write_asn_loop_entries(&asn_path, &self.loop_members, &self.routers_to_asn, &self.persistent_loops) {
                error!("Could not write loop_asn.csv");
                return Err(_e);
            }

            Ok(())
        }

        // fn generate_preceding_router_stats(&self, ) -> Result<(), YarrpError> {
        //     let shadowed_preceding_path = self.loop_storage.get_storage_file(SHADOWED_PRECEDING_INFO)?;
        //
        //     if !shadowed_preceding_path.exists() {
        //         info!("No shadowed preceding file, not doing analysis");
        //         return Ok(());
        //     }
        //
        //     let mut reader = csv::Reader::from_path(shadowed_preceding_path)?;
        //     let mut total_result = ShadowedPrecedingCounter::new();
        //
        //     // iterate through all shadowed preceding routers from file
        //     for result in reader.deserialize() {
        //         let obj: ShadowedPreceding = result?;
        //         // grab asn of shadowed net and preceding router
        //
        //         let (shadowed_asn, preceding_asn) = self.asn_attribution.get_shadowed_preceding_asn(&obj.shadowed_net, &obj.preceding_router)?;
        //
        //     }
        //
        //     Ok(())
        // }
    }

    impl<T: 'static + Display + Ord + Copy + Clone + Hash + IpAddrExt + FromStr> ModeTrait for PostLoopStatsMode<T> {
        fn get_mode(&self) -> ModeEnum {
            self.mode
        }

        fn no_input_capable(&self) -> bool {
            true
        }

        fn parse_comment_line(&mut self, _input: &str) {
            // Dummy implementation, just ignore comment lines
        }

        fn parse_string_line(&mut self, _input: &str) {
            // nothing to do here!
            // not being used
        }

        fn do_file_rotate(&mut self, _file_number: u64, _file_name: &str) {}

        fn do_calculations(&mut self) {
            if let Err(_) = self.read_loop_identifiers() {
                error!("Could not read loop identifiers from {}", IDENTIFIERS);
                exit(1);
            }

            if let Err(_) = self.read_router_associations() {
                error!("Could not read router associations from {}!", ROUTERS);
                exit(1);
            }

            if let Err(_) = self.read_loop_destinations() {
                error!("Could not read loop destinations from {} directory!", LOOPS);
                exit(1);
            }

            if let Err(_) = self.read_imperiled_by_router() {
                error!("Could not read imperiled destinations from {} directory!", IMPERILED);
                exit(1);
            }

            if ! self.skip_densities {
                if let Err(_) = self.create_densities() {
                    error!("Could not create densities!");
                    exit(1);
                }
            } else {
                info!("Skipping density calculation!");
            }

            self.build_router_shadowed();

            if let Err(_e) = self.load_asn_attribution() {
                error!("Could not load ASN attribution!");
            }

            if let Err(_e) = self.write_asn_files() {
                error!("Could not write asn files!")
            }

            if let Err(_e) = self.write_routers_csv() {
                error!("Could not write routers.csv!");
            }

            if let Err(_e) = self.write_loops_csv() {
                error!("Could not write loops.csv!");
            }

            if let Err(_e) = self.write_post_loop_stats() {
                error!("Could not write postloop_stats.csv!");
            }


            if self.target_number > 0 {
                info!("Building target information!");
                self.add_targets();
                self.store_targets_to_file();
            }
        }

        fn print_output(&self) {
            self.print_unique_loops();
            self.print_total_loops();

            println!();
            println!("Routers found: {}", self.router_loops.len());
            println!("Router Stats:");

            let mut router_map: HashMap<u64, HashSet<String>> = HashMap::new();
            for (router, identifiers) in &self.router_loops {
                let value_len = identifiers.len() as u64;
                if !router_map.contains_key(&value_len) {
                    router_map.insert(value_len, HashSet::new());
                }

                if let Some(value) = router_map.get_mut(&value_len) {
                    value.insert(router.clone());
                } else {
                    error!("Could not get value from hashmap!");
                    exit(1);
                }
            }
            println!("Router Member in Number Loops");

            let keys = router_map.keys();
            let keys = sorted(keys);
            for key in keys {
                if let Some(value) = router_map.get(key) {
                    print!("{:6}, {:12}", key, value.len());
                    if value.len() < 3 {
                        for item in value {
                            print!(" {}", item);
                        }
                    }
                    println!();
                }
            }

            println!();
            println!("Routers with most shadowed destinations:");

            let mut count_vec: Vec<(&String, &u64)> = self.router_shadowed.iter().collect();
            count_vec.sort_by(|a, b| b.1.cmp(a.1));

            let mut count = 0;

            for (max_router, value) in count_vec {
                if !self.print_all_output && count >= 25 { break; }
                println!("{:48}, {:15}", max_router, value);
                count += 1;
            }

            println!();
            println!("Loops with most destinations");

            let mut count_vec: Vec<(&String, &Vec<T>)> = self.loop_destinations.iter().collect();
            count_vec.sort_by(|a, b| b.1.len().cmp(&a.1.len()));

            count = 0;
            for (loop_id, value) in count_vec {
                if !self.print_all_output && count >= 25 { break; }
                println!("{:48}, {:15}", loop_id, value.len());
                count += 1;
            }

            let mut routers_involved = 0;
            for (_router, nets) in &self.router_imperiled {
                if nets.len() > 0 {
                    routers_involved += 1;
                }
            }

            let mut router_perc: f64 = routers_involved as f64;
            router_perc = 100.0 * router_perc / (self.router_loops.len() as f64);


            println!();
            println!("Imperiled Nets: {}", self.num_imperiled);
            println!("Routers involved: {} / {} ({:.2} %)", routers_involved, self.router_loops.len(), router_perc);

            if self.target_file.len() > 0 && (self.target_number > 0 || self.target_take_all) {
                println!("New target destinations: {}", self.target_destinations.len());
                let keys = self.loops_with_low_targets.keys();
                let keys = sorted(keys);
                for key in keys {
                    if let Some(value) = self.loops_with_low_targets.get(key) {
                        println!("{:6}, {:12}", key, value);
                    }
                }
            }
        }

        fn close(&mut self) {}
    }
}