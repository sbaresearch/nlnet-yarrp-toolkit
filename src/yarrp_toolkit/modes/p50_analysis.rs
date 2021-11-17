pub mod p50_analysis {
    use std::fmt::Display;
    use std::hash::Hash;
    use std::str::FromStr;
    use clap::ArgMatches;
    use log::{info, error, trace};
    use std::process::exit;
    use std::path::{PathBuf, Path};
    use std::collections::{HashMap, HashSet};
    use ipnet::IpNet;

    use crate::traits::IpAddrExt;
    use crate::modes::{ModeTrait, ModeEnum, load_path_param, parse_param};
    use crate::structs::{YarrpError, ZMAPLine, ZMAPClassification, ShadowedAnswer};
    use crate::read_lines;
    use crate::analytics::{LoopStorage, LOOPS};

    pub struct P50Analysis<T> {
        pub mode: ModeEnum,
        input_path: PathBuf,
        output_path: PathBuf,
        original_targets_path: PathBuf,
        full_scan_path: PathBuf,
        persistent_loops_path: PathBuf,
        original_targets: HashSet<IpNet>,
        persistent_loops: HashSet<String>,
        responses: HashMap<String, u64>,
        ignore_map: HashMap<T, u64>,
        shadowed_responses: HashMap<IpNet, ShadowedAnswer>,
        prefix_len: u8,
        file_limit: u64,
        skip_files: u64,
    }

    impl<T: Display + Ord + Copy + Clone + Hash + IpAddrExt + FromStr> P50Analysis<T> {
        pub fn new(matches: ArgMatches) -> P50Analysis<T> {
            let mode = ModeEnum::P50Analysis;
            let mode_string = mode.to_string().to_lowercase();
            let sub_matches;
            if let Some(value) = matches.subcommand_matches(mode_string) {
                sub_matches = value;
            } else {
                error!("Could not read args!");
                exit(1);
            }

            let input_path = load_path_param(sub_matches, "input_path");
            let output_path = load_path_param(sub_matches, "output_path");
            let original_targets_path = load_path_param(sub_matches, "original_targets");
            let full_scan_path = load_path_param(sub_matches, "full_scan");
            let persistent_loops_path = load_path_param(sub_matches, "persistent_loops");

            let file_limit = parse_param::<u64>(sub_matches, "file_limit", 0);
            let skip_files = parse_param::<u64>(sub_matches, "skip_files", 0);

            if file_limit > 0 {
                info!("Limiting files to read to {}", file_limit);
            }

            if skip_files > 0 {
                info!("Skipping first {} files to read", skip_files);
            }

            let prefix_len;
            if T::is_v4() {
                prefix_len = 24;
            } else {
                prefix_len = 48;
            }

            P50Analysis {
                mode,
                input_path,
                output_path,
                original_targets_path,
                full_scan_path,
                persistent_loops_path,
                original_targets: HashSet::new(),
                persistent_loops: HashSet::new(),
                responses: HashMap::new(),
                ignore_map: HashMap::new(),
                shadowed_responses: HashMap::new(),
                prefix_len,
                file_limit,
                skip_files
            }
        }

        fn load_original_targets(&mut self) -> Result<(), YarrpError> {
            info!("Reading original targets from file!");
            let mut count: u64 = 0;
            let lines = read_lines(&self.original_targets_path)?;

            for line in lines {
                let line = line?;
                let ip_net = IpNet::from_str(&line)?;
                if !self.original_targets.insert(ip_net.clone()) {
                    info!("Duplicate entry {}", &ip_net);
                }
                count += 1;
            }
            let orig_len = self.original_targets.len() as u64;
            info!("Loaded {} original targets, (ignored {} duplicates)", orig_len, count - orig_len);

            Ok(())
        }

        fn load_persistent_loops(&mut self) -> Result<(), YarrpError> {
            info!("Reading persistent loops!");
            let loops = LoopStorage::<T>::read_id_file(&self.persistent_loops_path)?;
            for loop_id in loops.keys() {
                self.persistent_loops.insert(loop_id.clone());
            }

            info!("Found {} persistent loops!", self.persistent_loops.len());
            Ok(())
        }

        fn load_files(&mut self) -> Result<(), YarrpError> {
            let input_path_str;
            if let Some(path) = self.input_path.to_str() {
                input_path_str = path;
            } else {
                error!("Could not parse path to string!");
                exit(1);
            }
            info!("Loading files from input {}", input_path_str);

            let pattern = format!("{}/*", input_path_str);

            let paths = glob::glob(&pattern)?;

            let mut count = 0;
            for path in paths {

                if self.file_limit != 0 && count >= self.file_limit {
                    info!("Reached file limit, finishing up.");
                    break;
                }

                if self.skip_files == 0 || count >= self.skip_files {
                    let path = path?;
                    let str_path = path.file_name().unwrap().to_str().unwrap();
                    info!("Loading {}", str_path);
                    self.load_file(&path)?;
                }

                count += 1;
            }

            Ok(())
        }

        fn load_file(&mut self, file_path: &Path) -> Result<(), YarrpError> {
            let csv_reader = csv::Reader::from_path(file_path)?;
            for line in csv_reader.into_deserialize() {
                let record: ZMAPLine;
                match line {
                    Ok(result) => {
                        record = result
                    }
                    Err(e) => {
                        error!("{}", e.to_string());
                        return Err(YarrpError::CouldNotParseError);
                    }
                }

                let classification = &record.classification.to_string();
                if !self.responses.contains_key(classification) {
                    self.responses.insert(classification.clone(), 0);
                }

                if let Some(entry) = self.responses.get_mut(classification) {
                    *entry += 1;
                } else {
                    error!("Could not get mutable reference to reponse number");
                }

                self.add_line_to_responses(&record)?;
            }
            Ok(())
        }

        fn add_line_to_responses(&mut self, record: &ZMAPLine) -> Result<(), YarrpError> {
            let mut orig_net;
            if let Ok(orig_ip) = T::from_str(&record.orig_dest_ip) {
                orig_net = orig_ip.to_network_with_prefix_length(self.prefix_len)?;
                orig_net = orig_net.trunc();

                if !self.ignore_map.contains_key(&orig_ip) {
                    self.ignore_map.insert(orig_ip, 0);
                } else {
                    if let Some(entry) = self.ignore_map.get_mut(&orig_ip) {
                        *entry += 1;
                    }
                    return Ok(());
                }
            } else {
                error!("Could not parse IPAdress to IPNet at {}/{}!", &record.orig_dest_ip, self.prefix_len);
                return Err(YarrpError::CouldNotParseError);
            }

            if !self.shadowed_responses.contains_key(&orig_net) {
                let shadowed = ShadowedAnswer::new(&orig_net);
                self.shadowed_responses.insert(orig_net.clone(), shadowed);
            }

            if let Some(shadowed) = self.shadowed_responses.get_mut(&orig_net) {
                match record.classification {
                    ZMAPClassification::EchoReply => { shadowed.echoreply += 1; }
                    ZMAPClassification::Timxceed => { shadowed.timxceed += 1; }
                    ZMAPClassification::Unreach => { shadowed.unreach += 1; }
                    ZMAPClassification::UnreachNoRoute => {
                        shadowed.unreach_noroute += 1;
                        shadowed.unreach += 1;
                    }
                    ZMAPClassification::UnreachAddr => {
                        shadowed.unreach_addr += 1;
                        shadowed.unreach += 1;
                    }
                    ZMAPClassification::UnreachRejectRoute => {
                        shadowed.unreach_rejectroute += 1;
                        shadowed.unreach += 1;
                    }
                    ZMAPClassification::UnreachNoPort => {
                        shadowed.unreach_noport += 1;
                        shadowed.unreach += 1;
                    }
                    ZMAPClassification::UnreachAdmin => {
                        shadowed.unreach_admin += 1;
                        shadowed.unreach += 1;
                    }
                    ZMAPClassification::UnreachPolicy => {
                        shadowed.unreach_policy += 1;
                        shadowed.unreach += 1;
                    }
                    ZMAPClassification::Paramprob => {
                        shadowed.paramprob += 1;
                    }
                }
            } else {
                error!("Could not add classification to net")
            }

            Ok(())
        }

        fn load_shadowed_destinations(&mut self) -> Result<(), YarrpError> {
            // for each persistent loop in our set, read all shadowed destinations
            // iterate over all shadowed nets and check if we got a hit in our result set
            // if so, set the persistent flag to true
            info!("Adding persistence info to found loops");

            let full_scan_storage;
            if let Some(storage_path) = self.full_scan_path.to_str() {
                full_scan_storage = LoopStorage::<T>::new(true, storage_path.to_string());
            } else {
                error!("Could not grab string for full scan path!");
                exit(2);
            }

            let mut persistent_nets = 0;

            for loop_id in &self.persistent_loops {
                let sub_file = format!("{}.dest", loop_id);
                let loop_path = full_scan_storage.get_storage_sub_file(LOOPS, &sub_file)?;
                let shadowed_nets = LoopStorage::<T>::read_details_file_as_t(&loop_path)?;

                for shadowed_net in shadowed_nets {
                    let mut prefix = shadowed_net.to_network_with_prefix_length(self.prefix_len)?;
                    prefix = prefix.trunc();
                    if self.shadowed_responses.contains_key(&prefix) {
                        if let Some(value) = self.shadowed_responses.get_mut(&prefix) {
                            value.persistent_shadowed = true;
                            persistent_nets += 1;
                        }
                    }
                }
            }

            info!("Found {} persistent shadowed nets!", persistent_nets);
            Ok(())
        }

        fn write_responses(&self) -> Result<(), YarrpError> {
            let mut writer = csv::Writer::from_path(&self.output_path)?;

            for item in &self.original_targets {
                let answer;
                if let Some(value) = self.shadowed_responses.get(item) {
                    answer = value.clone();
                } else {
                    trace!("No element for ipnet {}", item);
                    answer = ShadowedAnswer::new_timeout(item);
                }
                writer.serialize(answer)?;
            }

            Ok(())
        }
    }

    impl<T: Display + Ord + Copy + Clone + Hash + IpAddrExt + FromStr> ModeTrait for P50Analysis<T> {
        fn get_mode(&self) -> ModeEnum {
            ModeEnum::P50Analysis
        }

        fn no_input_capable(&self) -> bool {
            true
        }

        fn parse_comment_line(&mut self, _input: &str) {
            // nothing to do here
        }

        fn parse_string_line(&mut self, _input: &str) {
            // nothing to do here
        }

        fn do_file_rotate(&mut self, _file_number: u64, _file_name: &str) {
            // nothing to do here
        }

        fn do_calculations(&mut self) {
            if let Err(_) = self.load_persistent_loops() {
                error!("Could not persistent loops!");
                exit(1);
            }

            if let Err(_) = self.load_original_targets() {
                error!("Could not load original targets file!");
                exit(1);
            }

            if let Err(_) = self.load_files() {
                error!("Could not load input files!");
                exit(1);
            }

            if let Err(_) = self.load_shadowed_destinations() {
                error!("Could not add persistence to nets!");
                exit(1);
            }
        }

        fn print_output(&self) {
            // for (key, value) in &self.responses {
            //     println!("{}: {}", key, value);
            // }
            //
            // for (key, value) in &self.ignore_map {
            //     if *value > 3 {
            //         println!("{}: {}", key, value);
            //     }
            // }

            if let Err(_) = self.write_responses() {
                error!("Could not write response csv!");
            }
        }

        fn close(&mut self) {}
    }
}