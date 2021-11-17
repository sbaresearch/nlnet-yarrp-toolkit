pub mod merge_id_mode {
    use clap::ArgMatches;
    use std::process::exit;
    use log::{error, warn, info, trace};
    use std::path::{Path, PathBuf};
    use std::collections::{HashMap, HashSet};
    use std::net::Ipv4Addr;

    use crate::modes::{ModeTrait, ModeEnum};
    use crate::analytics::{LoopStorage, LoopStatistics};
    use crate::structs::{YarrpError, CountingFile, ShadowedPreceding};
    use crate::analytics::{ROUTERS, IDENTIFIERS, IMPERILED, LOOPS, STATS, SHADOWED_PRECEDING_INFO};
    use crate::read_lines;
    use std::borrow::BorrowMut;

    pub struct MergeIdMode {
        pub mode: ModeEnum,
        input_paths: Vec<PathBuf>,
        pub output_path: String,
        storage: LoopStorage<Ipv4Addr>,  // type does not matter here, we just want to use some lower functions
    }

    impl MergeIdMode {
        pub fn new(matches: ArgMatches) -> MergeIdMode {
            let mode = ModeEnum::MergeId;
            let mode_string = mode.to_string().to_lowercase();
            let sub_matches = matches.subcommand_matches(mode_string).unwrap();

            let mut output_path = String::new();

            if let Some(path) = sub_matches.value_of("output") {
                output_path = path.to_string();
            }

            let mut input_paths = Vec::new();
            if let Some(lines) = sub_matches.values_of("inputs") {
                for line in lines {
                    info!("lines: {}", line);
                    let path = Path::new(line);
                    input_paths.push(path.to_path_buf());
                }
            } else {
                error!("Could not parse any inputs");
            }

            if input_paths.len() < 2 {
                error!("Need at least two project paths to mergee!");
                exit(1);
            }

            if !MergeIdMode::check_input_paths(&input_paths) {
                error!("One or more paths does not exist!");
                exit(1);
            }

            let storage = LoopStorage::new(true, output_path.to_string());

            MergeIdMode {
                mode,
                input_paths,
                output_path,
                storage,
            }
        }

        fn check_input_paths(paths: &Vec<PathBuf>) -> bool {
            let mut return_value = true;

            for path in paths {
                if !path.exists() || !path.is_dir() {
                    if let Some(str_path) = path.to_str() {
                        error!("Input path ({}) is nonexistent or not a directory!", str_path);
                    }
                    return_value = false;
                }
            }

            return_value
        }

        fn merge_identifiers(&self, file: &str) -> Result<Vec<String>, YarrpError> {
            let mut output_identifiers = HashMap::new();
            let output_path = self.storage.get_storage_file(file)?;

            for path in &self.input_paths {
                let id_file = path.join(file);
                let temp_id = LoopStorage::<Ipv4Addr>::read_id_file(&id_file)?;
                LoopStorage::<Ipv4Addr>::merge_id_file_string(&mut output_identifiers, &temp_id)?;
            }

            LoopStorage::<Ipv4Addr>::write_id_file(&output_path, &output_identifiers)?;
            let mut keys = Vec::new();

            for item in output_identifiers.keys() {
                keys.push(item.to_string());
            }

            Ok(keys)
        }

        fn merge_details(&self, sub_folder: &str, keys: &Vec<String>, extension: &str) -> Result<(), YarrpError> {
            let subdir = self.storage.get_storage_sub_dir(sub_folder)?;
            info!("Merging details for sub dir {} and files with extension {}", sub_folder, extension);

            // iterate over keys from identifiers or routers
            for key in keys {
                let filename = format!("{}.{}", key, extension);
                trace!("Selecting file {}", filename);

                let mut key_set = HashSet::new();

                // iterate over existing projects and read the given key
                for input_path in &self.input_paths {
                    let file_path = input_path.join(sub_folder).join(&filename);
                    let file_path_str;
                    if let Some(string) = file_path.to_str() {
                        file_path_str = string;
                    } else {
                        error!("Could not create string for filepath!");
                        file_path_str = "";
                    }

                    trace!("Trying to read from {}", file_path_str);

                    // if the file exists, read the content, collect from all input paths
                    // and write to new output project
                    if file_path.exists() && file_path.is_file() {
                        trace!("File existed, reading from it");
                        let lines = read_lines(file_path)?;
                        for line in lines {
                            let line = line?;

                            key_set.insert(line.to_string());
                        }
                    }
                }

                let output_path = subdir.join(filename);
                if let Some(mut counting_file) = CountingFile::new(&output_path) {
                    for item in key_set {
                        counting_file.write_line(&item);
                    }
                } else {
                    if let Some(str_path) = output_path.to_str() {
                        error!("Could not open output file at {}", str_path);
                    } else {
                        error!("Could not open output file!");
                    }
                    exit(1);
                }
            }
            Ok(())
        }

        fn merge_stats(&self) -> Result<(), YarrpError> {
            let output_path = self.storage.get_storage_file(STATS)?;
            let mut output_stats = LoopStatistics::new(true, output_path);

            for path in &self.input_paths {
                let stats_file = path.join(STATS);
                let stats_mod = LoopStatistics::new(true, stats_file);
                output_stats.number_of_routes += stats_mod.number_of_routes;
                output_stats.number_of_load_balancers += stats_mod.number_of_load_balancers;
                output_stats.number_of_spammers += stats_mod.number_of_spammers;
                output_stats.number_of_loops += stats_mod.number_of_loops;
                output_stats.number_of_full_loops += stats_mod.number_of_full_loops;
                output_stats.number_of_imperiled += stats_mod.number_of_imperiled;
            }

            if let Err(err) = output_stats.write_csv() {
                error!("Could not write new stats.csv file!");
                return Err(err);
            }

            Ok(())
        }

        fn merge_loops_information(&mut self) -> Result<(), YarrpError> {
            for path in &self.input_paths {
                let path_info = LoopStorage::<Ipv4Addr>::read_loop_info(path)?;
                for (loop_id, info) in &path_info {
                    if ! self.storage.loop_information.contains_key(loop_id) {
                        self.storage.loop_information.insert(loop_id.clone(), info.clone());
                    } else if let Some(existing_info) = self.storage.loop_information.get_mut(loop_id) {
                        existing_info.shadowed_nets += info.shadowed_nets;
                    }
                }
            }
            Ok(())
        }

        fn merge_shadowed_preceding(&mut self) -> Result<(), YarrpError> {
            info!("Attempting to merge shadowed preceding files!");
            self.storage.create_shadowed_preceding_file_if_exists()?;
            let shadowed_writer;
            if let Some(temp_writer) = self.storage.shadowed_storage.borrow_mut() {
                shadowed_writer = temp_writer;
            } else {
                error!("Could not get writer!");
                exit(1);
            }

            for path in &self.input_paths {
                let existing_shadowed = path.join(SHADOWED_PRECEDING_INFO);
                if !existing_shadowed.exists() {
                    error!("Shadowed preceding file does not exist at {}", path.to_str().unwrap());
                }

                // open existing preceding file and parse records
                let mut reader = csv::Reader::from_path(existing_shadowed)?;
                for result in reader.deserialize() {
                    if let Ok(value) = result {
                        let value: ShadowedPreceding = value;
                        shadowed_writer.serialize(value)?;
                    } else {
                        warn!("Could not deserialize value!");
                    }
                }
            }

            Ok(())
        }

    }

    impl ModeTrait for MergeIdMode {
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
            // No input parsing here!
        }

        fn do_file_rotate(&mut self, _file_number: u64, _file_name: &str) {
            // No file rotating here
        }

        fn do_calculations(&mut self) {
            // do the actual work here
            // merge identifiers

            let loop_identifiers;
            let routers;

            if let Ok(temp_loop_identifiers) = self.merge_identifiers(IDENTIFIERS) {
                loop_identifiers = temp_loop_identifiers;
            } else {
                error!("Could not merge identifiers!");
                exit(1);
            }

            // merge routers
            if let Ok(temp_routers) = self.merge_identifiers(ROUTERS) {
                routers = temp_routers;
            } else {
                error!("Could not merge routers!");
                exit(1);
            }

            if let Err(_e) = self.merge_details(LOOPS, &loop_identifiers, "dest") {
                error!("Could not merge destination details!");
            }

            if let Err(_e) = self.merge_details(IMPERILED, &routers, "imp") {
                error!("Could not merge destination details!");
            }

            if let Err(_e) = self.merge_stats() {
                error!("Could not merge stats.csv files!");
            }

            if let Err(_e) = self.merge_loops_information() {
                error!("Could not merge loops.csv files!");
            }

            if let Err(_e) = self.merge_shadowed_preceding() {
                error!("Could not merge shadowed_preceding.csv files!");
            }
        }

        fn print_output(&self) {}

        fn close(&mut self) {}
    }
}