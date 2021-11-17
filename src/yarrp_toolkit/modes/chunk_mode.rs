pub mod chunk_mode {
    use std::collections::{HashMap};
    use std::path::PathBuf;
    use std::process::exit;
    use std::fs::{create_dir_all, remove_file};
    use std::str::FromStr;
    use clap::ArgMatches;
    use log::{error, info, trace};
    use ipnet::IpNet;

    use crate::modes::{ModeEnum, ModeTrait, load_path_param, parse_param};
    use crate::structs::{CountingFile, YarrpError};
    use crate::read_lines;
    use itertools::Itertools;

    pub struct ChunkMode {
        mode: ModeEnum,
        prefix_file: PathBuf,
        target_prefix: u8,
        ping_prefix: u8,
        output_path: PathBuf,
        prefixes: HashMap<u8, Vec<IpNet>>,
        output_map: HashMap<u64, u64>,
    }

    impl ChunkMode {
        pub fn new(matches: ArgMatches) -> ChunkMode {
            let mode = ModeEnum::Chunk;
            let mode_string = mode.to_string().to_lowercase();
            let sub_matches = matches.subcommand_matches(mode_string).unwrap();

            let prefix_file = load_path_param(&sub_matches, "prefix_file");
            if !prefix_file.exists() {
                error!("Prefix file does not exist!");
                exit(1);
            }

            let output_path = load_path_param(&sub_matches, "output");
            if output_path.exists() && output_path.is_file() {
                error!("Output path is file and exists!");
                exit(1);
            }

            if !output_path.exists() {
                if let Err(_) = create_dir_all(&output_path) {
                    error!("Could not create output path!");
                    exit(1);
                }
            }

            let target_prefix = sub_matches.value_of("target_prefix").unwrap();
            let target_prefix = target_prefix.parse().unwrap();

            let ping_prefix = parse_param::<u8>(&sub_matches, "ping_prefix", 0);
            if ping_prefix == 0 || ping_prefix > 128 || ping_prefix < target_prefix {
                error!("Ping Prefix must be between Target Prefix and Protocol Max Value!");
                exit(1);
            }

            println!("Using a smallest prefix length of {}", target_prefix);

            if let Some(value) = output_path.to_str() {
                println!("Storing chunks into {}", value);
            } else {
                error!("Could not parse path into string at output_path!");
                exit(1);
            }

            ChunkMode {
                mode,
                prefix_file,
                target_prefix,
                ping_prefix,
                output_path,
                prefixes: HashMap::new(),
                output_map: HashMap::new(),
            }
        }

        fn calculate_ping_prefixes(&self, length: u64, prefix_len: &u8) -> u64 {
            let length_diff = (self.ping_prefix - prefix_len) as u32;
            length * (2_u64.pow(length_diff))
        }

        fn read_prefix_file(&mut self) -> Result<u64, YarrpError> {
            let values = read_lines(&self.prefix_file)?;
            for line in values {
                let string_line = line?;
                let ip_net = IpNet::from_str(&string_line)?;

                if ip_net.prefix_len() > self.ping_prefix {
                    trace!("Removed longer prefix {}", &string_line);
                }

                if !self.prefixes.contains_key(&ip_net.prefix_len()) {
                    self.prefixes.insert(ip_net.prefix_len(), Vec::new());
                }

                if let Some(value) = self.prefixes.get_mut(&ip_net.prefix_len()) {
                    value.push(ip_net.clone());
                }
            }

            let mut total_prefixes_of_correct_size = 0;

            for (prefix_len, prefixes) in &self.prefixes {
                total_prefixes_of_correct_size += self.calculate_ping_prefixes(prefixes.len() as u64, prefix_len);
            }

            Ok(total_prefixes_of_correct_size as u64)
        }

        fn write_files(&mut self, output_files: &mut Vec<CountingFile>) -> Result<(), YarrpError> {
            // do the rotation of prefixes and write to output file
            let mut current_file = 0;


            for (prefix_length, prefixes) in &self.prefixes {
                for prefix in prefixes {
                    if *prefix_length < self.target_prefix {
                        let sub_prefixes = prefix.subnets(self.target_prefix)?;
                        for sub_prefix in sub_prefixes {
                            if let Some(file) = output_files.get_mut(current_file) {
                                let prefix_string = sub_prefix.to_string();
                                file.write_line(&prefix_string);
                            } else {
                                error!("Could not get current file!");
                                exit(1);
                            }

                            let index = current_file as u64;
                            let ping_prefixes = self.calculate_ping_prefixes(1, &sub_prefix.prefix_len());
                            if let Some(counter) = self.output_map.get_mut(&index) {
                                *counter += ping_prefixes;
                            }

                            current_file = (current_file + 1) % output_files.len();
                        }
                    } else {
                        if let Some(file) = output_files.get_mut(current_file) {
                            let prefix_string = prefix.to_string();
                            file.write_line(&prefix_string);
                        } else {
                            error!("Could not get current file!");
                            exit(1);
                        }

                        let index = current_file as u64;
                        let ping_prefixes = self.calculate_ping_prefixes(1, &prefix.prefix_len());
                        if let Some(counter) = self.output_map.get_mut(&index) {
                            *counter += ping_prefixes;
                        }

                        current_file = (current_file + 1) % output_files.len();
                    }
                }
            }

            Ok(())
        }

        pub fn clear(&mut self) {}
    }

    impl ModeTrait for ChunkMode {
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
            // nothing to do here
        }

        fn do_file_rotate(&mut self, _file_number: u64, _file_name: &str) {
            // nothing to do here
        }

        fn do_calculations(&mut self) {
            // read prefix file
            let total_number_prefixes;
            if let Ok(value) = self.read_prefix_file() {
                total_number_prefixes = value;
            } else {
                error!("Could not read prefix file!");
                exit(1);
            }

            info!("Found a total of {} prefixes of size {}", total_number_prefixes, self.ping_prefix);

            // calculate number of chunks
            let arbitrary_yarrp_number: u64 = 5000000;
            let number_files: u64 = if total_number_prefixes <= arbitrary_yarrp_number {
                1
            } else {
                let fraction = total_number_prefixes as f64 / arbitrary_yarrp_number as f64;
                fraction.ceil() as u64
            };

            info!("Splitting prefixes into {} chunks", number_files);
            let mut output_files = Vec::<CountingFile>::new();
            for index in 0..number_files {
                let file_path = self.output_path.join(format!("prefix_{:05}.lst", index));
                if file_path.exists() && file_path.is_file() {
                    if let Err(_) = remove_file(&file_path) {
                        error!("Could not delete existing file!");
                        exit(1);
                    }
                }

                self.output_map.insert(index, 0);

                if let Some(counting_file) = CountingFile::new(&file_path) {
                    output_files.push(counting_file);
                } else {
                    error!("Could not create file!");
                    exit(1);
                }
            }

            if let Err(_) = self.write_files(&mut output_files) {
                error!("Could not write files!");
                exit(1);
            }
        }

        fn print_output(&self) {
            info!("Written target prefixes of size {} to files:", self.ping_prefix);

            let mut total_written = 0;
            for file in self.output_map.keys().sorted() {
                if let Some(prefixes) = self.output_map.get(file) {
                    info!("{:05}: {:32}", file, prefixes);
                    total_written += prefixes;
                }
            }

            info!("Prefixes per Prefix Length");
            let mut total_prefixes = 0;
            let mut total_traceable = 0;
            for prefix_len in self.prefixes.keys().sorted() {
                if let Some(prefixes) = self.prefixes.get(prefix_len) {
                    let num_prefixes = prefixes.len() as u64;
                    let num_traceable_prefixes = self.calculate_ping_prefixes(num_prefixes, prefix_len);

                    total_prefixes += num_prefixes;
                    total_traceable += num_traceable_prefixes;
                    info!("{:5} - {:16} - {:16}", prefix_len, num_prefixes, num_traceable_prefixes);
                }
            }
            info!("Total - {:16} - {:16}", total_prefixes, total_traceable);
            info!("Total Written: {:16}", total_written);
        }

        fn close(&mut self) {
            self.clear();
        }
    }
}