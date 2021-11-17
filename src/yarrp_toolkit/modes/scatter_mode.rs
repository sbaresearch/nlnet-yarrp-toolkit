pub mod scatter_mode {
    use clap::ArgMatches;

    use crate::modes::{ModeEnum, ModeTrait};
    use std::collections::{HashMap, HashSet};
    use std::str::FromStr;
    use log::{error, info};
    use crate::structs::YarrpError;
    use std::fs::File;
    use std::io::Write;
    use std::process::exit;
    use crate::traits::IpAddrExt;
    use std::fmt::Display;
    use std::hash::Hash;
    use ipnet::IpNet;
    use std::marker::PhantomData;

    pub struct ScatterMode<T> {
        pub mode: ModeEnum,
        pub bucket_prefix: u8,
        pub target_prefix: u8,
        pub output_file: String,
        bucket_prefix_dict: HashMap<IpNet, Vec<String>>,
        ip_type: PhantomData<T>
    }

    impl<T: Display + Ord + Copy + Clone + Hash + IpAddrExt + FromStr> ScatterMode<T> {
        pub fn new(matches: ArgMatches) -> ScatterMode<T> {
            let mode = ModeEnum::Scatter;
            let mode_string = mode.to_string().to_lowercase();
            let sub_matches = matches.subcommand_matches(mode_string).unwrap();

            let bucket_prefix = sub_matches.value_of("bucket_prefix").unwrap();
            let bucket_prefix = bucket_prefix.parse().unwrap();

            let target_prefix = sub_matches.value_of("target_prefix").unwrap();
            let target_prefix = target_prefix.parse().unwrap();

            let output_file = sub_matches.value_of("output").unwrap().to_owned();

            info!("Loading Scatter Mode...");

            ScatterMode {
                mode,
                bucket_prefix,
                target_prefix,
                output_file,
                bucket_prefix_dict: HashMap::new(),
                ip_type: PhantomData
            }
        }

        pub fn clear(&mut self) {
            self.bucket_prefix_dict.clear();
        }

        /// Adds an IPv6 address to a per ScatterMode instance hashmap.
        /// Each IPv6 address is transformed into its /48 network, and collected in buckets of
        /// a given prefix size.
        pub fn add_ip_addr(&mut self, ip_addr: &str) -> Result<(), YarrpError> {
            let destination_addr;
            if let Ok(temp_destination_addr) = T::from_str(ip_addr) {
                destination_addr = temp_destination_addr;
            } else {
                error!("Could not read IP Address ({})!", ip_addr);
                exit(1);
            }

            // create IPvX net with prefix length of bucket_prefix for bucket scattering
            let mut bucket_net = destination_addr.to_network_with_prefix_length(self.bucket_prefix)?;
            bucket_net = bucket_net.trunc();

            // create IPvX net with prefix length of target_prefix for actual storage and output
            let mut output_net = destination_addr.to_network_with_prefix_length(self.target_prefix)?;
            output_net = output_net.trunc();

            // check if bucket exists
            if !self.bucket_prefix_dict.contains_key(&bucket_net) {
                self.bucket_prefix_dict.insert(bucket_net.clone(), Vec::new());
            }

            // add output net to bucket dict
            if let Some(destinations) = self.bucket_prefix_dict.get_mut(&bucket_net) {
                destinations.push(output_net.to_string());
            } else {
                return Err(YarrpError::CouldNotParseError);
            }
            Ok(())
        }

        /// Retrieves the minimum and maximum length of the inner vector of a given input HashMap.
        /// Returns (minimum length, maximum length)
        fn get_min_max(hashmap: &HashMap<IpNet, Vec<String>>) -> (usize, usize)
        {
            let mut max_size = 0;
            let mut min_size = usize::MAX;

            // check margins to build small heuristic
            for (_, value) in hashmap {
                if value.len() > max_size {
                    max_size = value.len();
                }

                if value.len() < min_size {
                    min_size = value.len();
                }
            }
            return (min_size, max_size);
        }


        fn merge_lists(&mut self) -> Result<(u64, HashMap<IpNet, Vec<String>>), YarrpError> {
            let mut return_map = HashMap::new();
            let (min_size, max_size) = ScatterMode::<T>::get_min_max(&self.bucket_prefix_dict);

            // hashset to ignore already added prefixes
            let mut ignore_vec: HashSet<IpNet> = HashSet::new();

            info!("Total in list: {}", self.bucket_prefix_dict.len());
            info!("Min size: {} ; Max size: {}", min_size, max_size);
            let mut no_merge_written = 0;
            let mut merge_basis = 0;
            let mut merged_into = 0;
            for (key, value) in &self.bucket_prefix_dict {

                // if already added, ignore prefix
                if ignore_vec.contains(&key) {
                    continue;
                }

                // add curent prefix to ignore vec
                ignore_vec.insert(key.clone());

                // if the current prefix plus the smallest found prefix are larger than the max
                // just write it through, wont find a match anyways
                if value.len() + min_size >= max_size {
                    no_merge_written += 1;
                    return_map.insert(key.clone(), value.clone());
                } else {
                    let mut has_merged = false;
                    // iterate a second time to find a *perfect* match to merge with
                    for (second_key, second_value) in &self.bucket_prefix_dict {

                        // second collection is already present, ignore it
                        if ignore_vec.contains(&second_key) {
                            continue;
                        }

                        // the current second prefix fits in length, so merge with it
                        if value.len() + second_value.len() <= max_size {
                            merge_basis += 1;
                            merged_into += 1;
                            let mut insert_vec = value.clone();
                            let mut second_vec = second_value.clone();
                            insert_vec.append(&mut second_vec);
                            ignore_vec.insert(second_key.clone());
                            return_map.insert(key.clone(), insert_vec);
                            has_merged = true;
                            break;
                        }
                    }

                    // if the current prefix hasn't been merged, write it through
                    if ! has_merged {
                        no_merge_written += 1;
                        return_map.insert(key.clone(), value.clone());
                    }
                }
            }
            info!("No Mergers: {}", no_merge_written);
            info!("Merge Basis: {}", merge_basis);
            info!("Mergers {}", merged_into);
            info!("Total \"Prefixes\": {}", no_merge_written + merge_basis + merged_into);

            Ok((merge_basis, return_map))
        }

        fn do_merge(&mut self) -> u64{
            if let Ok((merged, new_list)) = self.merge_lists() {
                let mut count_vec: Vec<(&IpNet, &Vec<String>)> = new_list.iter().collect();
                count_vec.sort_by(|a, b| b.1.len().cmp(&a.1.len()));

                info!("Merge LEN: {}", new_list.len());

                if merged == 0 {
                    let (min, max) = ScatterMode::<T>::get_min_max(&new_list);
                    info!("Last Min: {}; Last Max: {}", min, max);
                }

                self.bucket_prefix_dict = new_list;

                return merged;
            } else {
                error!("Something failed here!")
            }
            return 0;
        }

        /// Write the destination nets from the bucket dict into the given output path
        /// We iterate over all buckets and take one value from it to write to the output path.
        /// This way we can somewhat guarantee to scatter the destinations of each bucket prefix
        fn write_output(&self) -> Result<(), YarrpError>{
            let mut counter = 0;

            let mut added_lines = 0;

            let mut added = true;
            let mut output_file = File::create(&self.output_file)?;

            while added {
                added = false;

                for item in self.bucket_prefix_dict.values() {
                    if let Some(value) = item.get(counter) {
                        let format_string = format!("{}\n", value);
                        output_file.write(format_string.as_bytes())?;
                        // set added flag so we know, we added at *least* one value from the buckets to the output list
                        added = true;
                        added_lines += 1;
                    }
                }
                counter += 1;
            }

            info!("Written {} lines to the output file", added_lines);
            Ok(())
        }
    }

    impl<T: Display + Ord + Copy + Clone + Hash + FromStr + IpAddrExt> ModeTrait for ScatterMode<T> {
        fn get_mode(&self) -> ModeEnum {
            self.mode
        }

        fn no_input_capable(&self) -> bool {
            false
        }

        fn parse_comment_line(&mut self, _input: &str) {
            // Dummy implementation, just ignore comment lines
        }

        fn parse_string_line(&mut self, input: &str) {
            if let Err(_) = self.add_ip_addr(input) {
                error!("Could not parse {}", input);
            }
        }

        fn do_file_rotate(&mut self, _file_number: u64, _file_name: &str) {}

        fn do_calculations(&mut self) {
            let mut merged = 1;
            let mut counter = 0;
            while merged > 0 {
                info!("***********************************");
                info!("Merging #{}", counter);
                merged = self.do_merge();
                info!("Merged {} items", merged);
                counter += 1;
            }
        }

        fn print_output(&self) {
            if let Err(_) = self.write_output() {
                error!("Could not open or write to output file!");
                exit(1);
            }
        }

        fn close(&mut self) {
            self.clear();
        }
    }
}