pub mod target_mode {
    use std::fmt::Display;
    use std::hash::Hash;
    use std::str::FromStr;

    use clap::ArgMatches;
    use ipnet::{IpNet};
    use log::{info, error, trace, warn};
    use std::process::exit;
    use rand::prelude::SeedableRng;
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::traits::IpAddrExt;
    use crate::modes::{ModeEnum, ModeTrait, parse_param, load_path_or_default, load_path_param, read_blocklist};
    use std::marker::PhantomData;
    use crate::structs::CountingFile;
    use std::collections::HashSet;
    use std::fs::remove_file;

    pub struct TargetMode<T> {
        mode: ModeEnum,
        target_prefix: u8,
        output_file: CountingFile,
        blocklist: HashSet<IpNet>,
        blocklist_filtered: u64,
        rng: rand_pcg::Lcg128Xsl64,
        ip_type: PhantomData<T>,
    }

    impl<T: Display + Ord + Copy + Clone + Hash + IpAddrExt + FromStr> TargetMode<T> {
        pub fn new(matches: ArgMatches) -> TargetMode<T> {
            let mode = ModeEnum::Target;
            let mode_string = mode.to_string().to_lowercase();
            let sub_matches;
            if let Some(value) = matches.subcommand_matches(mode_string) {
                sub_matches = value;
            } else {
                error!("Could not read args!");
                exit(1);
            }

            let target_prefix = parse_param::<u8>(sub_matches, "prefix_length", 48);
            let mut seed = parse_param::<u64>(sub_matches, "seed", 0);
            let blocklist_file = load_path_or_default(sub_matches, "blocklist", "");
            let output_path = load_path_param(sub_matches, "output");

            let blocklist;
            if blocklist_file.exists() {
                if let Some(path_str) = blocklist_file.to_str() {
                    info!("Using blocklist file {}", path_str);
                } else {
                    error!("Using blocklist file but encountered an error while printing string");
                    exit(1);
                }

                if let Ok(value) = read_blocklist(&blocklist_file) {
                    blocklist = value;
                } else {
                    error!("Could not read blocklist!");
                    exit(1);
                }

                for item in &blocklist {
                    if item.network().is_ipv4() != T::is_v4() {
                        error!("Block list first item is of different protocol than program runtime");
                        exit(1);
                    }
                    break;
                }

            } else {
                blocklist = HashSet::new();
            }

            if output_path.exists() && output_path.is_file() {
                if let Err(_) = remove_file(&output_path) {
                    error!("Could not delete existing output file!");
                    exit(1);
                }
            }

            let output_file;
            if let Some(value) = CountingFile::new(&output_path) {
                output_file = value;
            } else {
                error!("Could not open output file!");
                exit(1);
            }

            info!("Using RNG with seed {}", seed);
            info!(
                "Breaking down prefixes to /{} to and creating addresses for each",
                target_prefix
            );
            if let Some(output_str) = output_path.to_str() {
                info!("Storing address list at {}", output_str);
            } else {
                error!("Encountered error while printing output_file");
                exit(1);
            }

            if seed == 0 {
                let start = SystemTime::now();
                let since_the_epoch = start
                    .duration_since(UNIX_EPOCH)
                    .expect("Time went backwards");
                since_the_epoch.as_secs();
                seed = since_the_epoch.as_secs();
                info!("");
            }
            let rng = rand_pcg::Pcg64::seed_from_u64(seed);

            TargetMode {
                mode,
                target_prefix,
                output_file,
                blocklist,
                blocklist_filtered: 0,
                rng,
                ip_type: PhantomData,
            }
        }

        pub fn clear(&mut self) {}
    }

    impl<T: Display + Ord + Copy + Clone + Hash + IpAddrExt + FromStr> ModeTrait for TargetMode<T> {
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
            if let Ok(ip_net) = input.parse::<IpNet>() {
                if ip_net.network().is_ipv4() != T::is_v4() {
                    error!("Error! Configured IP Version differs from input!");
                    exit(1);
                }

                // check if net is smaller than wanted prefix size
                if ip_net.prefix_len() > self.target_prefix {
                    warn!("IP Net smaller than target prefix length");
                    return;
                }

                // check if net is in blocklist
                for block_net in &self.blocklist {
                    if block_net.contains(&ip_net) {
                        trace!("IP Net in blocklist");
                        self.blocklist_filtered += 1;
                        return;
                    }
                }

                let target;
                if let Ok(value) = T::create_target(input, &mut self.rng) {
                    target = value;
                } else {
                    error!("Could not create target for input!");
                    return;
                }

                trace!("Generated address {} for input {}", &target, ip_net);
                self.output_file.write_line(&target);
            } else {
                error!("Could not parse input as network");
            }
        }

        fn do_file_rotate(&mut self, _file_number: u64, _file_name: &str) {}

        fn do_calculations(&mut self) {
            // nothing to do here :)
        }

        fn print_output(&self) {
            info!("Generated {} targets from input.", self.output_file.len());
        }

        fn close(&mut self) {
            self.clear();
        }
    }
}