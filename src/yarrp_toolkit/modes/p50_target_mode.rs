pub mod p50_target_mode {
    use clap::ArgMatches;

    use crate::modes::{ModeEnum, ModeTrait};
    use std::process::exit;
    use log::{info, error};
    use rand::prelude::*;
    use std::fs::File;
    use std::io::Write;
    use std::marker::PhantomData;
    use std::str::FromStr;
    use crate::traits::IpAddrExt;
    use std::hash::Hash;
    use std::fmt::Display;
    use crate::structs::YarrpError;
    use ipnet::{Ipv4Net, IpAdd};

    pub struct P50TargetMode<T> {
        pub mode: ModeEnum,
        pub target_prefix: u8,
        output_file: File,
        file_number: u64,
        rng: rand_pcg::Lcg128Xsl64,
        ip_type: PhantomData<T>
    }

    impl<T: Display + Ord + Copy + Clone + Hash + IpAddrExt + FromStr> P50TargetMode<T> {
        pub fn new(matches: ArgMatches) -> P50TargetMode<T> {
            let mode = ModeEnum::P50Target;
            let mode_string = mode.to_string().to_lowercase();
            let sub_matches = matches.subcommand_matches(mode_string).unwrap();

            let target_prefix = sub_matches.value_of("prefix_length").unwrap();
            let target_prefix = target_prefix.parse().unwrap();

            let file_number = sub_matches.value_of("file_number").unwrap();
            let file_number: u64 = file_number.parse().unwrap();

            let seed = sub_matches.value_of("base_seed").unwrap();
            let mut seed: u64 = seed.parse().unwrap();
            seed += file_number;

            let output_file = sub_matches.value_of("output").unwrap().to_owned();
            let output_file = format!("{}/targets_p50_{}.lst", output_file, file_number);

            info!("Using seed {} from base seed + file number", seed);
            info!("Storing address list at {}", output_file);
            let rng = rand_pcg::Pcg64::seed_from_u64(seed);

            let output_file_pointer;
            if let Ok(output_file) = File::create(output_file) {
                output_file_pointer = output_file;
            } else {
                error!("Could not open file!");
                exit(1);
            }

            P50TargetMode {
                mode,
                target_prefix,
                file_number,
                output_file: output_file_pointer,
                rng,
                ip_type: PhantomData
            }
        }

        pub fn clear(&mut self) {}

        pub fn create_target(&mut self, input: &str) -> Result<String, YarrpError> {
            if T::is_v4() {
                let net = Ipv4Net::from_str(input)?;
                let add_number = (self.file_number as u32 + 1) * 5;
                let ip = net.network().saturating_add(add_number);
                return Ok(ip.to_string());
            } else {
                return T::create_target(input, &mut self.rng);
            }
        }
    }

    impl<T: Display + Ord + Copy + Clone + Hash + IpAddrExt + FromStr>  ModeTrait for P50TargetMode<T> {
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
            if let Ok(target_host) = self.create_target(input) {
                let formatted = format!("{}\n", target_host);
                if let Err(_) = self.output_file.write(formatted.as_bytes()) {
                    error!("Could not write to output file!");
                    exit(1);
                }
            } else {
                error!("Could not create target for {}", input);
                exit(1);
            }
        }

        fn do_file_rotate(&mut self, _file_number: u64, _file_name: &str) {}

        fn do_calculations(&mut self) {}

        fn print_output(&self) {}

        fn close(&mut self) {
            self.clear();
        }
    }
}