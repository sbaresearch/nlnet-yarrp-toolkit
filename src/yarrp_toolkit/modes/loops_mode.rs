pub mod loops_mode {

    use crate::structs::{YarrpLine};
    use crate::analytics::{LoopAnalysis};
    use crate::modes::{ModeEnum, ModeTrait};
    use crate::create_dir_if_not_existing;

    use clap::ArgMatches;
    use std::process::exit;
    use log::{error};
    use std::fmt::Display;
    use std::hash::Hash;
    use std::str::FromStr;
    use crate::traits::IpAddrExt;

    pub struct LoopsMode<T> {
        pub mode: ModeEnum,
        pub line_count: u64,
        pub loop_analysis: LoopAnalysis<T>,
        min_ttl: u8,
        max_ttl: u8,
    }

    impl<T: Display + Ord + Copy + Clone + Hash + IpAddrExt + FromStr> LoopsMode<T> {

        pub fn new(matches: ArgMatches) -> LoopsMode<T> {
            let mode = ModeEnum::Loops;
            let mode_string = mode.to_string().to_lowercase();
            let sub_matches = matches.subcommand_matches(mode_string).unwrap();

            let loop_storage_path ;
            let imperiled_router_test_file;
            let imperiled_router_blocklist;

            let mut only_full_loops = false;

            let min_ttl = sub_matches.value_of("min_ttl").unwrap().parse().unwrap();
            let max_ttl = sub_matches.value_of("max_ttl").unwrap().parse().unwrap();

            if min_ttl >= max_ttl {
                error!("min_ttl >= max_ttl, aborting!");
                exit(1);
            }

            if sub_matches.occurrences_of("only_full_loops") > 0 {
                only_full_loops = true;
            }

            if let Some(temp_loop_storage) = sub_matches.value_of("loop_output") {
                loop_storage_path = temp_loop_storage.to_owned();
                // check if output directory path exists, if not create it
                if ! create_dir_if_not_existing(&loop_storage_path) {
                    error!("Could not create output directory!");
                    exit(1);
                }
            } else {
                error!("Could not read loop_output!");
                exit(1);
            }

            if let Some(router_input_file) = sub_matches.value_of("imperiled_router_test") {
                imperiled_router_test_file = router_input_file;
            } else {
                imperiled_router_test_file = "";
            }

            if let Some(blocklist_file) = sub_matches.value_of("imperiled_blocklist_prefixes") {
                imperiled_router_blocklist = blocklist_file;
            } else {
                imperiled_router_blocklist = "";
            }

            LoopsMode {
                mode,
                line_count: 0,
                loop_analysis: LoopAnalysis::new(only_full_loops, loop_storage_path, imperiled_router_test_file, imperiled_router_blocklist),
                min_ttl,
                max_ttl
            }
        }

        pub fn clear(&mut self) {
            self.line_count = 0;
        }

    }

    impl<T: Display + Ord + Copy + Clone + Hash + FromStr + IpAddrExt> ModeTrait for LoopsMode<T> {
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
            self.line_count += 1;
            if let Some(yarrp_line) = YarrpLine::new(input){
                self.loop_analysis.add_ttl(yarrp_line);
            } else {
                error!("Could not parse line!");
            }
        }

        fn do_file_rotate(&mut self, _file_number: u64, _file_name: &str) {

        }

        fn do_calculations(&mut self) {
            self.loop_analysis.generate_loop_stats(self.min_ttl, self.max_ttl);
        }

        fn print_output(&self) {
            self.loop_analysis.print_summary();
        }

        fn close(&mut self) {
            self.clear();
        }
    }
}