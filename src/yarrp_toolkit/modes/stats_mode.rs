pub mod stats_mode {
    use std::cmp::{max, min};
    use std::collections::{HashMap, HashSet};
    use std::net::Ipv6Addr;

    use clap::ArgMatches;
    use itertools::Itertools;

    use crate::modes::{ModeEnum, ModeTrait};
    use crate::structs::YarrpLine;

    pub struct StatsMode {
        pub mode: ModeEnum,
        max_ttl: u8,
        min_ttl: u8,
        ttl_map: HashMap<u8, i32>,
        hop_map: HashMap<u8, Vec<Ipv6Addr>>,
        type_map: HashMap<i32, i32>,
        responders_set: HashSet<Ipv6Addr>,
        target_set: HashSet<Ipv6Addr>,
    }

    impl StatsMode {
        pub fn new(matches: ArgMatches) -> StatsMode {
            let mode = ModeEnum::Stats;
            let mode_string = mode.to_string().to_lowercase();
            let _sub_matches = matches.subcommand_matches(mode_string).unwrap();

            StatsMode{
                mode,
                max_ttl: 0,
                min_ttl: 255,
                ttl_map: HashMap::new(),
                hop_map: HashMap::new(),
                type_map: HashMap::new(),
                responders_set: HashSet::new(),
                target_set: HashSet::new(),
            }
        }
    }

    impl ModeTrait for StatsMode  {
        fn get_mode(&self) -> ModeEnum {
            self.mode
        }

        fn no_input_capable(&self) -> bool {
            false
        }

        fn parse_comment_line(&mut self, _input: &str) {
            // Dummy implementation, just ignore comment lines
        }

        fn parse_string_line(&mut self, _input: &str) {
            let yarrp_line;
            if let Some(yarrp_line_temp) = YarrpLine::new(_input){
                yarrp_line = yarrp_line_temp;
            } else {
                return;
            }
            let input = yarrp_line;

            /* Working with response_type as key*/
            if input.sent_ttl == 63 {
                if let Some(value) = self.type_map.get_mut(&input.r_type) {
                    *value += 1;
                } else {
                    self.type_map.insert(input.r_type, 1);
                }
            }

            /* Working with ttl_sent as key*/
            if let Some(value) = self.ttl_map.get_mut(&input.sent_ttl) {
                *value += 1;
            } else {
                self.ttl_map.insert(input.sent_ttl, 1);
            }

            if 3 <= input.sent_ttl && input.sent_ttl <= 5{
                if let Some(value) = self.hop_map.get_mut(&input.sent_ttl) {
                    if ! value.contains(&input.hop){
                        value.push(input.hop);
                    }
                } else {
                    let mut new_vec:Vec<Ipv6Addr> = Vec::new();
                    new_vec.push(input.hop);
                    self.hop_map.insert(input.sent_ttl, new_vec);
                }
            }

            self.max_ttl = max(self.max_ttl, input.sent_ttl);
            self.min_ttl = min(self.min_ttl, input.sent_ttl);

            self.responders_set.insert(input.hop);
            self.target_set.insert(input.destination);
        }

        fn do_file_rotate(&mut self, _file_number: u64, _file_name: &str) {

        }

        fn do_calculations(&mut self) {
            //
        }

        fn print_output(&self) {

            println!("Min TTL encountered: {}", self.min_ttl);
            println!("Max TTL encountered: {}", self.max_ttl);

            println!("\nTTL Map:");

            for key in self.ttl_map.keys().sorted() {
                let value = self.ttl_map.get(key).unwrap();
                println!("{:03} : {:9}", key, value);
            }

            println!("\nHop Map:");

            for key in self.hop_map.keys().sorted() {
                let value = self.hop_map.get(key).unwrap();
                println!("{} : {:03}", key, value.len());
            }

            println!("\nResponse Type Map:");

            for key in self.type_map.keys().sorted() {
                let value = self.type_map.get(key).unwrap();
                println!("{:03} : {:010}", key, value);
            }

            println!("\nUnique Targets: {}", self.target_set.len());
            println!("Unique Responders: {}", self.responders_set.len());

        }

        fn close(&mut self) {

        }
    }
}