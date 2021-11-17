pub mod loop_analysis {
    use std::collections::{HashMap, HashSet};
    use crate::structs::YarrpLine;
    use crate::structs::Route;
    use crate::analytics::{LoopStatistics, LoopStorage, LoopImperiled};
    use itertools::sorted;
    use log::{error};
    use std::fmt::Display;
    use std::hash::Hash;
    use crate::traits::IpAddrExt;
    use std::str::FromStr;
    use std::process::exit;

    pub struct LoopAnalysis<T> {
        pub ttl_map: HashMap<T, HashMap<u8, Vec<YarrpLine<T>>>>,
        pub looping_destinations: HashSet<T>,
        pub looping_routers: HashSet<T>,
        pub loop_statistics: LoopStatistics,
        pub loop_storage: LoopStorage<T>,
        loop_imperiled: LoopImperiled<T>,
    }

    impl<T: Display + Ord + Copy + Clone + Hash + IpAddrExt + FromStr> LoopAnalysis<T> {
        pub fn new(only_full_loops: bool, storage_path: String, imperiled_routers: &str, imperiled_blocklist: &str) -> LoopAnalysis<T> {

            let loop_storage = LoopStorage::new(only_full_loops, storage_path.clone());

            let imperiled_storage;
            let statistics_storage;

            if let Ok(temp_value) = loop_storage.get_storage_sub_dir("imperiled") {
                imperiled_storage = temp_value;
            } else {
                error!("Could not create path for imperiled data!");
                exit(1);
            }

            if let Ok(path) = loop_storage.get_storage_file("stats.csv") {
                statistics_storage = path;
            } else {
                error!("Could not create for stats.csv!");
                exit(1);
            }

            LoopAnalysis {
                ttl_map: HashMap::new(),
                looping_destinations: HashSet::new(),
                looping_routers: HashSet::new(),
                loop_statistics: LoopStatistics::new(only_full_loops, statistics_storage),
                loop_storage,
                loop_imperiled: LoopImperiled::from_router_file(&imperiled_routers, &imperiled_blocklist, &imperiled_storage)
            }
        }

        pub fn add_ttl(&mut self, yarrp_line: YarrpLine<T>) {
            let ttl_entry;
            match self.ttl_map.get_mut(&yarrp_line.destination) {
                None => {
                    self.ttl_map.insert(yarrp_line.destination, HashMap::new());
                    ttl_entry = self.ttl_map.get_mut(&yarrp_line.destination).unwrap();
                }
                Some(temp_ttl_entry) => {
                    ttl_entry = temp_ttl_entry;
                }
            }

            let ttl_answers;
            match ttl_entry.get_mut(&yarrp_line.sent_ttl) {
                None => {
                    ttl_entry.insert(yarrp_line.sent_ttl, Vec::new());
                    ttl_answers = ttl_entry.get_mut(&yarrp_line.sent_ttl).unwrap();
                }
                Some(temp_ttl_answers) => {
                    ttl_answers = temp_ttl_answers;
                }
            }

            ttl_answers.push(yarrp_line);
        }

        pub fn generate_loop_stats(&mut self, min_ttl: u8, max_ttl: u8) {
            for (_key, value) in &self.ttl_map {
                let mut route = Route::new(&value, min_ttl, max_ttl);

                if route.is_looping {
                    self.looping_destinations.insert(route.destination);
                    self.looping_routers.extend(route.get_loop_routers());
                    if let Err(_) = self.loop_storage.add_route_information(&route) {
                        error!("Could not add route information for route to {}", route.destination);
                    }
                }

                // Add imperiled check if so desired
                self.loop_imperiled.check_route(&mut route);
                self.loop_statistics.handle_route(&route);
            }

            self.loop_storage.update_statistics();

            if let Err(_) = self.loop_statistics.write_csv() {
                error!("Could not write loop statistics file!");
            }
        }

        pub fn clear(&mut self) {
            self.ttl_map.clear();
        }

        pub fn print_summary(&self) {
            let percentage = self.loop_statistics.get_loop_percentage() * 100.0;
            let credibility = self.loop_statistics.average_credibility * 100.0;

            // General Stats
            println!("Data line count: {}", self.loop_statistics.number_of_routes);
            println!("Amount of destination IPs: {}", self.ttl_map.len());

            println!();
            println!("Loops found: {}", self.looping_destinations.len());
            println!("Full Loops found: {}", self.loop_statistics.number_of_full_loops);
            println!("Percentage of routes containing loops: {:.02}%", percentage);
            println!("Unique Routers involved: {}", self.looping_routers.len());
            println!("Average Loop Length: {:.02}", self.loop_statistics.average_loop_length);
            println!("Imperiled Nets: {}", self.loop_statistics.number_of_imperiled);
            println!("Routes with spammer: {}", self.loop_statistics.number_of_spammers);
            println!("Routes with load balancers {}", self.loop_statistics.number_of_load_balancers);
            println!("Loop Lengths: ");
            let loop_lengths = self.loop_statistics.loop_size_map.keys();
            for length in sorted(loop_lengths)
            {
                let number = self.loop_statistics.loop_size_map.get(length).unwrap();
                println!("{:3}: {:7}", length, number);
            }

            println!();
            println!("Average credibility: {:.02}%", credibility);
            println!("Credibility Quantiles:");
            println!(" <25%: {:10}", self.loop_statistics.credibility_quantils.0);
            println!(" <50%: {:10}", self.loop_statistics.credibility_quantils.1);
            println!(" <75%: {:10}", self.loop_statistics.credibility_quantils.2);
            println!(">=75%: {:10}", self.loop_statistics.credibility_quantils.3);

            println!();
            println!("Imperiled Routes: ");
            self.loop_imperiled.print_stats();
        }
    }
}