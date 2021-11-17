pub mod loop_statistics {
    use std::collections::HashMap;
    use std::path::PathBuf;
    use log::{info, warn, error, trace};

    use crate::structs::Route;
    use crate::structs::YarrpError;
    use csv::StringRecord;
    use std::process::exit;
    use itertools::sorted;
    use std::fmt::Display;
    use std::hash::Hash;
    use crate::traits::IpAddrExt;

    pub struct LoopStatistics {
        pub only_full_routes: bool,
        pub storage_path: PathBuf,
        pub number_of_routes: u64,
        pub number_of_loops: u64,
        pub loop_size_map: HashMap<u8, u64>,
        pub average_loop_length: f64,
        pub number_of_load_balancers: u64,
        pub number_of_spammers: u64,
        pub number_of_full_loops: u64,
        pub number_of_imperiled: u64,
        pub average_credibility: f64,
        pub credibility_quantils: (u32, u32, u32, u32),
    }

    impl LoopStatistics {
        pub fn new(only_full_routes: bool, storage_path: PathBuf) -> LoopStatistics {

            // check if storage file exists
            let path = &storage_path.to_path_buf();

            let mut loop_statistics = LoopStatistics {
                only_full_routes,
                storage_path,
                number_of_routes: 0,
                number_of_loops: 0,
                loop_size_map: HashMap::new(),
                average_loop_length: 0.0,
                number_of_load_balancers: 0,
                number_of_spammers: 0,
                number_of_full_loops: 0,
                number_of_imperiled: 0,
                average_credibility: 0.0,
                credibility_quantils: (0, 0, 0, 0),
            };

            if path.exists() {
                info!("CSV File exists, attempting to read it...");
                if let Err(_) = loop_statistics.read_csv(&path) {
                    error!("Error while reading or parsing csv file!");
                    exit(1);
                }
            } else {
                if let Some(storage_path_str) = path.to_str() {
                    info!("No stats file found at {}.", storage_path_str);
                } else {
                    error!("Could not parse storage_path to string.");
                    info!("No stats file found");
                }
            }

            return loop_statistics;
        }

        fn read_csv(&mut self, stats_file: &PathBuf) -> Result<(), YarrpError> {
            let mut csv_reader = csv::Reader::from_path(stats_file)?;
            trace!("csv file has headers: {}", csv_reader.has_headers());
            for record in csv_reader.records() {
                let record = record?;
                self.parse_record(&record)?;
            }
            Ok(())
        }

        fn parse_record(&mut self, record: &StringRecord) -> Result<(), YarrpError> {
            // grab key and value
            if let (Some(key), Some(value)) = (record.get(0), record.get(1)) {
                if key.starts_with("loop_length_") {
                    // grab loop length
                    let split = key.split("_").collect::<Vec<&str>>();
                    let loop_length;
                    if let Some(temp_loop_length) = split.get(split.len() - 1) {
                        loop_length = temp_loop_length;
                    } else {
                        return Err(YarrpError::CouldNotReadError);
                    }
                    let loop_length: u8 = loop_length.parse()?;
                    let value: u64 = value.parse()?;

                    self.loop_size_map.insert(loop_length.clone(), value);
                } else {
                    match key {
                        "only_full_routes" => {
                            if (value == "1" && !self.only_full_routes) || (value == "0" && self.only_full_routes) {
                                error!("Existing Stats file differes on only_full_routes!");
                                error!("File: {}, Runtime: {}", value, self.only_full_routes);
                                return Err(YarrpError::NotCompatibleError);
                            }
                        }
                        "routes" => self.number_of_routes = value.parse()?,
                        "loops" => self.number_of_loops = value.parse()?,
                        "load_balancers" => self.number_of_load_balancers = value.parse()?,
                        "spammers" => self.number_of_spammers = value.parse()?,
                        "full_loops" => self.number_of_full_loops = value.parse()?,
                        "imperiled" => self.number_of_imperiled = value.parse()?,
                        "average_credibility" => self.average_credibility = value.parse()?,
                        _ => { warn!("Ignoring unknown Option '{}' from record!", key); }
                    }
                }
                trace!("Read key {} with value {}", key, value);

                Ok(())
            } else {
                error!("Could not get key or value from csv record");
                return Err(YarrpError::CouldNotReadError);
            }
        }

        pub fn write_csv(&self) -> Result<(), YarrpError> {
            let mut csv_writer = csv::Writer::from_path(&self.storage_path)?;

            if self.only_full_routes {
                csv_writer.write_record(&["only_full_routes", "1"])?;
            } else {
                csv_writer.write_record(&["only_full_routes", "0"])?;
            }

            let _ = csv_writer.write_record(&["routes", &self.number_of_routes.to_string()])?;
            let _ = csv_writer.write_record(&["loops", &self.number_of_loops.to_string()])?;
            let _ = csv_writer.write_record(&["load_balancers", &self.number_of_load_balancers.to_string()])?;
            let _ = csv_writer.write_record(&["spammers", &self.number_of_spammers.to_string()])?;
            let _ = csv_writer.write_record(&["full_loops", &self.number_of_full_loops.to_string()])?;
            let _ = csv_writer.write_record(&["imperiled", &self.number_of_imperiled.to_string()])?;
            let _ = csv_writer.write_record(&["average_credibility", &self.average_credibility.to_string()])?;

            let keys = &self.loop_size_map.keys().collect::<Vec<&u8>>();
            let keys = sorted(keys);

            for key in keys {
                if let Some(value) = self.loop_size_map.get(key) {
                    let csv_key = format!("loop_length_{}", key);
                    let _ = csv_writer.write_record(&[&csv_key, &value.to_string()]);
                }
            }
            Ok(())
        }

        pub fn handle_route<T: Display + Copy + Clone + Eq + Hash + IpAddrExt>(&mut self, route: &Route<T>) {
            let counter = self.number_of_routes as f64;
            let loop_counter = self.number_of_loops as f64;

            self.add_to_credibility(route.credibility, counter);

            if (self.only_full_routes && route.has_full_loop) || (!self.only_full_routes && route.is_looping) {
                self.add_to_loops(route.loop_len(), loop_counter);
                self.number_of_loops += 1;
            }

            if route.has_spammer {
                self.number_of_spammers += 1;
            }

            if route.has_load_balancer {
                self.number_of_load_balancers += 1;
            }

            if route.has_full_loop {
                self.number_of_full_loops += 1;
            }

            if route.is_imperiled {
                self.number_of_imperiled += 1;
            }

            self.number_of_routes += 1;
        }

        fn add_to_credibility(&mut self, credibility: f64, counter: f64) {
            self.average_credibility = (self.average_credibility * counter + credibility) / (counter + 1.0);
            if credibility < 0.25 {
                self.credibility_quantils.0 += 1;
            } else if credibility < 0.5 {
                self.credibility_quantils.1 += 1;
            } else if credibility < 0.75 {
                self.credibility_quantils.2 += 1;
            } else {
                self.credibility_quantils.3 += 1;
            }
        }

        fn add_to_loops(&mut self, loop_len: u8, counter: f64) {
            self.average_loop_length = (self.average_loop_length * counter + loop_len as f64) / (counter + 1.0);

            match self.loop_size_map.get_mut(&loop_len) {
                None => {
                    self.loop_size_map.insert(loop_len, 1);
                }
                Some(loop_number) => {
                    *loop_number += 1;
                }
            }
        }

        pub fn get_loop_percentage(&self) -> f64 {
            return self.number_of_loops as f64 / self.number_of_routes as f64;
        }
    }
}