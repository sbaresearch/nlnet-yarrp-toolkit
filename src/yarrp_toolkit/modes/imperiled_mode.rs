pub mod imperiled_mode {
    use crate::modes::{ModeTrait, ModeEnum};
    use crate::{read_lines, create_dir_if_not_existing};

    use std::path::Path;
    use std::collections::HashSet;
    use std::fs::File;
    use std::process::exit;
    use std::io::Write;
    use log::{error};
    use clap::ArgMatches;

    pub struct ImperiledMode {
        pub mode: ModeEnum,
        pub output_directory: String,
        router_set: HashSet<String>,
        potential_imperiled: HashSet<String>,
        destination_set: HashSet<String>,
        shadowed_nets: HashSet<String>,
        ttl_filter: u8,
        ignored_shadowed: HashSet<String>,
        echo_replied: HashSet<String>,
    }

    impl ImperiledMode {
        pub fn new(matches: ArgMatches) -> ImperiledMode {
            let mode = ModeEnum::Imperiled;
            let mode_string = mode.to_string().to_lowercase();
            let sub_matches = matches.subcommand_matches(mode_string).unwrap();

            let routers_file;
            let mut shadowed_file = String::new();
            let mut output_directory;

            let mut router_set = HashSet::new();
            let mut shadowed_nets = HashSet::new();
            let mut ttl_filter = 0;

            // get parameter file path
            if let Some(temp_router_file) = sub_matches.value_of("router_file") {
                routers_file = temp_router_file.to_string();
            } else {
                eprintln!("Error loading router path from parameters!");
                exit(1);
            }

            if let Some(temp_shadowed_file) = sub_matches.value_of("shadowed_nets") {
                shadowed_file = temp_shadowed_file.to_string();
            }

            if let Some(temp_imperiled_path) = sub_matches.value_of("imperiled_directory") {
                output_directory = temp_imperiled_path.to_string();
            } else {
                eprintln!("Error loading output directory path from parameters!");
                exit(1);
            }

            if let Some(temp_ttl_filter) = sub_matches.value_of("ttl_filter") {
                if let Ok(temp_ttl_filter) = temp_ttl_filter.parse() {
                    ttl_filter = temp_ttl_filter;
                    println!("Filtering below {} ttl!", ttl_filter);
                } else {
                    eprintln!("ttl_filter must be an 8bit signed integer! (0 <= ttl_filter <= 255)");
                    exit(1);
                }
            }

            // check if output directory path exists, if not create it
            if ! create_dir_if_not_existing(&output_directory) {
                error!("Could not create output directory!");
                exit(1);
            }

            if !output_directory.ends_with('/') {
                output_directory = output_directory + "/";
            }

            // we can assume, output directory exists

            // check if router file exists and read line by line
            if let Ok(lines) = read_lines(&routers_file) {
                for line in lines {
                    if let Ok(str_line) = line {
                        let str_line = str_line.trim();
                        if str_line.starts_with("2a01:190") {
                            println!("Ignored nextlayer hop! {}", str_line);
                            continue;
                        } else {
                            router_set.insert(str_line.to_owned());
                        }
                    }
                }
                println!("Loaded {} routers", router_set.len());
            } else {
                eprintln!("Error reading routers file!");
                exit(1);
            }

            if shadowed_file.len() > 0 {
                if let Ok(lines) = read_lines(&shadowed_file) {
                    for line in lines {
                        if let Ok(str_line) = line {
                            let mut str_line = str_line.trim();
                            str_line = &str_line[0..str_line.len() - 3];
                            shadowed_nets.insert(str_line.to_owned());
                        }
                    }
                    println!("Loaded {} shadowed nets", shadowed_nets.len());
                }
            }

            ImperiledMode {
                mode,
                output_directory,
                router_set,
                potential_imperiled: HashSet::new(),
                destination_set: HashSet::new(),
                shadowed_nets,
                ttl_filter,
                ignored_shadowed: HashSet::new(),
                echo_replied: HashSet::new(),
            }
        }

        fn clear(&mut self) {
            // only clear the imperiled set, do not clear the router set or the output directory
            self.potential_imperiled.clear();
            self.ignored_shadowed.clear();
            self.shadowed_nets.clear();
            self.destination_set.clear();
            self.echo_replied.clear();
        }
    }

    impl ModeTrait for ImperiledMode {
        fn get_mode(&self) -> ModeEnum {
            return self.mode;
        }

        fn no_input_capable(&self) -> bool {
            false
        }

        fn parse_comment_line(&mut self, _input: &str) {
            // nothing to do here :)
        }

        fn parse_string_line(&mut self, input: &str) {
            // parse line, extract the destination as well as the hop that answered
            let vec = input.split(' ').collect::<Vec<&str>>();
            if vec.len() != 15 {
                eprintln!("Ignoring this line, not enough parameters");
                return;
            }

            let mut destination = vec[0];
            destination = destination.trim();

            let hop = vec[6];
            let sent_ttl: u8 = vec[5].parse().unwrap();
            let r_type: i32 = vec[3].parse().unwrap();
            let r_code: i32 = vec[4].parse().unwrap();

            if r_type == 129 && r_code == 0 {
                self.echo_replied.insert(destination.to_owned());
                return;
            }

            self.destination_set.insert(destination.to_owned());
            let router_loops = self.router_set.contains(hop);

            if self.ttl_filter > 0 && router_loops && sent_ttl <= self.ttl_filter {
                return;
            }

            if self.shadowed_nets.contains(destination) {
                self.ignored_shadowed.insert(destination.to_owned());
                return;
            }

            if router_loops {
                // println!("Found looping router in line to {}! {}", destination, hop);
                self.potential_imperiled.insert(destination.to_owned());
            }
        }

        fn do_file_rotate(&mut self, _file_number: u64, file_name: &str) {
            // grab file stem from original file
            println!("Received file rotation, storing results to file");
            let file_path = Path::new(file_name);
            let file_stem;
            if let Some(temp_file_stem) = file_path.file_stem() {
                file_stem = temp_file_stem.to_str().unwrap();
            } else {
                eprintln!("Could not get file stem from incoming file!");
                exit(1);
            }

            // build file path for output file
            let output_file = format!("{}{}.dst", self.output_directory, file_stem);

            let output_file_fp = File::create(&output_file);
            let mut output_file_fp = match output_file_fp {
                Ok(file) => file,
                Err(_) => {
                    println!("Could not create/open the imperiled output file!");
                    exit(1);
                }
            };

            // write routers involved in loops to file
            let mut written_nets = 0;
            for net in &self.echo_replied {
                if !self.potential_imperiled.contains(net) {
                    continue;
                }

                let formatted_data = format!("{}\n", net);
                let formatted_data = formatted_data.as_bytes();
                written_nets += 1;
                if let Err(x) = output_file_fp.write(formatted_data) {
                    eprintln!("Could not write to output file!");
                    eprintln!("{}", x);
                    exit(1);
                }
            }

            self.print_output();
            println!("{:10} imperiled nets!", written_nets);

            self.clear();
        }

        fn do_calculations(&mut self) {
            // nothing to do here :)
        }

        fn print_output(&self) {
            if self.destination_set.len() == 0 && self.potential_imperiled.len() == 0 && self.echo_replied.len() == 0 {
                // do not print anything if everything is 0
                return;
            }

            println!("Imperiled search done!");
            println!("{:10} destination nets.", self.destination_set.len());
            if self.ignored_shadowed.len() > 0 {
                println!("{:10} ignored shadowed nets.", self.ignored_shadowed.len());
            }
            println!("{:10} potential imperiled nets.", self.potential_imperiled.len());
            println!("{:10} answering destinations: ", self.echo_replied.len());
        }

        fn close(&mut self) {}
    }
}