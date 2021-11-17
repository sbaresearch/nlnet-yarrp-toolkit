pub mod reimagine_mode {
    use std::fs::File;
    use std::io::{Write};
    use std::process::exit;

    use clap::ArgMatches;

    use crate::modes::{ModeEnum, ModeTrait};
    use std::collections::HashSet;

    pub struct ReimagineMode {
        pub mode: ModeEnum,
        reimagine_count: u64,
        total_count: u64,
        max_ttl: String,
        output_file: File,
        ip_set: HashSet<String>,
        ignored_double: u64,
    }

    impl ReimagineMode {

        pub fn new(matches: ArgMatches) -> ReimagineMode {
            let mode = ModeEnum::Reimagine;
            let mode_string = mode.to_string().to_lowercase();
            let sub_matches = matches.subcommand_matches(mode_string).unwrap();

            let max_ttl = sub_matches.value_of("max_ttl").unwrap().to_owned();
            let output_path = sub_matches.value_of("output").unwrap();

            let output_file = File::create(output_path);
            let output_file = match output_file {
                Ok(file) => file,
                Err(_) => {
                    println!("Could not create/open the output file!");
                    exit(1);
                }
            };

            println!("Working with output file {}", output_path);

            ReimagineMode{
                mode,
                reimagine_count: 0,
                total_count: 0,
                max_ttl,
                output_file,
                ip_set: HashSet::new(),
                ignored_double: 0
            }
        }

        pub fn clear(&mut self) {
            self.total_count = 0;
            self.reimagine_count = 0;
        }
    }

    impl ModeTrait for ReimagineMode  {
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
            let vec = input.split(' ').collect::<Vec<&str>>();
            let destination = vec[0].trim().to_owned();
            let sent_ttl = vec[5];
            let response_type = vec[3];

            self.total_count += 1;

            if sent_ttl == self.max_ttl && response_type == "3" {
                // check if destination already in set
                if ! self.ip_set.insert(destination.clone()) {
                    self.ignored_double += 1;
                    return;
                }

                self.reimagine_count += 1;
                if let Err(x) = self.output_file.write(format!("{}\n", destination).as_bytes()) {
                    eprintln!("Could not write to output filez!");
                    eprintln!("{}", x);
                    exit(1);
                }
            }
        }

        fn do_file_rotate(&mut self, _file_number: u64, _file_name: &str) {

        }

        fn do_calculations(&mut self) {
            // do something?
        }

        fn print_output(&self) {
            println!("Total Count:     {:>15}", self.total_count);
            println!("Reimagine Count: {:>15}", self.reimagine_count);
            println!("Ignored Double:  {:>15}", self.ignored_double);
        }

        fn close(&mut self) {
            self.clear();
        }
    }
}