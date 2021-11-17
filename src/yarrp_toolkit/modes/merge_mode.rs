pub mod merge_mode {
    use clap::ArgMatches;

    use crate::modes::{ModeEnum, ModeTrait};
    use std::collections::HashSet;
    use std::fs::File;
    use std::process::exit;
    use std::io::Write;

    pub struct MergeMode {
        pub mode: ModeEnum,
        pub output_file: String,
        unique_set: HashSet<String>,
        ignored: u64,
    }

    impl MergeMode {
        pub fn new(matches: ArgMatches) -> MergeMode {
            let mode = ModeEnum::Merge;
            let mode_string = mode.to_string().to_lowercase();
            let sub_matches = matches.subcommand_matches(mode_string).unwrap();

            let output_file = sub_matches.value_of("output").unwrap().to_owned();
            println!("Writing to outputfile {}", output_file);

            MergeMode {
                mode,
                output_file,
                unique_set: HashSet::new(),
                ignored: 0,
            }
        }

        pub fn clear(&mut self) {}
    }

    impl ModeTrait for MergeMode {
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
            if !self.unique_set.insert(_input.to_string()) {
                self.ignored += 1;
            }
        }

        fn do_file_rotate(&mut self, _file_number: u64, _file_name: &str) {

        }

        fn do_calculations(&mut self) {

        }

        fn print_output(&self) {
            println!("Added {}, ignored {}", self.unique_set.len(), self.ignored);

            let output_file = File::create(&self.output_file);
            let mut output_file = match output_file {
                Ok(file) => file,
                Err(_) => {
                    println!("Could not create/open the output file!");
                    exit(1);
                }
            };

            for item in &self.unique_set {
                let formatted_data = format!("{}\n", item);
                let formatted_data = formatted_data.as_bytes();
                if let Err(x) = output_file.write(formatted_data) {
                    eprintln!("Could not write to output file!");
                    eprintln!("{}", x);
                    exit(1);
                }
            }
        }

        fn close(&mut self) {
            self.clear();
        }
    }
}