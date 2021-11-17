pub mod couting_file {
    use std::fs::{File, OpenOptions};
    use std::path::{Path};
    use log::{error};
    use std::io::{Write};
    use std::fmt::Display;

    pub enum CountingEntity {
        NoWrite(CountingVoid),
        Write(CountingFile),
    }

    impl CountingEntity{
        pub fn write_line(&mut self, input: &str) -> bool {
            match self {
                CountingEntity::NoWrite(counting) => counting.write_line(input),
                CountingEntity::Write(counting) => counting.write_line(input),
            }
        }

        pub fn write_ip_line<T: Display + Clone + Copy>(&mut self, input: &T) -> bool {
            match self {
                CountingEntity::NoWrite(counting) => counting.write_ip_line(input),
                CountingEntity::Write(counting) => counting.write_ip_line(input),
            }
        }

        pub fn len(&self) -> u64 {
            match self {
                CountingEntity::NoWrite(counting) => counting.len(),
                CountingEntity::Write(counting) => counting.len(),
            }
        }
    }

    impl From<CountingVoid> for CountingEntity {
        fn from(item: CountingVoid) -> CountingEntity {
            CountingEntity::NoWrite(item)
        }
    }

    impl From<CountingFile> for CountingEntity {
        fn from(item: CountingFile) -> CountingEntity {
            CountingEntity::Write(item)
        }
    }

    pub struct CountingVoid {
        line_counter: u64
    }

    impl CountingVoid {
        pub fn new(_file_path: &Path) -> Option<CountingVoid> {
            // just ignore the path :)
            Some(CountingVoid {
                line_counter: 0,
            })
        }

        pub fn from_str(file_path: &str) -> Option<CountingVoid> {
            let path = Path::new(file_path);
            CountingVoid::new(path)
        }

        pub fn write_line(&mut self, _input: &str) -> bool {
            self.line_counter += 1;
            return true;
        }

        pub fn write_ip_line<T: Display + Clone + Copy>(&mut self, _input: &T) -> bool {
            self.line_counter += 1;
            return true;
        }

        pub fn len(&self) -> u64 {
            self.line_counter
        }
    }

    pub struct CountingFile {
        writing_file: File,
        line_counter: u64,
        file_path: String,
    }

    impl CountingFile {
        pub fn new(file_path: &Path) -> Option<CountingFile> {
            let parent;
            let writing_file;

            let path_str;
            if let Some(temp_path_str) = file_path.to_str() {
                path_str = temp_path_str;
            } else {
                error!("Could not get string from path!");
                return None;
            }

            if let Some(temp_parent) = file_path.parent() {
                parent = temp_parent;
            } else {
                error!("Could not create parent dir for {}!", path_str);
                return None;
            }

            if !parent.exists() {
                error!("Parent of counting file {} does not exist!", path_str);
                return None;
            }

            match OpenOptions::new().append(true).create(true).open(file_path) {
                Ok(temp_writing_file) => {
                    writing_file = temp_writing_file;
                }
                Err(error) => {
                    error!("Could not create file ptions for counting file {}!", path_str);
                    error!("{}", error);
                    return None;
                }
            }

            Some(CountingFile {
                writing_file,
                line_counter: 0,
                file_path: path_str.to_owned(),
            })
        }

        pub fn from_str(file_path: &str) -> Option<CountingFile> {
            let path = Path::new(file_path);
            CountingFile::new(path)
        }

        pub fn write_line(&mut self, input: &str) -> bool {
            self.line_counter += 1;
            let formatted_line = format!("{}\n", input);
            if let Err(_) = self.writing_file.write(formatted_line.as_bytes()) {
                error!("Could not write data to file {}!", self.file_path);
                // ToDo: Figure out way to handle this
                return false;
            }
            return true;
        }

        pub fn write_ip_line<T: Display + Clone + Copy>(&mut self, input: &T) -> bool {
            self.line_counter += 1;
            let formatted_line = format!("{}\n", input);
            if let Err(_) = self.writing_file.write(formatted_line.as_bytes()) {
                error!("Could not write data to file {}!", self.file_path);
                // ToDo: Figure out way to handle this
                return false;
            }
            return true;
        }

        pub fn len(&self) -> u64 {
            self.line_counter
        }
    }
}