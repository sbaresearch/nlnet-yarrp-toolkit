pub mod config {
    use crate::modes::ModeTrait;

    pub struct Config {
        pub input_files: Vec<String>,
        pub line_count: u64,
        pub debug_level: u64,
        pub quiet: bool,
        pub mode_item: Box<dyn ModeTrait>,
        pub no_input: bool,
    }

}