#[macro_use]
extern crate clap;
extern crate itertools;
extern crate pbr;
extern crate log;
extern crate env_logger;
extern crate md5;
extern crate rand;
extern crate rand_pcg;
extern crate serde_derive;

// Add own mods to the structure
use yarrp_toolkit::{read_lines, get_correct_mode};
use yarrp_toolkit::structs::Config;

// Mode Imports
use yarrp_toolkit::modes::ModeEnum;
use std::process::exit;
use std::time::Duration;

use clap::App;
use pbr::ProgressBar;

use log::{info, error, LevelFilter, debug, trace};
use env_logger::Env;

fn parse_args() -> Config {
    // The YAML file is found relative to the current file, similar to how modules are found
    let yaml = load_yaml!("cli.yml");
    let matches = App::from_yaml(yaml).get_matches();
    let subcommand: ModeEnum;

    let mut be_quiet = false;
    let mut ipv4_mode = false;
    let mut no_input = false;

    if let Some(temp_subcommand) =  matches.subcommand_name() {
        subcommand = temp_subcommand.parse().unwrap();
    } else {
        println!("No subcommand called!");
        println!("{}", matches.usage());
        exit(0);
    }

    let mut input_files = Vec::new();
    let debug_level = matches.occurrences_of("verbose");
    if let Some(lines) = matches.values_of("INPUT") {
        for line in lines {
            input_files.push(line.to_owned());
        }
    }

    let mut line_count = 10000000;
    if matches.occurrences_of("line_count") > 0 {
        let temp_line_count = matches.value_of("line_count").unwrap();
        line_count = temp_line_count.parse().unwrap();
        info!("Line Count: {}", line_count);
    }

    if matches.occurrences_of("quiet") > 0 {
        be_quiet = true;
        info!("Setting quiet to {}", be_quiet);
    }

    if matches.occurrences_of("ipv4") > 0 {
        ipv4_mode = true;
        info!("Switching to IPv4 handling!");
    }

    if matches.occurrences_of("no_input") > 0 {
        no_input = true;
        info!("Switching to postprocessing without input.");
    }

    let mode_item = get_correct_mode(subcommand, matches, ipv4_mode);

    Config{
        input_files,
        line_count,
        quiet: be_quiet,
        debug_level,
        mode_item,
        no_input
    }
}

fn main() {

    let mut env_builder = env_logger::builder();
    let env = Env::new().filter("YARRP_LOG");

    env_builder.filter_level(LevelFilter::Info);
    env_builder.parse_env(env);
    env_builder.init();

    trace!("Printing trace level!");
    debug!("Printing debug level!");

    let mut config = parse_args();

    if config.mode_item.no_input_capable() {
        info!("Module {} not reading global input files, skipping reading", config.mode_item.get_mode());
    } else if ! config.no_input || config.input_files.len() == 0 {
        read_input_files(&mut config);
    }

    config.mode_item.do_calculations();
    config.mode_item.print_output();
    config.mode_item.close();
}

fn read_input_files(config: &mut Config) {
    let mut pb = ProgressBar::new(config.line_count);
    pb.set_max_refresh_rate(Some(Duration::from_millis(100)));

    info!("Working with {} input files.", config.input_files.len());
    let mut file_number = 0;

    for file_path in &config.input_files {
        info!("Using file {}", file_path);

        if let Ok(lines) = read_lines(&file_path) {
            // Consumes the iterator, returns an (Optional) String
            for line in lines {
                if let Ok(str_line) = line {

                    if str_line.starts_with('#') {
                        // remove leading '#' and resulting whitespaces
                        let str_line = str_line[1..].trim();
                        config.mode_item.parse_comment_line(&str_line);
                    } else {
                        config.mode_item.parse_string_line(&str_line);
                    }

                    if !config.quiet && pb.inc() == pb.total{
                        pb.total = pb.total + config.line_count;
                    }
                } else {
                    error!("Could not read line?");
                }

            }
        } else {
            error!("Input file not found!");
            exit(1);
        }

        config.mode_item.do_file_rotate(file_number, &file_path);
        info!("File ({}) {} finished.", file_number, &file_path);
        file_number += 1;

    }

    if !config.quiet {
        pb.finish_print("done");
        println!();
    }

}
