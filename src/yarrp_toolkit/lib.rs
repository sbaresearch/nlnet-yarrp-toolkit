extern crate tokio;
extern crate glob;

// Add own mods to the structure
pub mod modes;
pub mod structs;
pub mod analytics;
pub mod traits;
pub mod helpers;

use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;

use log::{error};

use modes::{
    TargetMode,
    ChunkMode,
    ReimagineMode,
    StatsMode,
    LoopsMode,
    ImperiledMode,
    MergeMode,
    ExportMode,
    ScatterMode,
    P50TargetMode,
    P50Analysis
};
use crate::modes::{ModeTrait, ModeEnum, PostLoopStatsMode, MergeIdMode, ASNMode};
use clap::ArgMatches;
use std::fs;
use std::net::{Ipv6Addr, Ipv4Addr};

// The output is wrapped in a Result to allow matching on errors
// Returns an Iterator to the Reader of the lines of the file.
pub fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
    where P: AsRef<Path>, {
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

pub fn create_dir_if_not_existing(path: &str) -> bool {
    let output_path = Path::new(&path);
    if output_path.exists() && !output_path.is_dir() {
        // already exists and is not dir
        error!("Output path exists, but isnt a directory!");
        return false;
    } else if !output_path.exists() {
        if let Err(test) = fs::create_dir_all(output_path) {
            // directory does not exist, lets create it
            eprintln!("Could not create output directories");
            eprintln!("{}", test);
            return false;
        }
    }
    return true;
}

pub fn get_correct_mode(subcommand: ModeEnum, matches: ArgMatches, v4_mode: bool) -> Box<dyn ModeTrait> {
    if v4_mode {
        return get_correct_mode_v4(subcommand, matches);
    }
    return get_correct_mode_v6(subcommand, matches);
}

pub fn get_correct_mode_v4(subcommand: ModeEnum, matches: ArgMatches) -> Box<dyn ModeTrait> {
    match subcommand {
        ModeEnum::Stats => Box::new(StatsMode::new(matches)),
        ModeEnum::Reimagine => Box::new(ReimagineMode::new(matches)),
        ModeEnum::Chunk => Box::new(ChunkMode::new(matches)),
        ModeEnum::Target => Box::new(TargetMode::<Ipv4Addr>::new(matches)),
        ModeEnum::Loops => Box::new(LoopsMode::<Ipv4Addr>::new(matches)),
        ModeEnum::Export => Box::new(ExportMode::new(matches)),
        ModeEnum::Merge => Box::new(MergeMode::new(matches)),
        ModeEnum::Imperiled => Box::new(ImperiledMode::new(matches)),
        ModeEnum::PostLoopStats => Box::new(PostLoopStatsMode::<Ipv4Addr>::new(matches)),
        ModeEnum::MergeId => Box::new(MergeIdMode::new(matches)),
        ModeEnum::Scatter => Box::new(ScatterMode::<Ipv4Addr>::new(matches)),
        ModeEnum::P50Target => Box::new(P50TargetMode::<Ipv4Addr>::new(matches)),
        ModeEnum::P50Analysis => Box::new(P50Analysis::<Ipv4Addr>::new(matches)),
        ModeEnum::ASN => Box::new(ASNMode::new(matches, true))
    }
}


pub fn get_correct_mode_v6(subcommand: ModeEnum, matches: ArgMatches) -> Box<dyn ModeTrait> {
    match subcommand {
        ModeEnum::Stats => Box::new(StatsMode::new(matches)),
        ModeEnum::Reimagine => Box::new(ReimagineMode::new(matches)),
        ModeEnum::Chunk => Box::new(ChunkMode::new(matches)),
        ModeEnum::Target => Box::new(TargetMode::<Ipv6Addr>::new(matches)),
        ModeEnum::Loops => Box::new(LoopsMode::<Ipv6Addr>::new(matches)),
        ModeEnum::Export => Box::new(ExportMode::new(matches)),
        ModeEnum::Merge => Box::new(MergeMode::new(matches)),
        ModeEnum::Imperiled => Box::new(ImperiledMode::new(matches)),
        ModeEnum::PostLoopStats => Box::new(PostLoopStatsMode::<Ipv6Addr>::new(matches)),
        ModeEnum::MergeId => Box::new(MergeIdMode::new(matches)),
        ModeEnum::Scatter => Box::new(ScatterMode::<Ipv6Addr>::new(matches)),
        ModeEnum::P50Target => Box::new(P50TargetMode::<Ipv6Addr>::new(matches)),
        ModeEnum::P50Analysis => Box::new(P50Analysis::<Ipv6Addr>::new(matches)),
        ModeEnum::ASN => Box::new(ASNMode::new(matches, false))
    }
}
