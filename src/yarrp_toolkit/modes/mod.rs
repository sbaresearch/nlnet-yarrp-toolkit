use std::fmt::{Display, Formatter};
use std::fmt;
use std::str::FromStr;
use clap::ArgMatches;
use std::path::{PathBuf, Path};
use std::process::exit;
use log::{error};

mod reimagine_mode;
mod stats_mode;
mod chunk_mode;
mod target_mode;
mod loops_mode;
mod export_mode;
mod merge_mode;
mod imperiled_mode;
mod post_loop_stats_mode;
mod merge_id_mode;
mod scatter_mode;
mod p50_target_mode;
mod p50_analysis;
mod asn_mode;

pub use reimagine_mode::reimagine_mode::ReimagineMode;
pub use stats_mode::stats_mode::StatsMode;
pub use chunk_mode::chunk_mode::ChunkMode;
pub use target_mode::target_mode::TargetMode;
pub use loops_mode::loops_mode::LoopsMode;
pub use export_mode::export_mode::ExportMode;
pub use merge_mode::merge_mode::MergeMode;
pub use imperiled_mode::imperiled_mode::ImperiledMode;
pub use post_loop_stats_mode::post_loop_stats_mode::PostLoopStatsMode;
pub use merge_id_mode::merge_id_mode::MergeIdMode;
pub use scatter_mode::scatter_mode::ScatterMode;
pub use p50_target_mode::p50_target_mode::P50TargetMode;
pub use p50_analysis::p50_analysis::P50Analysis;
pub use asn_mode::asn_mode::ASNMode;
use std::collections::HashSet;
use ipnet::IpNet;
use crate::structs::YarrpError;
use crate::read_lines;


#[derive(Copy, Clone)]
pub enum ModeEnum {
    Chunk,
    Target,
    Reimagine,
    Stats,
    Loops,
    Export,
    Merge,
    Imperiled,
    PostLoopStats,
    MergeId,
    Scatter,
    P50Target,
    P50Analysis,
    ASN
}

impl FromStr for ModeEnum {
    type Err = ();

    fn from_str(input: &str) -> Result<ModeEnum, Self::Err> {
        let input = input.to_lowercase();
        match input.as_str() {
            "chunk" => Ok(ModeEnum::Chunk),
            "target" => Ok(ModeEnum::Target),
            "reimagine" => Ok(ModeEnum::Reimagine),
            "stats" => Ok(ModeEnum::Stats),
            "loops" => Ok(ModeEnum::Loops),
            "export" => Ok(ModeEnum::Export),
            "merge" => Ok(ModeEnum::Merge),
            "imperiled" => Ok(ModeEnum::Imperiled),
            "postloopstats" => Ok(ModeEnum::PostLoopStats),
            "mergeid" => Ok(ModeEnum::MergeId),
            "scatter" => Ok(ModeEnum::Scatter),
            "p50targets" => Ok(ModeEnum::P50Target),
            "p50analysis" => Ok(ModeEnum::P50Analysis),
            "asn" => Ok(ModeEnum::ASN),
            _ => Err(())
        }
    }
}

impl Display for ModeEnum {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mode_enum_string = match self {
            ModeEnum::Chunk => "Chunk",
            ModeEnum::Target => "Target",
            ModeEnum::Reimagine => "Reimagine",
            ModeEnum::Stats => "Stats",
            ModeEnum::Loops => "Loops",
            ModeEnum::Export => "Export",
            ModeEnum::Merge => "Merge",
            ModeEnum::Imperiled => "Imperiled",
            ModeEnum::PostLoopStats => "PostLoopStats",
            ModeEnum::MergeId => "MergeId",
            ModeEnum::Scatter => "Scatter",
            ModeEnum::P50Target => "P50Targets",
            ModeEnum::P50Analysis => "P50Analysis",
            ModeEnum::ASN => "ASN"
        };

        write!(f, "{}", mode_enum_string)
    }
}

pub trait ModeTrait {
    fn get_mode(&self) -> ModeEnum;

    fn no_input_capable(&self) -> bool;

    fn parse_comment_line(&mut self, input: &str);

    fn parse_string_line(&mut self, input: &str);

    fn do_file_rotate(&mut self, file_number: u64, file_name: &str);

    fn do_calculations(&mut self);

    fn print_output(&self);

    fn close(&mut self);
}

pub fn load_path_or_default(args: &ArgMatches, path: &str, default: &str) -> PathBuf {
    if ! args.is_present(path) {
        return PathBuf::from(default);
    }
    return load_path_param(args, path);
}

pub fn  load_path_param(args: &ArgMatches, path: &str) -> PathBuf {
    let return_path;
    if let Some(value) = args.value_of(path) {
        return_path = value;
    } else {
        error!("Could not read {}!", path);
        exit(1);
    }
    return PathBuf::from(return_path);
}

pub fn parse_param<T>(args: &ArgMatches, param_name: &str, default: T) -> T
    where T: FromStr {
    let param: T;

    if let Some(value) = args.value_of(param_name) {
        if let Ok(parsed_value) = value.parse() {
            param = parsed_value;
        } else {
            error!("Could not parse parameter {}", param_name);
            exit(1);
        }
    } else {
        param = default;
    }

    return param;
}

pub fn read_blocklist(path: &Path) -> Result<HashSet<IpNet>, YarrpError> {
    let mut return_set = HashSet::new();

    let input_lines = read_lines(path)?;
    for line in input_lines {
        let line = line?;

        let ipnet = IpNet::from_str(&line)?;
        return_set.insert(ipnet);
    }

    Ok(return_set)
}
