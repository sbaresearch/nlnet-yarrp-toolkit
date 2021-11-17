mod yarrp_line;
mod config;
mod route;
mod couting_file;
mod yarrp_error;
mod asn_tree;
mod zmap;
mod csv_structs;
mod loop_info;

pub use yarrp_line::yarrp_line::YarrpLine;
pub use config::config::Config;
pub use route::route::Route;
pub use couting_file::couting_file::{CountingEntity, CountingVoid, CountingFile};
pub use yarrp_error::yarrp_error::YarrpError;
pub use asn_tree::asn_tree::{ASNTree, ASNTreeRoot, ASNTreeNode};
pub use zmap::{ZMAPLine, ZMAPClassification};
pub use csv_structs::{LoopDensityOutput, ASNLoopEntry, ASNRouterEntry, ASNShadowedResults, ASNShadowedOutput, ShadowedAnswer, ASNIPAttribution};
pub use loop_info::{SimpleLoopOutput, AdvancedLoopOutput, ShadowedPreceding};

use std::collections::{HashMap, HashSet};
use ipnet::IpNet;

pub type MapSetString = HashMap<String, HashSet<String>>;
pub type MapSetT<T> = HashMap<String, HashSet<T>>;
pub type MapVecT<T> = HashMap<String, Vec<T>>;
pub type ASNCSVOutput = HashMap<IpNet, Vec<ASNShadowedOutput>>;

use serde::{Serializer};

pub fn string_set_ser<S>(string_set: &HashSet<String>, s: S) -> Result<S::Ok, S::Error>
    where S: Serializer {

    let mut string = String::new();
    for item in string_set {
        let tmp_str;
        if string.len() == 0 {
            tmp_str = item.to_string();
        } else {
            tmp_str = format!(";{}", item);
        }
        string += &tmp_str;
    }

    s.serialize_str(&string)
}

pub fn string_vec_ser<S>(string_set: &Vec<String>, s: S) -> Result<S::Ok, S::Error>
    where S: Serializer {

    let mut string = String::new();
    for item in string_set {
        let tmp_str;
        if string.len() == 0 {
            tmp_str = item.to_string();
        } else {
            tmp_str = format!(";{}", item);
        }
        string += &tmp_str;
    }

    s.serialize_str(&string)
}

pub fn count_ser<S,T>(set: &Vec<T>, s: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
    let count = set.len() as u64;
    s.serialize_u64(count)
}