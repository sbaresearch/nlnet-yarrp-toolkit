use std::fmt::Formatter;
use serde_derive::{Deserialize};

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ZMAPClassification {
    EchoReply,
    Timxceed,
    Unreach,
    #[serde(rename = "unreach_noroute")]
    UnreachNoRoute,
    #[serde(rename = "unreach_addr")]
    UnreachAddr,
    #[serde(rename = "unreach_rejectroute")]
    UnreachRejectRoute,
    #[serde(rename = "unreach_noport")]
    UnreachNoPort,
    #[serde(rename = "unreach_admin")]
    UnreachAdmin,
    #[serde(rename = "unreach_policy")]
    UnreachPolicy,
    Paramprob,
}

impl std::fmt::Display for ZMAPClassification {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let printable = match self {
            ZMAPClassification::EchoReply => "echoreply",
            ZMAPClassification::Timxceed => "timxceed",
            ZMAPClassification::Unreach => "unreach",
            ZMAPClassification::UnreachNoRoute => "unreach_noroute",
            ZMAPClassification::UnreachAddr => "unreach_addr",
            ZMAPClassification::UnreachRejectRoute => "unreach_rejectroute",
            ZMAPClassification::UnreachNoPort => "unreach_noroute",
            ZMAPClassification::UnreachAdmin => "unreach_admin",
            ZMAPClassification::UnreachPolicy => "unreach_policy",
            ZMAPClassification::Paramprob => "paramprob"
        };
        write!(f, "{}", printable)
    }
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
pub struct ZMAPLine {
    pub saddr: String,
    pub daddr: String,
    #[serde(rename = "orig-dest-ip")]
    pub orig_dest_ip: String,
    pub original_ttl: u8,
    pub ipid: u64,
    pub ttl: u8,
    pub classification: ZMAPClassification,
    pub timestamp_ts: u64,
    pub timestamp_us: u64,
}
