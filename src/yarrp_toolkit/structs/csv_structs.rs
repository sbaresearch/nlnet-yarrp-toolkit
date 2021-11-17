use serde::{Serialize};
use std::collections::HashSet;
use std::net::IpAddr;
use crate::structs::{string_set_ser, string_vec_ser};
use ipnet::IpNet;

#[derive(Serialize)]
pub struct LoopDensityOutput {
    pub(crate) loop_id: String,
    pub(crate) address_count: u64,
    pub(crate) same_bits: u64,
    pub(crate) density: f64,
    pub(crate) persistent: bool,
}

#[derive(Serialize)]
pub struct ASNLoopEntry{
    pub(crate) loop_id: String,
    pub(crate) number_asn: u64,
    pub(crate) is_persistent: bool,
    pub(crate) all_routers_assigned: bool,
    #[serde(serialize_with = "string_set_ser")]
    pub(crate) asn_list: HashSet::<String>,
}

#[derive(Serialize)]
pub struct ASNRouterEntry{
    pub(crate) router_ip: String,
    pub(crate) number_asn: u64,
    pub(crate) is_persistent: bool,
    #[serde(serialize_with = "string_set_ser")]
    pub(crate) asn_list: HashSet::<String>,
}

pub struct ASNShadowedResults {
    pub(crate) shadowed_asn_is_with_loop: u64,
    pub(crate) shadowed_asn_is_not_with_loop: u64,
    pub(crate) shadowed_asn_is_unknown: u64,
    pub(crate) shadowed_asn_with_single_asn: u64,
    pub(crate) shadowed_asn_with_multiple_asn: u64
}

#[derive(Serialize)]
pub struct ASNShadowedOutput {
    pub(crate) shadowed_net: IpAddr,
    #[serde(serialize_with = "string_vec_ser")]
    pub(crate) asn_entries: Vec<String>,
    pub(crate) loop_id: String,
    pub(crate) asn_in_loop: bool,
    pub(crate) all_asn_in_loop: bool,
    pub(crate) num_asn: u8,
    pub(crate) loop_asn: u8
}

#[derive(Serialize)]
pub struct ASNIPAttribution{
    pub(crate) asn: String,
    pub(crate) num_ips: u64
}

#[derive(Serialize, Clone)]
pub struct ShadowedAnswer {
    pub(crate) net: IpNet,
    pub(crate) timeout: u64,
    pub(crate) unreach: u64,
    pub(crate) unreach_noroute: u64,
    pub(crate) unreach_addr: u64,
    pub(crate) unreach_rejectroute: u64,
    pub(crate) unreach_noport: u64,
    pub(crate) unreach_admin: u64,
    pub(crate) unreach_policy: u64,
    pub(crate) paramprob: u64,
    pub(crate) timxceed: u64,
    pub(crate) echoreply: u64,
    pub(crate) persistent_shadowed: bool
}

impl ShadowedAnswer {
    pub fn new(orig_net: &IpNet) -> ShadowedAnswer {
        ShadowedAnswer {
            net: orig_net.clone(),
            timeout: 0,
            unreach: 0,
            unreach_noroute: 0,
            unreach_addr: 0,
            unreach_rejectroute: 0,
            unreach_noport: 0,
            unreach_admin: 0,
            unreach_policy: 0,
            paramprob: 0,
            timxceed: 0,
            echoreply: 0,
            persistent_shadowed: false
        }
    }

    pub fn new_timeout(orig_net: &IpNet) -> ShadowedAnswer {
        let mut result = ShadowedAnswer::new(orig_net);
        result.timeout = 50;
        result
    }
}