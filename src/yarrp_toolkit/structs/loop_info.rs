use serde::{Serialize, Deserialize};
use std::collections::HashSet;
use std::hash::Hash;
use std::fmt::{Display};
use log::{warn};
use crate::structs::{string_set_ser};
use crate::structs::{YarrpError, Route};
use crate::traits::IpAddrExt;
use std::str::FromStr;

#[derive(Serialize, Deserialize, Clone)]
pub struct SimpleLoopOutput {
    pub(crate) loop_id: String,
    pub(crate) preceding_router: String,
    pub(crate) shadowed_nets: u64,
    pub(crate) loop_len: u8,
    pub(crate) loop_start_ttl: u8,
    pub(crate) loop_stop_ttl: u8,
    pub(crate) preceding_router_ttl: u8,
}

impl SimpleLoopOutput{
    pub fn from_route<T>(loop_id: &str, route: &Route<T>) -> Result<SimpleLoopOutput, YarrpError>
        where T: Display + FromStr + Ord + Copy + Clone + Hash + IpAddrExt, {

        let (preceding, ttl) = route.get_preceding_router_named();

        let output = SimpleLoopOutput{
            loop_id: loop_id.to_string(),
            shadowed_nets: 0,
            loop_len: route.loop_len(),
            loop_start_ttl: route.loop_start,
            loop_stop_ttl: route.loop_end,
            preceding_router: preceding,
            preceding_router_ttl: ttl
        };
        Ok(output)
    }

    pub fn append(&mut self, simple_loop_output: &SimpleLoopOutput) {
        if self.loop_id != simple_loop_output.loop_id {
            warn!("Loop id does not match!");
            return;
        }

        if self.preceding_router != simple_loop_output.preceding_router {
            warn!("preceding router does not match!");
            return;
        }

        if self.preceding_router_ttl != simple_loop_output.preceding_router_ttl {
            warn!("preceding router ttl does not match!");
            return;
        }

        self.shadowed_nets += simple_loop_output.shadowed_nets;
    }
}

#[derive(Serialize)]
pub struct AdvancedLoopOutput {
    #[serde(flatten)]
    pub(crate) loop_info: SimpleLoopOutput,
    pub(crate) number_asn: u64,
    pub(crate) is_persistent: bool,
    pub(crate) all_routers_assigned: bool,
    #[serde(serialize_with = "string_set_ser")]
    pub(crate) asn_list: HashSet::<String>,
    pub(crate) preceding_router_same_asn: bool,
}

#[derive(Serialize, Deserialize)]
pub struct ShadowedPreceding {
    pub(crate) shadowed_net: String,
    pub(crate) preceding_router: String,
    pub(crate) preceding_ttl: u8,
    pub(crate) loop_id: String
}


// not yet used, commented so compiler is quiet
// pub struct ShadowedPrecedingCounter {
//     // table 5, destination domain involved
//     pub(crate) dest_domain_involved: u64,
//     pub(crate) only_one_address_in_dest_domain: u64,
//     pub(crate) two_or_more_addresses_in_dest_domain: u64,
//     pub(crate) all_addresses_in_dest_domain: u64,
//     pub(crate) dest_domain_not_involved: u64,
//     pub(crate) preceding_router_in_dest_domain: u64,
//     pub(crate) preceding_router_not_in_dest_domain: u64,
//     // table 6, number of involved domains
//     pub(crate) only_single_domain_as_loop: u64,
//     pub(crate) preceding_same_domain_as_loop: u64,
//     pub(crate) preceding_not_same_domain: u64,
//     pub(crate) multiple_domains_involved: u64,
//     pub(crate) two_domains: u64,
//     pub(crate) three_or_more_domains: u64
//
// }
//
// impl ShadowedPrecedingCounter {
//     pub fn new() -> ShadowedPrecedingCounter {
//         ShadowedPrecedingCounter{
//             dest_domain_involved: 0,
//             only_one_address_in_dest_domain: 0,
//             two_or_more_addresses_in_dest_domain: 0,
//             dest_domain_not_involved: 0,
//             preceding_router_in_dest_domain: 0,
//             preceding_router_not_in_dest_domain: 0,
//             only_single_domain_as_loop: 0,
//             preceding_same_domain_as_loop: 0,
//             preceding_not_same_domain: 0,
//             multiple_domains_involved: 0,
//             two_domains: 0,
//             three_or_more_domains: 0,
//             all_addresses_in_dest_domain: 0
//         }
//     }
// }