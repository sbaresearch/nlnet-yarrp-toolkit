use log::{trace, LevelFilter};
use std::net::{Ipv6Addr, Ipv4Addr};
use crate::structs::YarrpLine;
use std::str::FromStr;

pub const DESTINATION_STRING_V6: &str = "2001:db8::1000";
pub const DESTINATION_STRING_V4: &str = "192.0.2.254";
pub const EMPTY_STRING: String = String::new();
pub const MIN_TTL: u8 = 3;
pub const MAX_TTL: u8 = 18;

pub fn init() {
    let _ = env_logger::builder().is_test(true).filter_level(LevelFilter::Trace).try_init();
}

fn get_yarrp_line(dest: &str, r_type: u8, r_code: u8, sent_ttl: u8, hop: &str) -> String {
    format!("{} 1 1 {} {} {} {} 590 0 36 84 63 0 0 27", dest, r_type, r_code, sent_ttl, hop)
}

pub fn get_ipv6_hop(hop: u16) -> Ipv6Addr {
    Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, hop)
}

pub fn get_ipv4_hop(hop: u8) -> Ipv4Addr {
    Ipv4Addr::new(192, 0, 2, hop)
}

fn get_hop_line(hop: u16) -> String {
    format!("2001:db8::{:x}", hop)
}

fn get_v4_hop_line(hop: u8) -> String {
    format!("192.0.2.{}", hop)
}

pub fn create_v6_yarrp_line_vec(sent_ttl: u8, hop_id: u8, r_type: u8, r_code: u8, hop_string: &String) -> Vec<YarrpLine<Ipv6Addr>> {
    let hop_id = hop_id as u16;
    let hop;
    if hop_string == &EMPTY_STRING {
        hop = get_hop_line(hop_id);
    } else {
        hop = hop_string.to_string();
    }

    let yarrp_string = get_yarrp_line(DESTINATION_STRING_V6, r_type, r_code, sent_ttl, &hop);
    create_yarrp_line(yarrp_string)
}

pub fn create_v4_yarrp_line_vec(sent_ttl: u8, hop_id: u8, r_type: u8, r_code: u8, hop_string: &String) -> Vec<YarrpLine<Ipv4Addr>> {
    let hop_id = hop_id as u8;
    let hop;
    if hop_string == &EMPTY_STRING {
        hop = get_v4_hop_line(hop_id);
    } else {
        hop = hop_string.to_string();
    }

    let yarrp_string = get_yarrp_line(DESTINATION_STRING_V4, r_type, r_code, sent_ttl, &hop);
    create_yarrp_line(yarrp_string)
}

fn create_yarrp_line<T>(yarrp_string: String) -> Vec<YarrpLine<T>>
    where T: FromStr {
    if let Some(yarrp_line) = YarrpLine::new(&yarrp_string) {
        trace!("{}", &yarrp_string);

        let mut new_vec = Vec::new();
        new_vec.push(yarrp_line);
        return new_vec;
    }
    panic!("Could not create yarrp line for input {}!", yarrp_string);
}