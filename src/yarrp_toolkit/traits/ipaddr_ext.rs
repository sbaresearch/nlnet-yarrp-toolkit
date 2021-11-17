pub mod ipaddr_ext {
    use std::net::{Ipv6Addr, Ipv4Addr, IpAddr};
    use ipnet::{IpNet, Ipv4Net, Ipv6Net, IpAdd};
    use crate::structs::{YarrpError, YarrpLine};
    use rand::{RngCore, Rng};
    use std::str::FromStr;
    use log::{debug};

    pub enum ICMPMode {
        ICMPReply,
        TTLe,
        Other
    }

    pub trait IpAddrExt {
        fn to_network_with_prefix_length(&self, prefix_length: u8) -> Result<IpNet, YarrpError>;
        fn to_ipaddr(&self) -> Result<IpAddr, YarrpError>;
        fn ls_octets(&self) -> Vec<u8>;
        fn check_errors<T: IpAddrExt>(yarrp_line: &YarrpLine<T>) -> ICMPMode;
        fn create_target(input: &str, rng: &mut rand_pcg::Lcg128Xsl64) -> Result<String, YarrpError>;
        fn create_network_from_string(input: &str) -> Result<IpNet, YarrpError>;

        fn time_exceeded_type() -> u8;
        fn echo_response_type() -> u8;
        fn root_net() -> String;
        fn is_v4() -> bool;
    }

    impl IpAddrExt for Ipv6Addr {
        fn to_network_with_prefix_length(&self, prefix_length: u8) -> Result<IpNet, YarrpError> {
            let v6_net = Ipv6Net::new(*self, prefix_length)?;
            Ok(IpNet::V6(v6_net))
        }

        fn to_ipaddr(&self) -> Result<IpAddr, YarrpError> {
            Ok(IpAddr::V6(self.clone()))
        }

        fn ls_octets(&self) -> Vec<u8> {
            Vec::from(self.octets())
        }

        fn check_errors<Ipv6Addr: IpAddrExt>(yarrp_line: &YarrpLine<Ipv6Addr>) -> ICMPMode {
            if yarrp_line.r_type == 129 && yarrp_line.r_code == 0 {
                return ICMPMode::ICMPReply;
            } else if yarrp_line.r_type != 3 {
                return ICMPMode::Other
            }
            return ICMPMode::TTLe
        }

        fn create_target(input: &str, rng: &mut rand_pcg::Lcg128Xsl64) -> Result<String, YarrpError> {
            let net = Ipv6Net::from_str(input)?;

            let prefix_len = 128 - 64 - net.prefix_len();
            let prefix_mask: u128 = (1 << prefix_len) -1;
            debug!("Prefix mask: {} = 128 - 64 - {}", prefix_mask, prefix_len);

            let to_64_prefix: u64 = rng.gen();
            let to_64_prefix = (to_64_prefix as u128) & prefix_mask;
            let to_64_prefix: u128 = (to_64_prefix as u128) << 64;

            let target_subnet = net.network().saturating_add(to_64_prefix);
            let target_subnet = Ipv6Net::from(target_subnet);

            let host_part = rng.next_u64() as u128;
            let target_host = target_subnet.network().saturating_add(host_part);

            debug!("Original: {}", input);
            debug!("First   : {}", target_subnet);
            debug!("Second  : {}", target_host);

            Ok(target_host.to_string())
        }

        fn create_network_from_string(input: &str) -> Result<IpNet, YarrpError> {
            let net = Ipv6Net::from_str(input)?;
            return Ok(IpNet::V6(net));
        }

        fn time_exceeded_type() -> u8 {
            3
        }

        fn echo_response_type() -> u8 {
            129
        }

        fn root_net() -> String {
            "::0/0".to_string()
        }

        fn is_v4() -> bool {
            false
        }
    }

    impl IpAddrExt for Ipv4Addr {
        fn to_network_with_prefix_length(&self, prefix_length: u8) -> Result<IpNet, YarrpError> {
            let v4_net = Ipv4Net::new(*self, prefix_length)?;
            Ok(IpNet::V4(v4_net))
        }

        fn to_ipaddr(&self) -> Result<IpAddr, YarrpError> {
            Ok(IpAddr::V4(self.clone()))
        }

        fn ls_octets(&self) -> Vec<u8> {
            Vec::from(self.octets())
        }

        fn check_errors<Ipv4Addr: IpAddrExt>(yarrp_line: &YarrpLine<Ipv4Addr>) -> ICMPMode {
            if yarrp_line.r_type == 9 && yarrp_line.r_code == 0 {
                return ICMPMode::ICMPReply;
            } else if yarrp_line.r_type != 11 {
                return ICMPMode::Other
            }
            return ICMPMode::TTLe
        }

        fn create_target(input: &str, rng: &mut rand_pcg::Lcg128Xsl64) -> Result<String, YarrpError>  {
            let net = Ipv4Net::from_str(input)?;

            let prefix_len = 32 - 8 - net.prefix_len();
            let prefix_mask: u32 = (1 << prefix_len) -1;
            debug!("Prefix mask: {} = 32 - 8 - {}", prefix_mask, prefix_len);

            let to_24_prefix: u8 = rng.gen();
            let to_24_prefix = (to_24_prefix as u32) & prefix_mask;
            let to_24_prefix: u32 = (to_24_prefix as u32) << 8;

            let target_subnet = net.network().saturating_add(to_24_prefix);
            let target_subnet = Ipv4Net::from(target_subnet);

            let host_part: u8 = rng.gen();
            let host_part = host_part as u32;
            let target_host = target_subnet.network().saturating_add(host_part);

            debug!("Original: {}", input);
            debug!("First   : {}    ({})", target_subnet, to_24_prefix);
            debug!("Second  : {}    ({})", target_host, host_part);

            Ok(target_host.to_string())
        }

        fn create_network_from_string(input: &str) -> Result<IpNet, YarrpError> {
            let net = Ipv4Net::from_str(input)?;
            return Ok(IpNet::V4(net));
        }

        fn time_exceeded_type() -> u8 {
            11
        }

        fn echo_response_type() -> u8 {
            9
        }

        fn root_net() -> String {
            "0.0.0.0/0".to_string()
        }

        fn is_v4() -> bool {
            true
        }
    }

}