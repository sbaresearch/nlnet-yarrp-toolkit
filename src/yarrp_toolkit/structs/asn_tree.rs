pub mod asn_tree {
    use log::{error, info, trace};
    use ipnet::IpNet;
    use crate::structs::YarrpError;
    use std::net::{IpAddr, Ipv6Addr, Ipv4Addr};
    use std::collections::HashMap;


    pub trait ASNTree {
        fn add_network(&mut self, new_network: IpNet, asn: &str) -> bool;
        fn add_child(&mut self, network: IpNet, asn: &str);
        fn find_node(&self, address: &IpAddr) -> Option<&ASNTreeNode>;
        fn get_network(&self) -> &IpNet;
        fn get_asn(&self) -> &Vec<String>;
        fn get_num_asn(&self) -> usize;
        fn get_num_children(&self) -> u64;
    }

    pub struct ASNTreeNode {
        network: IpNet,
        asn: Vec<String>,
        children: Vec<ASNTreeNode>,
        num_children: u64,
    }

    pub struct ASNTreeRoot {
        network: IpNet,
        asn: Vec<String>,
        pub children: HashMap<u16, Vec<ASNTreeNode>>,
        num_children: u64,
    }

    impl ASNTreeRoot {
        pub fn new(network: IpNet) -> Result<ASNTreeRoot, YarrpError> {
            Ok(ASNTreeRoot {
                network,
                asn: vec!["root".to_string()],
                children: HashMap::new(),
                num_children: 0,
            })
        }

        pub fn get_net_hash(network: &IpNet) -> Option<u16> {
            let net = &network.network();
            let hash: u16;

            match net {
                IpAddr::V4(ip4) => {
                    if network.prefix_len() < 8 {
                        return None;
                    }
                    hash = ASNTreeRoot::get_v4_addr_hash(ip4)
                }
                IpAddr::V6(ip6) => {
                    if network.prefix_len() < 16 {
                        return None;
                    }
                    hash = ASNTreeRoot::get_v6_addr_hash(ip6);
                }
            }

            trace!("Using {} as hash for network {}", &hash, &network);

            return Some(hash);
        }

        pub fn get_addr_hash(addr: &IpAddr) -> Option<u16> {
            let hash: u16;

            match addr {
                IpAddr::V4(ip4) => {
                    hash = ASNTreeRoot::get_v4_addr_hash(ip4)
                }
                IpAddr::V6(ip6) => {
                    hash = ASNTreeRoot::get_v6_addr_hash(ip6);
                }
            }
            return Some(hash);
        }

        fn get_v4_addr_hash(net: &Ipv4Addr) -> u16 {
            net.octets()[0] as u16
        }

        fn get_v6_addr_hash(net: &Ipv6Addr) -> u16 {
            trace!("upper: {} ; lower {}", net.octets()[0], net.octets()[1]);
            let mut hash = net.octets()[0] as u16;
            hash = (hash << 8) + net.octets()[1] as u16;

            hash
        }
    }

    impl ASNTreeNode {
        pub fn new(network: IpNet, asn: &str) -> Result<ASNTreeNode, YarrpError> {
            let asn_list = asn.split("_");
            let mut asn = Vec::new();
            for item in asn_list {
                let item = item.split(",");
                for subitem in item {
                    asn.push(subitem.to_string());
                }
            }

            Ok(ASNTreeNode {
                network,
                asn,
                children: Vec::new(),
                num_children: 0,
            })
        }
    }

    impl ASNTree for ASNTreeRoot {
        fn add_network(&mut self, new_network: IpNet, asn: &str) -> bool {
            let net_hash;
            if let Some(hash) = ASNTreeRoot::get_net_hash(&new_network) {
                net_hash = hash;
            } else {
                info!("Ignored prefix {} due to no hash, probably below threshold.", new_network);
                return true;
            }

            if !self.children.contains_key(&net_hash) {
                self.children.insert(net_hash.clone(), Vec::new());
            }

            if let Some(hash_children) = self.children.get_mut(&net_hash) {
                // let children check if they are a super net
                for child in hash_children.iter_mut() {
                    // if we found some net that takes the new net
                    if child.add_network(new_network, asn) {
                        self.num_children += 1;
                        return true;
                    }
                }

                // add to own children if not already added
                if let Ok(leaf) = ASNTreeNode::new(new_network, asn) {
                    hash_children.push(leaf);
                } else {
                    error!("Could not added network {} as new leaf!", new_network);
                }
                self.num_children += 1;
            }

            return true;
        }

        fn add_child(&mut self, _network: IpNet, _asn: &str) {}


        fn find_node(&self, address: &IpAddr) -> Option<&ASNTreeNode> {
            trace!("Looking for node containing {}", address);
            let net_suffix;
            if let Some(hash) = ASNTreeRoot::get_addr_hash(&address) {
                net_suffix = hash;
            } else {
                info!("Ignored prefix {} due to no hash, probably below threshold.", address);
                return None;
            }
            trace!("Got net suffix {} for address {}", net_suffix, address);

            // check if children contain network
            if let Some(hash_children) = self.children.get(&net_suffix) {
                trace!("Found suffix entry for {}", &net_suffix);
                for child in hash_children {
                    // if child contains network, return it
                    if let Some(node) = child.find_node(address) {
                        return Some(node);
                    }
                }
            }

            // otherwise this node is the best suited one, return nothing :shrug:
            None
        }

        fn get_network(&self) -> &IpNet {
            &self.network
        }

        fn get_asn(&self) -> &Vec<String> {
            &self.asn
        }

        fn get_num_asn(&self) -> usize {
            self.asn.len()
        }

        fn get_num_children(&self) -> u64 {
            self.num_children
        }
    }


    impl ASNTree for ASNTreeNode {
        fn add_network(&mut self, new_network: IpNet, asn: &str) -> bool {
            // check if we are super net of new net
            if !self.network.contains(&new_network) {
                return false;
            }

            // let children check if they are a super net
            for child in self.children.iter_mut() {
                // if we found some net that takes the new net
                if child.add_network(new_network, asn) {
                    self.num_children += 1;
                    return true;
                }
            }

            // add to own children if not already added
            self.add_child(new_network, asn);
            self.num_children += 1;
            return true;
        }

        fn add_child(&mut self, network: IpNet, asn: &str) {
            if let Ok(leaf) = ASNTreeNode::new(network, asn) {
                self.children.push(leaf);
            } else {
                error!("Could not added network {} as new leaf!", network);
            }
        }

        fn find_node(&self, address: &IpAddr) -> Option<&ASNTreeNode> {
            // check if in own network, otherwise return None
            if !self.network.contains(address) {
                return None;
            }

            // check if children contain network
            for child in &self.children {

                // if child contains network, return it
                if let Some(node) = child.find_node(address) {
                    return Some(node);
                }
            }
            // otherwise this node is the best suited one, return ourself
            Some(self)
        }

        fn get_network(&self) -> &IpNet {
            &self.network
        }

        fn get_asn(&self) -> &Vec<String> {
            &self.asn
        }

        fn get_num_asn(&self) -> usize {
            self.asn.len()
        }

        fn get_num_children(&self) -> u64 {
            self.num_children
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::structs::{ASNTreeRoot, ASNTree};
    use ipnet::IpNet;
    use std::str::FromStr;
    use std::net::IpAddr;
    use crate::helpers::test_helper::init;

    fn prepare_root_v6() -> ASNTreeRoot {
        let root_net;
        if let Ok(net) = IpNet::from_str("::0/0") {
            root_net = net;
        } else {
            panic!("Could not parse IPv6 network");
        }

        let root_node;
        if let Ok(node) = ASNTreeRoot::new(root_net) {
            root_node = node;
        } else {
            panic!("Could not create root node for IPv6");
        }
        return root_node;
    }

    fn prepare_root_v4() -> ASNTreeRoot {
        let root_net;
        if let Ok(net) = IpNet::from_str("0.0.0.0/0") {
            root_net = net;
        } else {
            panic!("Could not parse IPv4 network");
        }

        let root_node;
        if let Ok(node) = ASNTreeRoot::new(root_net) {
            root_node = node;
        } else {
            panic!("Could not create root node for IPv4");
        }
        return root_node;
    }

    fn easy_add(root: &mut ASNTreeRoot, ip_net: &str, asn: &str) {
        let net;
        if let Ok(tmp_net) = IpNet::from_str(ip_net) {
            net = tmp_net;
        } else {
            panic!("Could not parse network");
        }

        assert!(root.add_network(net, asn));
    }

    #[test]
    fn test_ipv6_address_hash() {
        let ip_addr = IpAddr::from_str("2001:200::66").unwrap();
        let ip_net = IpNet::from_str("2001:200::/32").unwrap();

        let hash_comparison: u16 = 0x2001;

        if let Some(hash) = ASNTreeRoot::get_addr_hash(&ip_addr) {
            assert_eq!(hash, hash_comparison, "Hash should be 0x2001");
        } else {
            panic!("Should have gotten a hash!");
        }

        if let Some(hash) = ASNTreeRoot::get_net_hash(&ip_net) {
            assert_eq!(hash, hash_comparison, "Hash should be 0x2001");
        } else {
            panic!("Should have gotten a hash!");
        }
    }

    #[test]
    fn test_ipv4_address_hash() {
        let ip_addr = IpAddr::from_str("172.18.10.66").unwrap();
        let ip_net = IpNet::from_str("172.18.0.0/12").unwrap();

        let hash_comparison: u16 = 172;

        if let Some(hash) = ASNTreeRoot::get_addr_hash(&ip_addr) {
            assert_eq!(hash, hash_comparison, "Hash should be 172");
        } else {
            panic!("Should have gotten a hash!");
        }

        if let Some(hash) = ASNTreeRoot::get_net_hash(&ip_net) {
            assert_eq!(hash, hash_comparison, "Hash should be 0x2001");
        } else {
            panic!("Should have gotten a hash!");
        }
    }

    #[test]
    fn test_empty_root_v6() {
        let root = prepare_root_v6();

        assert_eq!(root.get_num_children(), 0, "number children should be 0");
        assert_eq!(root.get_asn(), &vec!["root".to_string()], "ASN should be 'root'");

        let ip_addr = IpAddr::from_str("2001::66").unwrap();
        if let Some(_) = root.find_node(&ip_addr) {
            panic!("Should not result in value!");
        }
    }

    #[test]
    fn test_empty_root_v4() {
        init();
        let root = prepare_root_v4();

        assert_eq!(root.get_num_children(), 0, "number children should be 0");
        assert_eq!(root.get_asn(), &vec!["root".to_string()], "ASN should be 'root'");

        let ip_addr = IpAddr::from_str("123.0.0.1").unwrap();
        if let Some(_) = root.find_node(&ip_addr) {
            panic!("Should not result in value!");
        }
    }

    #[test]
    fn test_hashmap_prefilter_v6() {
        init();
        let mut root = prepare_root_v6();

        easy_add(&mut root, "2001::/32", "6939_1101_211722");
        easy_add(&mut root, "2001:200::/23", "13030");
        easy_add(&mut root, "2001:200:e000::/35", "7660");

        assert_eq!(root.get_num_children(), 3, "number children should be 3");
        assert_eq!(root.get_asn(), &vec!["root".to_string()], "ASN should be 'root'");

        let net_suffix: u16 = 0x2001;
        assert_eq!(root.children.len(), 1, "roots children hashmap should have one entry!");

        if let Some(vector) = root.children.get(&net_suffix) {
            assert_eq!(vector.len(), 2, "hashmap entry vector should have two entries!");
        } else {
            panic!("Did not get a node for valid entry");
        }
    }

    #[test]
    fn test_hashmap_prefilter_v4() {
        init();
        let mut root = prepare_root_v6();

        easy_add(&mut root, "172.18.0.0/16", "1");
        easy_add(&mut root, "172.19.0.0/16", "2");
        easy_add(&mut root, "172.18.20.0/24", "3");

        assert_eq!(root.get_num_children(), 3, "number children should be 3");
        assert_eq!(root.get_asn(), &vec!["root".to_string()], "ASN should be 'root'");

        let net_suffix: u16 = 172;
        assert_eq!(root.children.len(), 1, "roots children hashmap should have one entry!");

        if let Some(vector) = root.children.get(&net_suffix) {
            assert_eq!(vector.len(), 2, "hashmap entry vector should have two entries!");
        } else {
            panic!("Did not get a node for valid entry");
        }
    }

    #[test]
    fn test_filtered_v6() {
        init();
        let mut root = prepare_root_v6();

        easy_add(&mut root, "2002::/12", "1");
        easy_add(&mut root, "2003::/13", "1");
        easy_add(&mut root, "2400::/14", "1");
        easy_add(&mut root, "2600::/15", "1");

        assert_eq!(root.get_num_children(), 0, "number children should be 0");
        assert_eq!(root.get_asn(), &vec!["root".to_string()], "ASN should be 'root'");
    }



    #[test]
    fn test_filtered_v4() {
        init();
        let mut root = prepare_root_v4();

        easy_add(&mut root, "8.0.0.0/4", "1");
        easy_add(&mut root, "9.0.0.0/5", "1");
        easy_add(&mut root, "7.0.0.0/6", "1");
        easy_add(&mut root, "4.0.0.0/7", "1");

        assert_eq!(root.get_num_children(), 0, "number children should be 0");
        assert_eq!(root.get_asn(), &vec!["root".to_string()], "ASN should be 'root'");
    }

    #[test]
    fn test_node_search_v6() {
        init();
        let mut root = prepare_root_v6();

        easy_add(&mut root, "2001::/32", "6939_1101_211722");
        easy_add(&mut root, "2001:200::/23", "13030");
        easy_add(&mut root, "2001:200::/32", "2500");
        easy_add(&mut root, "2001:200:900::/40", "7660");
        easy_add(&mut root, "2001:200:c000::/35", "23634");
        easy_add(&mut root, "2001:200:e000::/35", "7660");

        let ip_addr = IpAddr::from_str("2001::66").unwrap();
        let ip_net = IpNet::from_str("2001::/32").unwrap();

        if let Some(node) = root.find_node(&ip_addr) {
            assert_eq!(node.get_num_asn(), 3, "Number of ASN should be three!");
            assert_eq!(node.get_network(), &ip_net, "Network should be 2001::/32");
            assert_eq!(node.get_num_children(), 0, "Node should have 0 children");
        } else {
            panic!("Should return a valid node!");
        }

        let ip_addr = IpAddr::from_str("2001:200::66").unwrap();
        let ip_net = IpNet::from_str("2001:200::/32").unwrap();

        if let Some(node) = root.find_node(&ip_addr) {
            assert_eq!(node.get_num_asn(), 1, "Number of ASN should be one!");
            if let Some(asn) = node.get_asn().get(0) {
                assert_eq!(asn, "2500", "ASN should be 2500!");
            }

            assert_eq!(node.get_network(), &ip_net, "Network should be 2001:200::/32");
            assert_eq!(node.get_num_children(), 3, "Node should have 3 children");
        } else {
            panic!("Should return a valid node!");
        }

        let ip_addr = IpAddr::from_str("2000::66").unwrap();
        if let Some(_) = root.find_node(&ip_addr) {
            panic!("Should not result in value!");
        }
    }

    #[test]
    fn test_node_search_v4() {
        init();
        let mut root = prepare_root_v6();

        easy_add(&mut root, "172.18.0.0/16", "1_7_8");
        easy_add(&mut root, "172.19.0.0/16", "2");
        easy_add(&mut root, "172.19.128.0/17", "3");
        easy_add(&mut root, "172.19.164.0/24", "4");
        easy_add(&mut root, "172.19.165.0/24", "5");
        easy_add(&mut root, "172.19.166.0/24", "6");

        let ip_addr = IpAddr::from_str("172.18.0.1").unwrap();
        let ip_net = IpNet::from_str("172.18.0.0/16").unwrap();

        if let Some(node) = root.find_node(&ip_addr) {
            assert_eq!(node.get_num_asn(), 3, "Number of ASN should be three!");
            assert_eq!(node.get_network(), &ip_net, "Network should be 172.18.0.0/16");
            assert_eq!(node.get_num_children(), 0, "Node should have 0 children");
        } else {
            panic!("Should return a valid node!");
        }

        let ip_addr = IpAddr::from_str("172.19.128.1").unwrap();
        let ip_net = IpNet::from_str("172.19.128.0/17").unwrap();

        if let Some(node) = root.find_node(&ip_addr) {
            assert_eq!(node.get_num_asn(), 1, "Number of ASN should be one!");
            if let Some(asn) = node.get_asn().get(0) {
                assert_eq!(asn, "3", "ASN should be 3!");
            }

            assert_eq!(node.get_network(), &ip_net, "Network should be 172.19.128.0/17");
            assert_eq!(node.get_num_children(), 3, "Node should have 3 children");
        } else {
            panic!("Should return a valid node!");
        }

        let ip_addr = IpAddr::from_str("172.17.255.255").unwrap();
        if let Some(_) = root.find_node(&ip_addr) {
            panic!("Should not result in value!");
        }
    }
}