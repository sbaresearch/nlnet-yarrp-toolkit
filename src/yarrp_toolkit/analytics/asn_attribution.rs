pub mod asn_attribution {
    use crate::structs::{ASNTreeRoot, YarrpError, ASNTree, MapSetString, ASNRouterEntry, ASNLoopEntry, MapVecT, ASNShadowedResults, ASNShadowedOutput};
    use ipnet::IpNet;
    use std::process::exit;
    use log::{error, info, trace};
    use std::str::FromStr;
    use std::path::{Path, PathBuf};
    use crate::read_lines;
    use itertools::Itertools;
    use std::collections::{HashMap, HashSet};
    use std::net::IpAddr;
    use std::fs::File;
    use std::io::Write;
    use std::fmt::Display;
    use std::hash::Hash;
    use crate::traits::IpAddrExt;

    pub struct ASNAttribution {
        root: ASNTreeRoot,
    }

    impl ASNAttribution {
        pub fn new(root_str: &str) -> ASNAttribution {
            let root_net: IpNet;

            if let Ok(net) = IpNet::from_str(root_str) {
                root_net = net;
            } else {
                error!("Could not create root node for IPv6");
                exit(1);
            }

            let root_node;
            if let Ok(node) = ASNTreeRoot::new(root_net) {
                root_node = node;
            } else {
                error!("Could not initialize root node!");
                exit(1);
            }
            ASNAttribution {
                root: root_node,
            }
        }

        pub fn load_routeviews_bgp(&mut self, path: &str) -> Result<(), YarrpError> {
            info!("Loading BGP data into ASNTree");
            let path = Path::new(path);

            let lines = read_lines(path)?;
            for input in lines {
                let input = input?;
                let split = input.split("\t");
                let vec = split.collect_vec();

                let net_str = format!("{}/{}", vec[0], vec[1]);
                let asn = vec[2];

                if let Ok(ip_net) = IpNet::from_str(&net_str) {
                    if !self.root.add_network(ip_net, asn) {
                        error!("Could not add network {} to tree!", &net_str);
                    }
                }
            }
            info!("Added {} networks to the root tree!", self.root.get_num_children());

            Ok(())
        }

        pub fn get_asn_for_ip(&self, ip_addr: &IpAddr) -> Option<Vec<String>> {
            let mut asn = None;

            if let Some(asn_node) = self.root.find_node(ip_addr) {
                let asn_vec = asn_node.get_asn().clone();
                asn = Some(asn_vec);
            }

            return asn;
        }

        ///
        ///
        /// # Arguments
        ///
        /// * `routers`:
        ///
        /// returns: Result<(HashMap<String, HashSet<String, RandomState>, RandomState>, HashMap<String, HashSet<String, RandomState>, RandomState>), YarrpError>
        ///     Result<(asn to router, router to asn), YarrpError>
        /// # Examples
        ///
        /// ```
        ///
        /// ```
        pub fn build_routers_to_asn(&mut self, routers: &HashMap<String, HashSet<String>>)
                                    -> Result<(HashMap<String, HashSet<String>>, HashMap<String, HashSet<String>>), YarrpError> {
            let mut asn_to_router = HashMap::new();
            let mut router_to_asn = HashMap::new();

            for (router, _loops) in routers {
                let router_ip = IpAddr::from_str(&router)?;

                if !router_to_asn.contains_key(router) {
                    router_to_asn.insert(router.clone(), HashSet::new());
                }

                let asn_set;
                if let Some(set) = router_to_asn.get_mut(router) {
                    asn_set = set;
                } else {
                    error!("Could not get hashset!");
                    return Err(YarrpError::CouldNotWriteError);
                }

                if let Some(leaf) = self.root.find_node(&router_ip) {
                    for asn_string in leaf.get_asn() {
                        asn_set.insert(asn_string.clone());

                        if !asn_to_router.contains_key(asn_string) {
                            asn_to_router.insert(asn_string.clone(), HashSet::new());
                        }

                        if let Some(asn_entry) = asn_to_router.get_mut(asn_string) {
                            asn_entry.insert(router.clone());
                        }
                    }
                }
            }

            Ok((asn_to_router, router_to_asn))
        }

        pub fn build_loops_to_asn(&self, loops: &MapSetString, routers_to_asn: &MapSetString)
                                  -> Result<(MapSetString, MapSetString), YarrpError> {
            let mut l2a: MapSetString = HashMap::new();
            let mut a2l: MapSetString = HashMap::new();

            for (loop_id, members) in loops {
                if !l2a.contains_key(loop_id) {
                    l2a.insert(loop_id.clone(), HashSet::new());
                }

                if let Some(set) = l2a.get_mut(loop_id) {
                    for router in members {
                        if let Some(router_asn) = routers_to_asn.get(router) {
                            for asn in router_asn {
                                set.insert(asn.clone());

                                if !a2l.contains_key(asn) {
                                    a2l.insert(asn.clone(), HashSet::new());
                                }

                                if let Some(loop_set) = a2l.get_mut(asn) {
                                    loop_set.insert(loop_id.clone());
                                }
                            }
                        }
                    }
                }
            }
            Ok((a2l, l2a))
        }

        pub fn build_shadowed_asn_to_loop<T>(&self, loop_destinations: &MapVecT<T>, loops_to_asn: &MapSetString, output_path: &PathBuf)
                                             -> Result<ASNShadowedResults, YarrpError>
            where T: 'static + Display + Ord + Copy + Eq + Clone + Hash + IpAddrExt + FromStr
        {
            info!("Creating shadowed asn attribution");
            let mut writer = csv::Writer::from_path(output_path)?;

            let mut shadowed_count = ASNShadowedResults {
                shadowed_asn_is_with_loop: 0,
                shadowed_asn_is_not_with_loop: 0,
                shadowed_asn_is_unknown: 0,
                shadowed_asn_with_single_asn: 0,
                shadowed_asn_with_multiple_asn: 0,
            };
            // let mut shadowed_to_asn = HashMap::new();

            for (loop_id, shadowed) in loop_destinations {
                let current_loop_asn: HashSet<String>;
                if let Some(value) = loops_to_asn.get(loop_id) {
                    current_loop_asn = value.clone();
                } else {
                    current_loop_asn = HashSet::new();
                }

                for shadowed_net in shadowed {
                    let ip_addr = shadowed_net.to_ipaddr()?;

                    // get network above address for pre sorting
                    // let entry_net;
                    // if T::is_v4() {
                    //     entry_net = shadowed_net.to_network_with_prefix_length(16)?;
                    // } else {
                    //     entry_net = shadowed_net.to_network_with_prefix_length(36)?;
                    // }

                    // build csv export object
                    let mut shadowed_csv_obj = ASNShadowedOutput {
                        shadowed_net: ip_addr,
                        asn_entries: Vec::new(),
                        loop_id: loop_id.clone(),
                        asn_in_loop: false,
                        all_asn_in_loop: false,
                        num_asn: 0,
                        loop_asn: current_loop_asn.len() as u8,
                    };

                    // grab asn
                    let shadowed_asn: Vec<String>;
                    if let Some(node) = self.root.find_node(&shadowed_csv_obj.shadowed_net) {
                        shadowed_asn = node.get_asn().clone();
                    } else {
                        shadowed_asn = Vec::new();
                    }

                    // if multiple shadowed asn
                    match shadowed_asn.len() {
                        0 => {},
                        1 => shadowed_count.shadowed_asn_with_single_asn += 1,
                        _ => shadowed_count.shadowed_asn_with_multiple_asn += 1
                    }

                    // basic pre condition checks dont have to do a lot if there are no found asn
                    if current_loop_asn.len() == 0 && shadowed_asn.len() == 0 {
                        shadowed_count.shadowed_asn_is_unknown += 1;
                    } else if current_loop_asn.len() == 0 && shadowed_asn.len() > 0 {
                        shadowed_count.shadowed_asn_is_not_with_loop += 1;
                    } else if current_loop_asn.len() > 0 && shadowed_asn.len() == 0 {
                        shadowed_count.shadowed_asn_is_unknown += 1;
                    } else {
                        // do the actual ASN check here
                        let mut found_asn_in_loop = false;
                        let mut found_all_asn = true;

                        // check if at least one ASN matches and if all ASN match
                        for asn in &shadowed_asn {
                            if current_loop_asn.contains(asn) {
                                found_asn_in_loop = true;
                            } else {
                                found_all_asn = false;
                            }
                        }

                        // set counting results accordingly
                        if found_asn_in_loop {
                            shadowed_count.shadowed_asn_is_with_loop += 1;
                        } else {
                            shadowed_count.shadowed_asn_is_not_with_loop += 1;
                        }

                        shadowed_csv_obj.num_asn = shadowed_asn.len() as u8;
                        shadowed_csv_obj.all_asn_in_loop = found_all_asn;
                        shadowed_csv_obj.asn_in_loop = found_asn_in_loop;
                        shadowed_csv_obj.asn_entries = shadowed_asn;
                    }

                    writer.serialize(shadowed_csv_obj)?;
                    // // add vector if pre sorting key not yet found
                    // if !shadowed_to_asn.contains_key(&entry_net) {
                    //     shadowed_to_asn.insert(entry_net.clone(), Vec::new());
                    // }
                    //
                    // // append csv entry to list
                    // if let Some(entries) = shadowed_to_asn.get_mut(&entry_net) {
                    //     entries.push(shadowed_csv_obj);
                    // } else {
                    //     error!("Could not append shadowed csv entry!");
                    // }
                }
            }
            Ok(shadowed_count)
        }

        pub fn get_shadowed_preceding_asn(&self, shadowed: &str, preceding: &str) -> Result<(Vec<String>, Vec<String>), YarrpError> {
            let shadowed_ip = IpAddr::from_str(shadowed)?;
            let preceding_ip = IpAddr::from_str(preceding)?;

            let shadowed_vec;
            let preceding_vec;

            if let Some(value) = self.root.find_node(&shadowed_ip) {
                shadowed_vec = value.get_asn().clone();
            } else {
                shadowed_vec = Vec::new();
                trace!("No node found for shadowed {}", &shadowed_ip);
            }

            if let Some(value) = self.root.find_node(&preceding_ip) {
                preceding_vec = value.get_asn().clone();
            } else {
                preceding_vec = Vec::new();
                trace!("No node found for preceding {}", &preceding_ip);
            }

            Ok((shadowed_vec, preceding_vec))
        }

        pub fn print_asn_map(&self, asn_map: &MapSetString) {
            let mut count_vec: Vec<(&String, &HashSet<String>)> = asn_map.iter().collect();
            count_vec.sort_by(|a, b| b.1.len().cmp(&a.1.len()));

            let mut count = 0;
            for (asn, routers) in count_vec {
                if count > 25 {
                    break;
                }
                println!("{} : {}", asn, routers.len());
                count += 1;
            }
        }

        pub fn write_item_to_asn_csv(&self, output_path: &Path, x2a: &MapSetString) -> Result<(), YarrpError> {
            if let Ok(mut output_file) = File::create(output_path) {
                for (key, values) in x2a {
                    let mut record = Vec::new();
                    record.push(key.clone());
                    for value in values {
                        record.push(value.clone());
                    }

                    let line = record.join(",");

                    let format_string = format!("{}\n", line);
                    if let Err(x) = output_file.write(format_string.as_bytes()) {
                        eprintln!("Could not write to output file!");
                        eprintln!("{}", x);
                        exit(1);
                    }
                }
            } else {
                error!("Could not open or create output file!");
            }


            Ok(())
        }

        pub fn write_asn_csv(&self, output_path: &Path, a2r: &MapSetString, a2l: &MapSetString) -> Result<(), YarrpError> {
            let mut keys = HashSet::new();
            for key in a2r.keys() {
                keys.insert(key.clone());
            }

            for key in a2l.keys() {
                keys.insert(key.clone());
            }

            let mut csv_writer = csv::Writer::from_path(output_path)?;

            if let Err(_e) = csv_writer.write_record(&["asn", "routers", "loops"]) {
                error!("Could not write header row for asn.csv!");
                return Err(YarrpError::CouldNotWriteError);
            }

            for key in keys {
                let routers;
                let loops;
                if let Some(set) = a2r.get(&key) {
                    routers = set.len() as u64;
                } else {
                    routers = 0;
                }

                if let Some(set) = a2l.get(&key) {
                    loops = set.len() as u64;
                } else {
                    loops = 0;
                }

                let record = [&key, &routers.to_string(), &loops.to_string()];
                csv_writer.write_record(&record)?;
            }
            Ok(())
        }

        pub fn write_asn_router_entries(&self, output_path: &Path, r2a: &MapSetString, router_persistent: &HashSet<String>) -> Result<(), YarrpError> {
            info!("Writing ASN Router Entries!");
            let mut writer = csv::Writer::from_path(output_path)?;
            for (router, asn) in r2a {
                let persistent = router_persistent.contains(router);

                let mut storage = ASNRouterEntry {
                    router_ip: router.clone(),
                    number_asn: asn.len() as u64,
                    is_persistent: persistent,
                    asn_list: asn.clone(),
                };

                if storage.asn_list.len() == 0 {
                    storage.asn_list.insert("undefined".to_string());
                }
                if let Err(_e) = writer.serialize(storage) {
                    error!("{}", _e);
                }
            }
            Ok(())
        }

        pub fn write_asn_loop_entries(&self, output_path: &Path, loop_members: &MapSetString, r2a: &MapSetString, loop_persistence: &HashSet<String>) -> Result<(), YarrpError> {
            info!("Writing ASN Loop Entries!");
            let mut writer = csv::Writer::from_path(output_path)?;

            for (loop_id, members) in loop_members {
                let persistent = loop_persistence.contains(loop_id);
                let mut all_assigned = true;

                let mut asn_list = HashSet::new();
                for member in members {
                    if let Some(asn_set) = r2a.get(member) {
                        if asn_set.len() == 0 {
                            all_assigned = false;
                            asn_list.insert("undefined".to_string());
                        } else {
                            for asn in asn_set {
                                asn_list.insert(asn.clone());
                            }
                        }
                    }
                }

                let storage = ASNLoopEntry {
                    loop_id: loop_id.clone(),
                    number_asn: asn_list.len() as u64,
                    is_persistent: persistent,
                    all_routers_assigned: all_assigned,
                    asn_list,
                };
                writer.serialize(storage)?;
            }
            Ok(())
        }
    }
}
