pub mod loop_imperiled {
    use std::collections::{HashSet, HashMap};
    use log::{error, info, trace};
    use std::fmt::Display;
    use std::hash::Hash;
    use std::process::exit;
    use std::str::FromStr;
    use std::path::Path;

    use crate::traits::IpAddrExt;
    use crate::structs::{Route, CountingFile, CountingEntity, CountingVoid};
    use crate::analytics::LoopStorage;
    use crate::modes::read_blocklist;

    pub struct LoopImperiled<T> {
        is_empty: bool,
        pub router_map: HashMap<T, CountingEntity>,
    }

    impl<T: Display + Ord + Copy + Clone + Hash + IpAddrExt + FromStr> LoopImperiled<T> {
        pub fn from_router_file(router_path: &str, blocklist_file: &str, output_path: &Path) -> LoopImperiled<T> {
            // check if path exists, if so read all ip addresses of routers from it

            let blocklist;
            let blocklist_filepath = Path::new(blocklist_file);
            if blocklist_file.len() > 0 && blocklist_filepath.exists() && blocklist_filepath.is_file() {
                if let Ok(temp_blocklist) = read_blocklist(&blocklist_filepath) {
                    blocklist = temp_blocklist;
                } else {
                    error!("Could not read blocklist!");
                    exit(1);
                }
            } else {
                blocklist = HashSet::new();
            }

            info!("Blocklist loaded with {} entries", blocklist.len());

            let mut router_list: HashSet<T> = HashSet::new();
            let file_path = Path::new(router_path).to_path_buf();

            if file_path.exists() && file_path.is_file() {
                if let Ok(routers) = LoopStorage::<T>::read_id_file(&file_path) {
                    for router in routers.keys() {
                        if let Ok(router_ip) = T::from_str(router) {
                            router_list.insert(router_ip);
                        } else {
                            error!("Could not parse ip address from string {}!", router);
                            exit(1);
                        }
                    }
                } else {
                    error!("Could not read routers!");
                    exit(1);
                }
            }

            let mut filtered_router_list = HashSet::new();

            if blocklist.len() > 0 && router_list.len() > 0 {
                for router in router_list {

                    let mut ignore = false;
                    for blocklist_prefix in &blocklist {
                        if let Ok(router_ip) = router.to_ipaddr() {
                            if blocklist_prefix.contains(&router_ip) {
                                ignore = true;
                            }
                        }
                    }
                    if !ignore {
                        filtered_router_list.insert(router.clone());
                    }
                }
            } else {
                filtered_router_list = router_list;
            }

            LoopImperiled::<T>::new(filtered_router_list, output_path)
        }

        pub fn new(router_list: HashSet<T>, output_path: &Path) -> LoopImperiled<T> {
            info!("Imperiled analysis working with {} routers", router_list.len());

            let mut router_map: HashMap<T, CountingEntity> = HashMap::new();

            for router in &router_list {
                let router_file = output_path.join(format!("{}.imp", router));
                if let Some(counting_file) = CountingFile::new(&router_file) {
                    let counting_entity = CountingEntity::from(counting_file);
                    router_map.insert(router.clone(), counting_entity);
                } else {
                    error!("Could not create counting file for {}!", router);
                }
            }

            LoopImperiled {
                is_empty: router_map.is_empty(),
                router_map,
            }
        }

        pub fn new_no_output(router_list: HashSet<T>) -> LoopImperiled<T> {
            info!("Imperiled analysis working with {} routers", router_list.len());

            let router_file = Path::new("/dev/null");
            let mut router_map: HashMap<T, CountingEntity> = HashMap::new();

            for router in &router_list {
                if let Some(counting_file) = CountingVoid::new(&router_file) {
                    let counting_entity = CountingEntity::from(counting_file);
                    router_map.insert(router.clone(), counting_entity);
                } else {
                    error!("Could not create counting file for {}!", router);
                }
            }

            LoopImperiled {
                is_empty: router_map.is_empty(),
                router_map,
            }
        }

        pub fn check_route(&mut self, route: &mut Route<T>) {
            // check if we have a list of persistent routers, so we can actually check for imperiled
            if self.is_empty {
                return;
            }

            // route cannot be imperiled if its looping
            if route.is_looping {
                return;
            }

            let mut is_imperiled = false;

            for route_hop in &route.route {
                // a hop cannot be imperiled if it is the destination
                if route_hop.hop == route_hop.destination {
                    continue;
                }

                // check if the current hop is in our set of persistent routers
                if let Some(counting_file) = self.router_map.get_mut(&route_hop.hop) {
                    trace!("Found imperiled router {} on route {}", &route_hop.hop, &route.destination);
                    is_imperiled = true;

                    // build list of imperiled routers per destination
                    route.imperiled_routers.push(route_hop.hop.clone());
                    counting_file.write_ip_line(&route.destination);
                }
            }
            route.is_imperiled = is_imperiled;
        }

        pub fn print_stats(&self) {
            if self.is_empty {
                return;
            }

            let mut count_vec: Vec<(&T, &CountingEntity)> = self.router_map.iter().collect();
            count_vec.sort_by(|a, b| b.1.len().cmp(&a.1.len()));

            let mut count = 0;

            for (router_hop, value) in count_vec {
                if count >= 25 { break; }
                println!("{:48}, {:15}", router_hop, value.len());
                count += 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};
    use std::net::{Ipv6Addr, Ipv4Addr};
    use crate::structs::Route;
    use crate::helpers::test_helper::{init, DESTINATION_STRING_V6, DESTINATION_STRING_V4};
    use crate::helpers::test_helper::{get_ipv6_hop, create_v6_yarrp_line_vec};
    use crate::helpers::test_helper::{get_ipv4_hop, create_v4_yarrp_line_vec};
    use crate::helpers::test_helper::{EMPTY_STRING, MIN_TTL, MAX_TTL};
    use crate::traits::IpAddrExt;
    use crate::analytics::LoopImperiled;

    #[test]
    fn test_imperiled_route() {
        init();

        let mut return_set = HashSet::new();
        return_set.insert(get_ipv6_hop(5));
        return_set.insert(get_ipv6_hop(6));

        let mut imperiled_algo = LoopImperiled::new_no_output(return_set.clone());

        let mut test_map = HashMap::new();
        let mut r_type = Ipv6Addr::time_exceeded_type();
        let mut r_code = 0;
        let mut hop_str = EMPTY_STRING;

        for i in 3..19 {
            if i >= 10 {
                r_type = Ipv6Addr::echo_response_type();
                r_code = 0;
                hop_str = String::from(DESTINATION_STRING_V6);
            }

            test_map.insert(i, create_v6_yarrp_line_vec(i, i, r_type, r_code, &hop_str));
        }
        let mut route = Route::new(&test_map, MIN_TTL, MAX_TTL);
        imperiled_algo.check_route(&mut route);

        assert!(route.is_imperiled, "Route should be imperiled, is {}", route.is_imperiled);
        for router in return_set {
            if let Some(counting_file) = imperiled_algo.router_map.get(&router) {
                assert_eq!(counting_file.len(), 1, "Counting file should be of length one!");
            } else {
                panic!("Could not get router from map");
            }
        }
    }

    #[test]
    fn test_imperiled_route_v4() {
        init();

        let mut return_set = HashSet::new();
        return_set.insert(get_ipv4_hop(5));
        return_set.insert(get_ipv4_hop(6));

        let mut imperiled_algo = LoopImperiled::new_no_output(return_set.clone());

        let mut test_map = HashMap::new();
        let mut r_type = Ipv4Addr::time_exceeded_type();
        let mut r_code = 0;
        let mut hop_str = EMPTY_STRING;

        for i in 3..19 {
            if i >= 10 {
                r_type = Ipv4Addr::echo_response_type();
                r_code = 0;
                hop_str = String::from(DESTINATION_STRING_V4);
            }

            test_map.insert(i, create_v4_yarrp_line_vec(i, i, r_type, r_code, &hop_str));
        }
        let mut route = Route::new(&test_map, MIN_TTL, MAX_TTL);
        imperiled_algo.check_route(&mut route);

        assert!(route.is_imperiled, "Route should be imperiled, is {}", route.is_imperiled);
        for router in return_set {
            if let Some(counting_file) = imperiled_algo.router_map.get(&router) {
                assert_eq!(counting_file.len(), 1, "Counting file should be of length one!");
            } else {
                panic!("Could not get router from map");
            }
        }
    }

    #[test]
    fn test_nonimperiled_looping_route() {
        init();

        let mut return_set = HashSet::new();
        return_set.insert(get_ipv6_hop(5));
        return_set.insert(get_ipv6_hop(6));

        let mut imperiled_algo = LoopImperiled::new_no_output(return_set.clone());

        let mut test_map = HashMap::new();
        let r_type = Ipv6Addr::time_exceeded_type();
        let r_code = 0;

        for i in 3..19 {
            let mut sent_ttl = i;
            if i >= 10 && i % 2 == 0 {
                sent_ttl = 8;
            } else if i >= 10 && i % 2 == 1 {
                sent_ttl = 9;
            }
            if 9 <= i && i <= 14 && i % 2 == 1 {
                continue;
            }
            test_map.insert(i, create_v6_yarrp_line_vec(i, sent_ttl, r_type, r_code, &EMPTY_STRING));
        }

        let mut route = Route::new(&test_map, MIN_TTL, MAX_TTL);
        imperiled_algo.check_route(&mut route);

        assert!(route.is_looping, "Route should be looping");
        assert!(!route.is_imperiled, "Route should not be imperiled, is {}", route.is_imperiled);

    }

    #[test]
    fn test_nonimperiled_looping_route_v4() {
        init();

        let mut return_set = HashSet::new();
        return_set.insert(get_ipv4_hop(5));
        return_set.insert(get_ipv4_hop(6));

        let mut imperiled_algo = LoopImperiled::new_no_output(return_set.clone());

        let mut test_map = HashMap::new();
        let r_type = Ipv4Addr::time_exceeded_type();
        let r_code = 0;

        for i in 3..19 {
            let mut sent_ttl = i;
            if i >= 10 && i % 2 == 0 {
                sent_ttl = 8;
            } else if i >= 10 && i % 2 == 1 {
                sent_ttl = 9;
            }
            if 9 <= i && i <= 14 && i % 2 == 1 {
                continue;
            }
            test_map.insert(i, create_v4_yarrp_line_vec(i, sent_ttl, r_type, r_code, &EMPTY_STRING));
        }

        let mut route = Route::new(&test_map, MIN_TTL, MAX_TTL);
        imperiled_algo.check_route(&mut route);

        assert!(route.is_looping, "Route should be looping");
        assert!(!route.is_imperiled, "Route should not be imperiled, is {}", route.is_imperiled);

    }

    #[test]
    fn test_nonimperiled_route() {
        init();

        let mut return_set = HashSet::new();
        return_set.insert(get_ipv6_hop(55));
        return_set.insert(get_ipv6_hop(66));

        let mut imperiled_algo = LoopImperiled::new_no_output(return_set.clone());

        let mut test_map = HashMap::new();
        let mut r_type = Ipv6Addr::time_exceeded_type();
        let mut r_code = 0;
        let mut hop_str = EMPTY_STRING;

        for i in 3..19 {
            if i >= 10 {
                r_type = Ipv6Addr::echo_response_type();
                r_code = 0;
                hop_str = String::from(DESTINATION_STRING_V6);
            }

            test_map.insert(i, create_v6_yarrp_line_vec(i, i, r_type, r_code, &hop_str));
        }
        let mut route = Route::new(&test_map, MIN_TTL, MAX_TTL);
        imperiled_algo.check_route(&mut route);

        assert!(!route.is_imperiled, "Route should not be imperiled, is {}", route.is_imperiled);

    }

    #[test]
    fn test_nonimperiled_route_v4() {
        init();

        let mut return_set = HashSet::new();
        return_set.insert(get_ipv4_hop(55));
        return_set.insert(get_ipv4_hop(66));

        let mut imperiled_algo = LoopImperiled::new_no_output(return_set.clone());

        let mut test_map = HashMap::new();
        let mut r_type = Ipv4Addr::time_exceeded_type();
        let mut r_code = 0;
        let mut hop_str = EMPTY_STRING;

        for i in 3..19 {
            if i >= 10 {
                r_type = Ipv4Addr::echo_response_type();
                r_code = 0;
                hop_str = String::from(DESTINATION_STRING_V4);
            }

            test_map.insert(i, create_v4_yarrp_line_vec(i, i, r_type, r_code, &hop_str));
        }
        let mut route = Route::new(&test_map, MIN_TTL, MAX_TTL);
        imperiled_algo.check_route(&mut route);

        assert!(!route.is_imperiled, "Route should not be imperiled, is {}", route.is_imperiled);

    }

    #[test]
    fn test_nonimperiled_route_destination_is_router() {
        init();

        let mut return_set = HashSet::new();
        return_set.insert(get_ipv6_hop(0x1000));

        let mut imperiled_algo = LoopImperiled::new_no_output(return_set.clone());

        let mut test_map = HashMap::new();
        let mut r_type = Ipv6Addr::time_exceeded_type();
        let mut r_code = 0;
        let mut hop_str = EMPTY_STRING;

        for i in 3..19 {
            if i >= 10 {
                r_type = Ipv6Addr::echo_response_type();
                r_code = 0;
                hop_str = String::from(DESTINATION_STRING_V6);
            }

            test_map.insert(i, create_v6_yarrp_line_vec(i, i, r_type, r_code, &hop_str));
        }
        let mut route = Route::new(&test_map, MIN_TTL, MAX_TTL);
        imperiled_algo.check_route(&mut route);

        assert!(!route.is_imperiled, "Route should not be imperiled, is {}", route.is_imperiled);

    }

    #[test]
    fn test_nonimperiled_route_destination_is_router_v4() {
        init();

        let mut return_set = HashSet::new();
        return_set.insert(get_ipv4_hop(254));

        let mut imperiled_algo = LoopImperiled::new_no_output(return_set.clone());

        let mut test_map = HashMap::new();
        let mut r_type = Ipv4Addr::time_exceeded_type();
        let mut r_code = 0;
        let mut hop_str = EMPTY_STRING;

        for i in 3..19 {
            if i >= 10 {
                r_type = Ipv4Addr::echo_response_type();
                r_code = 0;
                hop_str = String::from(DESTINATION_STRING_V4);
            }

            test_map.insert(i, create_v4_yarrp_line_vec(i, i, r_type, r_code, &hop_str));
        }
        let mut route = Route::new(&test_map, MIN_TTL, MAX_TTL);
        imperiled_algo.check_route(&mut route);

        assert!(!route.is_imperiled, "Route should not be imperiled, is {}", route.is_imperiled);

    }
}