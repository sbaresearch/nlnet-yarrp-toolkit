pub mod route {
    use crate::structs::yarrp_line::yarrp_line::YarrpLine;
    use std::collections::{HashMap, HashSet};
    use log::{error, warn, trace};
    use std::fmt::Display;
    use std::hash::Hash;
    use crate::traits::IpAddrExt;
    use crate::traits::ipaddr_ext::ipaddr_ext::ICMPMode;

    pub struct Route<'a, T> {
        pub route: Vec<&'a YarrpLine<T>>,
        pub hop_answers: HashMap<u8, u32>,
        pub destination: T,
        pub credibility: f64,
        pub loop_start: u8,
        pub loop_end: u8,
        pub is_looping: bool,
        pub is_imperiled: bool,
        pub imperiled_routers: Vec<T>,
        pub has_full_loop: bool,
        pub has_spammer: bool,
        pub has_load_balancer: bool,
    }

    impl<T: Display + Copy + Clone + Eq + Hash + IpAddrExt> Route<'_, T> {
        pub fn new(route: &HashMap<u8, Vec<YarrpLine<T>>>, min_ttl: u8, max_ttl: u8) -> Route<T> {
            let any_hop;

            if let Some(temp_any_hop) = route.values().next() {
                any_hop = temp_any_hop;
            } else {
                error!("Failed at getting next value from iterator at Route creation!");
                panic!();
            }

            let mut has_spammer = false;
            let is_imperiled = false;
            let mut is_looping = false;
            let mut has_full_loop = false;
            let mut destination_reached = false;
            let mut has_load_balancer = false;

            let mut loop_start = 0;
            let mut loop_end = 0;

            let mut route_vec = Vec::new();
            let mut loop_map: HashMap<T, &YarrpLine<T>> = HashMap::new();
            let mut loop_hops: HashMap<T, Vec<u8>> = HashMap::new();
            let mut loop_vec: Vec<T> = Vec::new();

            let destination = any_hop[0].destination;
            let credibility;
            let hops_scanned = max_ttl - min_ttl + 1;

            trace!("Scanning hops from {} to {}", min_ttl, max_ttl);

            for hop in min_ttl..max_ttl + 1 {
                if let Some(answers) = route.get(&hop) {
                    // check if we got multiple answers at one point, if so flag as contains spammer
                    if answers.len() > 1 {
                        has_spammer = true;
                    }

                    if let Some(first_answer) = answers.get(0) {
                        // check if we are still on TTL exceeded

                        let error = T::check_errors(first_answer);
                        match error {
                            ICMPMode::ICMPReply => { destination_reached = true; }
                            ICMPMode::Other => {
                                trace!("Got other reply, ignoring!");
                                break;
                            }
                            ICMPMode::TTLe => {}
                        }

                        if let Some(found_line) = loop_map.get(&first_answer.hop) {
                            // do basic loop check
                            if !is_looping {
                                is_looping = true;
                                loop_end = first_answer.sent_ttl - 1;
                                loop_start = found_line.sent_ttl;
                                has_full_loop = Route::is_full_loop(route, loop_start, loop_end);

                                trace!("Found loop! {} - {} ; is full {}", loop_start, loop_end, has_full_loop);
                            }
                            // do NOT overwrite the first found loop!

                            // build map of looping hops with found sent_ttls
                            // this makes it easy to check for full loops or smaller loops later on
                            if let Some(vec) = loop_hops.get_mut(&first_answer.hop) {
                                vec.push(first_answer.sent_ttl);
                            } else {
                                trace!("Created entry for {}", first_answer.hop);
                                loop_vec.push(first_answer.hop);
                                let mut vec = Vec::new();
                                vec.push(found_line.sent_ttl);
                                vec.push(first_answer.sent_ttl);
                                loop_hops.insert(first_answer.hop, vec);
                            }
                        } else if first_answer.hop == destination {
                            trace!("Destination has been found!");
                            // ignore this possibility, route cannot loop if the destination is involved
                        } else {
                            trace!("Added {} at {}", first_answer.hop, first_answer.sent_ttl);
                            loop_map.insert(first_answer.hop, first_answer);
                        }

                        // add one answer to the route
                        route_vec.push(first_answer);
                    } else {
                        error!("Something went wrong on unwrapping a yarrpline for Route!");
                        error!("Skipping hop {} for destination {}", hop, destination);
                        continue;
                    }
                }
            }

            if is_looping && !has_full_loop {
                // do a second check if we did not find a full loop
                trace!("Did not find a full loop, scanning for better loops!");
                let mut min_loop = loop_end - loop_start;
                let mut better_loop_start = 0;
                let mut better_loop_end = 0;

                for hop in loop_vec {
                    let indices;
                    if let Some(temp_indices) = loop_hops.get(&hop) {
                        indices = temp_indices;
                    } else {
                        warn!("Could not find loop indices for {}", hop);
                        continue;
                    }

                    trace!("Checking indices for {}", hop);
                    let mut previous_value = 0;

                    for index in indices {
                        let index = index.to_owned();

                        if previous_value == 0 {
                            previous_value = index;
                            continue;
                        }

                        let current_loop = index - previous_value - 1;
                        let is_full = Route::is_full_loop(route, previous_value, index);

                        trace!("Found loop of {}, is full: {}", current_loop + 1, is_full);

                        if current_loop < min_loop || is_full {
                            trace!("Found better loop! {} <= {}", current_loop + 1, min_loop + 1);
                            min_loop = current_loop;
                            better_loop_start = previous_value;
                            better_loop_end = index - 1;

                            if is_full {
                                trace!("Found best loop possible, is full with len {}", current_loop + 1);
                                has_full_loop = is_full;
                                break;
                            }
                        }
                        previous_value = index;
                    }

                    // fully exit for loops, we're done here
                    if has_full_loop {
                        break;
                    }
                }

                if better_loop_end != 0 && better_loop_start != 0 {
                    loop_start = better_loop_start;
                    loop_end = better_loop_end;
                }
            }

            if destination_reached && is_looping {
                is_looping = false;
                has_full_loop = false;
                has_load_balancer = true;

                // ToDo: Think about whats the best to treat them
                loop_start = 0;
                loop_end = 0;
            }

            credibility = (route.len() as f64) / (hops_scanned as f64);
            trace!("credibility: {} / {} = {}", route.len(), hops_scanned, credibility);

            Route {
                route: route_vec,
                hop_answers: HashMap::new(),
                destination,
                credibility,
                loop_start,
                loop_end,
                is_looping,
                is_imperiled,
                imperiled_routers: Vec::new(),
                has_full_loop,
                has_spammer,
                has_load_balancer,
            }
        }

        pub fn is_full_loop(route: &HashMap<u8, Vec<YarrpLine<T>>>, start: u8, end: u8) -> bool {
            let mut current_loop_is_full = true;
            for index in start..end + 1 {
                if !route.contains_key(&index) {
                    current_loop_is_full = false;
                    break;
                }
            }
            current_loop_is_full
        }

        pub fn loop_len(&self) -> u8 {
            // loop has *at least* length 1
            if self.is_looping {
                return self.loop_end - self.loop_start + 1;
            }
            return 0;
        }

        pub fn get_loop_routers(&self) -> HashSet<T> {
            let mut return_set = HashSet::new();

            if self.is_looping {
                for route_item in &self.route {
                    if self.loop_start <= route_item.sent_ttl && route_item.sent_ttl <= self.loop_end {
                        return_set.insert(route_item.hop);
                    }
                }
            }

            return return_set;
        }

        pub fn get_preceding_router(&self) -> Option<(T, u8)> {
            for router in &self.route {
                if router.sent_ttl == self.loop_start - 1 {
                    return Some((router.hop, router.sent_ttl));
                }
            }
            None
        }

        pub fn get_preceding_router_named(&self) -> (String, u8) {
            let mut return_string = String::new();
            let mut return_ttl= 0;

            for router in &self.route {
                if router.sent_ttl == self.loop_start - 1 {
                    return_string = router.hop.to_string();
                    return_ttl = router.sent_ttl;
                }
            }

            if return_ttl == 0 {
                return_ttl = self.loop_start - 1;
                return_string = format!("Unknown-{}", return_ttl)
            }

            return (return_string, return_ttl)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};
    use crate::structs::{Route};
    use std::net::{Ipv6Addr, Ipv4Addr};
    use crate::helpers::test_helper::{init, DESTINATION_STRING_V6, DESTINATION_STRING_V4};
    use crate::helpers::test_helper::{get_ipv6_hop, create_v6_yarrp_line_vec};
    use crate::helpers::test_helper::{get_ipv4_hop, create_v4_yarrp_line_vec};
    use crate::helpers::test_helper::{EMPTY_STRING, MIN_TTL, MAX_TTL};
    use crate::traits::IpAddrExt;

    #[test]
    fn is_not_looping() {
        init();

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
        let route = Route::new(&test_map, MIN_TTL, MAX_TTL);

        assert!(!route.is_looping, "Route should not be looping! (is {})", route.is_looping);
        assert!(!route.has_full_loop, "Route should not be full looping! (is {})", route.has_full_loop);
        assert!(!route.has_spammer, "Route should not have spammers (is {})", route.has_spammer);
        assert!(!route.has_load_balancer, "Route should not have load balancers! (is {})", route.has_load_balancer);

        assert_eq!(route.loop_start, 0, "Loop Start is not 0");
        assert_eq!(route.loop_end, 0, "Loop End is not 0");
        assert_eq!(route.loop_len(), 0, "Loop should be of length 0!");
        assert_eq!(route.get_loop_routers(), HashSet::new());

        assert_eq!(route.destination, get_ipv6_hop(0x1000));
        assert_eq!(route.credibility, 1.0);
    }

    #[test]
    fn is_looping() {
        init();

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
            test_map.insert(i, create_v6_yarrp_line_vec(i, sent_ttl, r_type, r_code, &EMPTY_STRING));
        }
        let route = Route::new(&test_map, MIN_TTL, MAX_TTL);

        assert!(route.is_looping, "Route should be looping! (is {})", route.is_looping);
        assert!(route.has_full_loop, "Route should be full looping! (is {})", route.has_full_loop);
        assert!(!route.has_spammer, "Route should not have spammers (is {})", route.has_spammer);
        assert!(!route.has_load_balancer, "Route should not have load balancers! (is {})", route.has_load_balancer);

        assert_eq!(route.loop_start, 8, "Loop Start is not 8!");
        assert_eq!(route.loop_end, 9, "Loop End is not 9");
        assert_eq!(route.loop_len(), 2, "Loop should be of length 2!");

        let mut looping_routers = HashSet::new();
        looping_routers.insert(get_ipv6_hop(8));
        looping_routers.insert(get_ipv6_hop(9));
        assert_eq!(route.get_loop_routers(), looping_routers);

        assert_eq!(route.destination, get_ipv6_hop(0x1000));
        assert_eq!(route.credibility, 1.0);
    }

    #[test]
    fn is_looping_fragmented() {
        init();

        let mut test_map = HashMap::new();
        let r_type = Ipv6Addr::time_exceeded_type();
        let r_code = 0;
        let loop_hops: [u8; 4] = [10, 14, 16, 18];

        for i in 3..9 {
            test_map.insert(i, create_v6_yarrp_line_vec(i, i, r_type, r_code, &EMPTY_STRING));
        }

        for i in loop_hops.iter() {
            let i = i.to_owned();
            test_map.insert(i, create_v6_yarrp_line_vec(i, 10, r_type, r_code, &EMPTY_STRING));
        }

        let route = Route::new(&test_map, MIN_TTL, MAX_TTL);

        assert!(route.is_looping, "Route should be looping! (is {})", route.is_looping);
        assert!(!route.has_full_loop, "Route should NOT be full looping! (is {})", route.has_full_loop);
        assert!(!route.has_spammer, "Route should not have spammers (is {})", route.has_spammer);
        assert!(!route.has_load_balancer, "Route should not have load balancers! (is {})", route.has_load_balancer);

        assert_eq!(route.loop_start, 14, "Loop Start is not 14!");
        assert_eq!(route.loop_end, 15, "Loop End is not 15");
        assert_eq!(route.loop_len(), 2, "Loop should be of length 2!");

        let mut looping_routers = HashSet::new();
        looping_routers.insert(get_ipv6_hop(10));
        assert_eq!(route.get_loop_routers(), looping_routers);

        assert_eq!(route.destination, get_ipv6_hop(0x1000));
        assert_eq!(route.credibility, 10.0 / 16.0); // 10 / 16 (missing 9, 11, 12, 13, 15, 17)
    }

    #[test]
    fn is_fully_looping_later() {
        init();

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

        let route = Route::new(&test_map, MIN_TTL, MAX_TTL);

        assert!(route.is_looping, "Route should be looping! (is {})", route.is_looping);
        assert!(route.has_full_loop, "Route should be full looping! (is {})", route.has_full_loop);
        assert!(!route.has_spammer, "Route should not have spammers (is {})", route.has_spammer);
        assert!(!route.has_load_balancer, "Route should not have load balancers! (is {})", route.has_load_balancer);

        assert_eq!(route.loop_start, 14, "Loop Start is not 14!");
        assert_eq!(route.loop_end, 15, "Loop End is not 16");
        assert_eq!(route.loop_len(), 2, "Loop should be of length 2!");

        let mut looping_routers = HashSet::new();
        looping_routers.insert(get_ipv6_hop(8));
        looping_routers.insert(get_ipv6_hop(9));
        assert_eq!(route.get_loop_routers(), looping_routers);

        assert_eq!(route.destination, get_ipv6_hop(0x1000));
        assert_eq!(route.credibility, 13.0 / 16.0); // 13 / 16
    }


    #[test]
    fn has_spammer() {
        init();

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
            let mut vec = create_v6_yarrp_line_vec(i, i, r_type, r_code, &hop_str);

            if i == 9 {
                let yarrp_line = vec.get(0).unwrap().clone();
                vec.push(yarrp_line);
            }

            test_map.insert(i, vec);
        }

        let route = Route::new(&test_map, MIN_TTL, MAX_TTL);

        assert!(!route.is_looping, "Route should not be looping! (is {})", route.is_looping);
        assert!(!route.has_full_loop, "Route should not be full looping! (is {})", route.has_full_loop);
        assert!(route.has_spammer, "Route should have spammers (is {})", route.has_spammer);
        assert!(!route.has_load_balancer, "Route should not have load balancers! (is {})", route.has_load_balancer);

        assert_eq!(route.loop_start, 0, "Loop Start is not 0");
        assert_eq!(route.loop_end, 0, "Loop End is not 0");
        assert_eq!(route.loop_len(), 0, "Loop should be of length 0!");
        assert_eq!(route.get_loop_routers(), HashSet::new());

        assert_eq!(route.destination, get_ipv6_hop(0x1000));
        assert_eq!(route.credibility, 1.0);
    }

    #[test]
    fn has_load_balancer() {
        init();

        let mut test_map = HashMap::new();
        let mut r_type = Ipv6Addr::time_exceeded_type();
        let mut r_code = 0;
        let mut hop_str = EMPTY_STRING;

        for i in 3..19 {
            let mut sent_ttl = i;
            if i == 8 {
                // introduce a load balancer where one route is 1 hop longer, so we get a double hop :)
                sent_ttl -= 1;
            }

            if i >= 10 {
                r_type = Ipv6Addr::echo_response_type();
                r_code = 0;
                hop_str = String::from(DESTINATION_STRING_V6);
            }

            let vec = create_v6_yarrp_line_vec(i, sent_ttl, r_type, r_code, &hop_str);
            test_map.insert(i, vec);
        }
        let route = Route::new(&test_map, MIN_TTL, MAX_TTL);

        assert!(!route.is_looping, "Route should not be looping! (is {})", route.is_looping);
        assert!(!route.has_full_loop, "Route should not be full looping! (is {})", route.has_full_loop);
        assert!(!route.has_spammer, "Route should not have spammers (is {})", route.has_spammer);
        assert!(route.has_load_balancer, "Route should have load balancers! (is {})", route.has_load_balancer);

        assert_eq!(route.loop_start, 0, "Loop Start is not 0");
        assert_eq!(route.loop_end, 0, "Loop End is not 0");
        assert_eq!(route.loop_len(), 0, "Loop should be of length 0!");
        assert_eq!(route.get_loop_routers(), HashSet::new());

        assert_eq!(route.destination, get_ipv6_hop(0x1000));
        assert_eq!(route.credibility, 1.0);
    }

    #[test]
    fn is_looping_v4() {
        init();

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
            test_map.insert(i, create_v4_yarrp_line_vec(i, sent_ttl, r_type, r_code, &EMPTY_STRING));
        }
        let route = Route::new(&test_map, MIN_TTL, MAX_TTL);

        assert!(route.is_looping, "Route should be looping! (is {})", route.is_looping);
        assert!(route.has_full_loop, "Route should be full looping! (is {})", route.has_full_loop);
        assert!(!route.has_spammer, "Route should not have spammers (is {})", route.has_spammer);
        assert!(!route.has_load_balancer, "Route should not have load balancers! (is {})", route.has_load_balancer);

        assert_eq!(route.loop_start, 8, "Loop Start is not 8!");
        assert_eq!(route.loop_end, 9, "Loop End is not 9");
        assert_eq!(route.loop_len(), 2, "Loop should be of length 2!");

        let mut looping_routers = HashSet::new();
        looping_routers.insert(get_ipv4_hop(8));
        looping_routers.insert(get_ipv4_hop(9));
        assert_eq!(route.get_loop_routers(), looping_routers);

        assert_eq!(route.destination, get_ipv4_hop(254));
        assert_eq!(route.credibility, 1.0);
    }

    #[test]
    fn has_load_balancer_v4() {
        init();

        let mut test_map = HashMap::new();
        let mut r_type = Ipv4Addr::time_exceeded_type();
        let mut r_code = 0;
        let mut hop_str = EMPTY_STRING;

        for i in 3..19 {
            let mut sent_ttl = i;
            if i == 8 {
                // introduce a load balancer where one route is 1 hop longer, so we get a double hop :)
                sent_ttl -= 1;
            }

            if i >= 10 {
                r_type = Ipv4Addr::echo_response_type();
                r_code = 0;
                hop_str = String::from(DESTINATION_STRING_V4);
            }

            let vec = create_v4_yarrp_line_vec(i, sent_ttl, r_type, r_code, &hop_str);
            test_map.insert(i, vec);
        }
        let route = Route::new(&test_map, MIN_TTL, MAX_TTL);

        assert!(!route.is_looping, "Route should not be looping! (is {})", route.is_looping);
        assert!(!route.has_full_loop, "Route should not be full looping! (is {})", route.has_full_loop);
        assert!(!route.has_spammer, "Route should not have spammers (is {})", route.has_spammer);
        assert!(route.has_load_balancer, "Route should have load balancers! (is {})", route.has_load_balancer);

        assert_eq!(route.loop_start, 0, "Loop Start is not 0");
        assert_eq!(route.loop_end, 0, "Loop End is not 0");
        assert_eq!(route.loop_len(), 0, "Loop should be of length 0!");
        assert_eq!(route.get_loop_routers(), HashSet::new());

        assert_eq!(route.destination, get_ipv4_hop(254));
        assert_eq!(route.credibility, 1.0);
    }

    #[test]
    fn is_looping_fragmented_v4() {
        init();

        let mut test_map = HashMap::new();
        let r_type = Ipv4Addr::time_exceeded_type();
        let r_code = 0;
        let loop_hops: [u8; 4] = [10, 14, 16, 18];

        for i in 3..9 {
            test_map.insert(i, create_v4_yarrp_line_vec(i, i, r_type, r_code, &EMPTY_STRING));
        }

        for i in loop_hops.iter() {
            let i = i.to_owned();
            test_map.insert(i, create_v4_yarrp_line_vec(i, 10, r_type, r_code, &EMPTY_STRING));
        }

        let route = Route::new(&test_map, MIN_TTL, MAX_TTL);

        assert!(route.is_looping, "Route should be looping! (is {})", route.is_looping);
        assert!(!route.has_full_loop, "Route should NOT be full looping! (is {})", route.has_full_loop);
        assert!(!route.has_spammer, "Route should not have spammers (is {})", route.has_spammer);
        assert!(!route.has_load_balancer, "Route should not have load balancers! (is {})", route.has_load_balancer);

        assert_eq!(route.loop_start, 14, "Loop Start is not 14!");
        assert_eq!(route.loop_end, 15, "Loop End is not 15");
        assert_eq!(route.loop_len(), 2, "Loop should be of length 2!");

        let mut looping_routers = HashSet::new();
        looping_routers.insert(get_ipv4_hop(10));
        assert_eq!(route.get_loop_routers(), looping_routers);

        assert_eq!(route.destination, get_ipv4_hop(254));
        assert_eq!(route.credibility, 10.0 / 16.0); // 10 / 16 (missing 9, 11, 12, 13, 15, 17)
    }

    #[test]
    fn is_fully_looping_later_v4() {
        init();

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

        let route = Route::new(&test_map, MIN_TTL, MAX_TTL);

        assert!(route.is_looping, "Route should be looping! (is {})", route.is_looping);
        assert!(route.has_full_loop, "Route should be full looping! (is {})", route.has_full_loop);
        assert!(!route.has_spammer, "Route should not have spammers (is {})", route.has_spammer);
        assert!(!route.has_load_balancer, "Route should not have load balancers! (is {})", route.has_load_balancer);

        assert_eq!(route.loop_start, 14, "Loop Start is not 14!");
        assert_eq!(route.loop_end, 15, "Loop End is not 16");
        assert_eq!(route.loop_len(), 2, "Loop should be of length 2!");

        let mut looping_routers = HashSet::new();
        looping_routers.insert(get_ipv4_hop(8));
        looping_routers.insert(get_ipv4_hop(9));
        assert_eq!(route.get_loop_routers(), looping_routers);

        assert_eq!(route.destination, get_ipv4_hop(254));
        assert_eq!(route.credibility, 13.0 / 16.0); // 13 / 16
    }


    #[test]
    fn has_spammer_v4() {
        init();

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
            let mut vec = create_v4_yarrp_line_vec(i, i, r_type, r_code, &hop_str);

            if i == 9 {
                let yarrp_line = vec.get(0).unwrap().clone();
                vec.push(yarrp_line);
            }

            test_map.insert(i, vec);
        }

        let route = Route::new(&test_map, MIN_TTL, MAX_TTL);

        assert!(!route.is_looping, "Route should not be looping! (is {})", route.is_looping);
        assert!(!route.has_full_loop, "Route should not be full looping! (is {})", route.has_full_loop);
        assert!(route.has_spammer, "Route should have spammers (is {})", route.has_spammer);
        assert!(!route.has_load_balancer, "Route should not have load balancers! (is {})", route.has_load_balancer);

        assert_eq!(route.loop_start, 0, "Loop Start is not 0");
        assert_eq!(route.loop_end, 0, "Loop End is not 0");
        assert_eq!(route.loop_len(), 0, "Loop should be of length 0!");
        assert_eq!(route.get_loop_routers(), HashSet::new());

        assert_eq!(route.destination, get_ipv4_hop(254));
        assert_eq!(route.credibility, 1.0);
    }

    #[test]
    fn is_not_looping_v4() {
        init();

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
        let route = Route::new(&test_map, MIN_TTL, MAX_TTL);

        assert!(!route.is_looping, "Route should not be looping! (is {})", route.is_looping);
        assert!(!route.has_full_loop, "Route should not be full looping! (is {})", route.has_full_loop);
        assert!(!route.has_spammer, "Route should not have spammers (is {})", route.has_spammer);
        assert!(!route.has_load_balancer, "Route should not have load balancers! (is {})", route.has_load_balancer);

        assert_eq!(route.loop_start, 0, "Loop Start is not 0");
        assert_eq!(route.loop_end, 0, "Loop End is not 0");
        assert_eq!(route.loop_len(), 0, "Loop should be of length 0!");
        assert_eq!(route.get_loop_routers(), HashSet::new());

        assert_eq!(route.destination, get_ipv4_hop(254));
        assert_eq!(route.credibility, 1.0);
    }
}