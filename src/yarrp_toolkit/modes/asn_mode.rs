pub mod asn_mode {
    use clap::ArgMatches;
    use std::str::FromStr;
    use std::process::exit;
    use log::{error, warn, info};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::collections::{HashMap};

    use crate::traits::IpAddrExt;
    use crate::modes::{ModeEnum, ModeTrait};
    use crate::structs::{YarrpError, ASNIPAttribution};
    use crate::analytics::{ASNAttribution};

    pub struct ASNMode {
        mode: ModeEnum,
        output_path: String,
        asn_attribution: ASNAttribution,
        asn_dict: HashMap<String, u64>
    }

    impl ASNMode {
        pub fn new(matches: ArgMatches, v4: bool) -> ASNMode {
            let mode = ModeEnum::ASN;
            let mode_string = mode.to_string().to_lowercase();
            let sub_matches = matches.subcommand_matches(mode_string).unwrap();

            let routeviews_path;
            if let Some(path) = sub_matches.value_of("routeviews") {
                routeviews_path = path.to_string();
            } else {
                error!("Could not parse routeviews!");
                exit(1);
            }

            let output_path;
            if let Some(path) = sub_matches.value_of("output") {
                output_path = path.to_string();
            } else {
                error!("Could not parse routeviews!");
                exit(1);
            }

            let net_str = match v4 {
                true => Ipv4Addr::root_net(),
                false => Ipv6Addr::root_net()
            };
            let mut asn_attribution = ASNAttribution::new(&net_str);
            if let Err(_) = asn_attribution.load_routeviews_bgp(&routeviews_path) {
                error!("Could not load asn file!");
                exit(5);
            }

            ASNMode {
                mode,
                output_path,
                asn_attribution,
                asn_dict: HashMap::new()
            }
        }

        fn write_asn_csv(&self) -> Result<(), YarrpError> {
            let mut writer = csv::Writer::from_path(&self.output_path)?;

            for (asn, numbers) in &self.asn_dict {
                let output_obj = ASNIPAttribution{ asn: asn.clone(), num_ips: numbers.clone() };
                if let Err(_) = writer.serialize(&output_obj) {
                    error!("Could not serialize output object!");
                    exit(5);
                }
            }

            Ok(())
        }
    }

    impl ModeTrait for ASNMode {
        fn get_mode(&self) -> ModeEnum {
            self.mode
        }

        fn no_input_capable(&self) -> bool {
            false
        }

        fn parse_comment_line(&mut self, _input: &str) {
            // do nothing
        }

        fn parse_string_line(&mut self, input: &str) {
            // parse each line and assign ASN
            if let Ok(addr) = IpAddr::from_str(input) {
                if let Some(asn_vec) = self.asn_attribution.get_asn_for_ip(&addr) {
                    for asn in asn_vec {
                        if ! self.asn_dict.contains_key(&asn){
                            self.asn_dict.insert(asn.clone(), 0);
                        }

                        if let Some(value) = self.asn_dict.get_mut(&asn) {
                            *value += 1;
                        } else {
                            error!("Could not update ASN numbers!");
                        }
                    }
                }
            } else {
                warn!("Could not parse IP address from str {}!", input);
            }
        }

        fn do_file_rotate(&mut self, _file_number: u64, _file_name: &str) {}

        fn do_calculations(&mut self) {

            if let Err(_) = self.write_asn_csv() {
                error!("Could not write asn csv file!");
            }
        }

        fn print_output(&self) {
            info!("Loaded {} ASN!", self.asn_dict.len());
        }

        fn close(&mut self) {}
    }
}