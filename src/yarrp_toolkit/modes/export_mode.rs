pub mod export_mode {
    use clap::ArgMatches;
    use elasticsearch::cluster::ClusterHealthParts;
    use elasticsearch::{Elasticsearch, IndexParts};
    use elasticsearch::http::StatusCode;
    use elasticsearch::http::transport::Transport;
    use elasticsearch::indices::{IndicesCreateParts, IndicesExistsParts, IndicesDeleteParts, Indices};
    use serde_json::{json, Value};
    use tokio::runtime::Runtime;
    use log::{error, info, debug, trace};
    use serde::{Serialize, Deserialize};

    use crate::modes::{ModeEnum, ModeTrait};
    use std::process::exit;
    use std::collections::{HashMap, HashSet};
    use crate::structs::{YarrpLine, Route, YarrpError};
    use crate::analytics::{LoopAnalysis, LoopStorage, LoopStorageError};
    use std::net::Ipv6Addr;

    pub struct ExportMode {
        pub mode: ModeEnum,
        pub tokio_runtime: Runtime,
        pub elastic_client: Elasticsearch,
        pub meta_info: HashMap<String, String>,
        pub line_count: u64,
        pub loop_analysis: LoopAnalysis<Ipv6Addr>,
        pub loop_ids: HashSet<String>,
        lower_ttl: u8,
        upper_ttl: u8,
    }

    #[derive(Serialize, Deserialize)]
    struct LoopBody {
        id: String,
        routers: HashMap<u8, RouteBody>,
        // ip address, rtt
        start: u8,
        end: u8,
        full_loop: bool,
        loop_length: u8,
    }

    #[derive(Serialize, Deserialize)]
    struct RouteBody {
        hop: String,
        rtt: i32
    }

    impl ExportMode {
        pub fn new(matches: ArgMatches) -> ExportMode {
            let mode = ModeEnum::Export;
            let mode_string = mode.to_string().to_lowercase();

            let sub_matches = matches.subcommand_matches(mode_string).unwrap();

            let subcommand: &str;
            if let Some(temp_subcommand) = sub_matches.subcommand_name() {
                subcommand = temp_subcommand;
            } else {
                println!("No subcommand called!");
                println!("{}", sub_matches.usage());
                exit(1);
            }
            if !subcommand.eq("es") {
                println!("Subcommand not recognized: {}", subcommand);
                println!("{}", sub_matches.usage());
                exit(1);
            }

            let export_command = sub_matches.subcommand_matches("es").unwrap();
            let host = export_command.value_of("host").unwrap();
            let port;
            let mut delete = false;

            let min_ttl = export_command.value_of("min_ttl").unwrap().parse().unwrap();
            let max_ttl = export_command.value_of("max_ttl").unwrap().parse().unwrap();

            if export_command.is_present("port") {
                port = export_command.value_of("port").unwrap()
            } else {
                port = "9200";
            }

            if export_command.occurrences_of("delete") > 0 {
                delete = true;
            }

            let mut connection_string = format!("{}:{}", host, port);
            if !connection_string.starts_with("http") {
                connection_string = format!("http://{}", connection_string);
            }
            info!("ElasticSearch Module says hi (^_^)/");
            info!("Connecting to {}", connection_string);
            let connection_url = &connection_string;

            let elastic_client;
            match Transport::single_node(connection_url) {
                Ok(transport) => {
                    elastic_client = Elasticsearch::new(transport);
                }
                Err(e) => {
                    error!("Could not create transport layer for ES Cluster: {}", e);
                    exit(1);
                }
            }

            // ToDo: React on cluster health other than green
            // e.g. if yellow, wait a bit, if red, cancel execution
            let tokio_runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(6)
                .thread_name("rust_yarrp_worker")
                .enable_io()
                .enable_time()
                .build()
                .unwrap();

            match tokio_runtime.block_on(ExportMode::get_health(&elastic_client)) {
                Ok(test) => println!("Cluster status: {}", test["status"]),
                Err(e) => {
                    error!("Could not read cluster health: {}", e);
                    exit(1);
                }
            };

            match tokio_runtime.block_on(ExportMode::check_and_create_indices(&elastic_client, delete)) {
                true => {}
                false => {
                    error!("Creating indices did not work! Exiting!");
                    exit(1);
                }
            };

            // TODO: add imperiled check

            ExportMode {
                mode,
                tokio_runtime,
                elastic_client,
                meta_info: HashMap::new(),
                line_count: 0,
                loop_analysis: LoopAnalysis::new(true, String::new(), "", ""),
                loop_ids: HashSet::new(),
                lower_ttl: min_ttl,
                upper_ttl: max_ttl
            }
        }

        async fn get_health(client: &Elasticsearch) -> Result<Value, elasticsearch::Error> {
            let cluster = client.cluster();
            let cluster_health_parts = cluster.health(ClusterHealthParts::None);

            match cluster_health_parts.send().await {
                Ok(cluster_health) => return cluster_health.json::<Value>().await,
                Err(e) => {
                    eprintln!("Could not read cluster health: {}", e);
                    exit(1);
                }
            };
        }

        async fn delete_index(client: &Indices<'_>, index: &[&str; 1]) -> bool {
            let return_code;
            match client.delete(IndicesDeleteParts::Index(index)).send().await {
                Ok(delete_response) => {
                    if delete_response.status_code() != StatusCode::OK {
                        let text = delete_response.text().await.unwrap();
                        eprintln!("Removal of index failed: {}", text);
                        return_code = false;
                    } else {
                        println!("Deleted Index {}", index[0]);
                        return_code = true;
                    }
                }
                Err(e) => {
                    eprintln!("Err: Removal of index failed: {}", e);
                    exit(1);
                }
            }
            return_code
        }

        async fn create_index(client: &Indices<'_>, index: &str) -> bool {
            let body = json!({
                    "mappings" : {
                        "properties" : {
                        }
                    },
                    "settings": {
                        "index": {
                          "number_of_shards": 3
                        }
                    }
                });
            let indices_create_parts = IndicesCreateParts::Index(index);

            let return_code;
            match client.create(indices_create_parts).body(body).send().await {
                Ok(response) => {
                    if response.status_code() != StatusCode::OK {
                        let text = response.text().await.unwrap();
                        eprintln!("Status Code: Something went wrong while creating index: {}", text);
                        return_code = false;
                    } else {
                        println!("Created index {}", index);
                        return_code = true;
                    }
                }
                Err(e) => {
                    eprintln!("Err: Could not create Index! {}", e);
                    return_code = false;
                }
            }
            return_code
        }

        async fn check_and_create_indices(client: &Elasticsearch, delete: bool) -> bool {
            let indices = ["scans", "routes", "stats", "loops"];
            let mut create_indices: Vec<String> = Vec::new();
            let ns_client = client.indices();

            for item in indices.iter() {
                let temp_list = [*item];
                let indices_parts = IndicesExistsParts::Index(&temp_list);

                // TODO:
                let responses = ns_client.exists(indices_parts).send().await.unwrap();

                if responses.status_code() == StatusCode::NOT_FOUND {
                    create_indices.push(item.to_string());
                } else if delete {
                    if ExportMode::delete_index(&ns_client, &temp_list).await == false {
                        return false;
                    }
                    create_indices.push(item.to_string());
                } else {
                    debug!("Index already existing {}", item);
                }
            }

            for item in create_indices {
                if ExportMode::create_index(&ns_client, &item).await == false {
                    return false;
                }
            }
            return true;
        }

        async fn create_scan(client: &Elasticsearch, meta_info: &HashMap<String, String>) -> bool {
            let body = serde_json::to_value(meta_info).unwrap();

            return match client.index(IndexParts::Index("scans")).body(body).send().await {
                Err(e) => {
                    error!("Could not create index for scan: {}", e);
                    false
                }
                Ok(_response) => {
                    true
                }
            };
        }

        async fn add_loop(client: Elasticsearch, data: LoopBody) -> Result<(), YarrpError> {
            let body = serde_json::to_value(&data)?;
            debug!("Created body for indexing {}", body);
            if let Ok(response) = client.index(IndexParts::IndexId("loops", &data.id)).body(body).send().await {
                if response.status_code().as_u16() >= 400 {
                    error!("Status code: {}", response.status_code());
                    error!("Got error!");
                    let text = response.text().await?;
                    error!("{}", text);
                    return Err(YarrpError::NotFoundError);
                }
            }
            trace!("Posted to es cluster!");
            return Ok(());
        }

        pub fn clear(&mut self) {
            self.meta_info.clear();
        }

        pub fn store_scan(&mut self) {
            info!("Storing scan!");
            let client = &self.elastic_client;
            let meta_info = &self.meta_info;

            match self.tokio_runtime.block_on(ExportMode::create_scan(client, meta_info)) {
                true => {}
                false => {
                    error!("Creating scan index did not work");
                }
            };
        }

        pub fn store_loops(&mut self) {
            info!("Storing loop!");
            for (_key, value) in &self.loop_analysis.ttl_map {
                let route = Route::new(value, self.lower_ttl, self.upper_ttl);
                let loop_id;

                if !route.is_looping || !route.has_full_loop {
                    continue;
                }

                match LoopStorage::create_loop_identifier(&route.get_loop_routers()) {
                    Ok(temp_id) => {loop_id = temp_id}
                    Err(LoopStorageError::NothingToHashError) => {
                        error!("Nothing to hash for the given router set!");
                        continue;
                    }
                    Err(_e) => {
                        eprintln!("Other error");
                        continue;
                    }
                }

                trace!("Got loop id {}", loop_id);

                // only insert loop into es if its not already been added
                if self.loop_ids.contains(&loop_id) {
                    trace!("Loop id is known, ignoring!");
                    continue;
                }

                debug!("Inserting Loop {}", loop_id);
                self.loop_ids.insert(loop_id.clone());

                trace!("Building Hashmap with tuples!");
                let mut loop_map = HashMap::new();
                for router_line in &route.route {
                    if route.loop_start <= router_line.sent_ttl && router_line.sent_ttl <= route.loop_end {
                        let hop_str = router_line.hop.to_string();
                        let hop_tuple = RouteBody{ hop: hop_str, rtt: router_line.rtt };
                        loop_map.insert(router_line.sent_ttl, hop_tuple);
                    }
                }

                trace!("Building LoopBody!");
                let loop_item = LoopBody {
                    id: loop_id.clone(),
                    routers: loop_map,
                    start: route.loop_start,
                    end: route.loop_end,
                    full_loop: route.has_full_loop,
                    loop_length: route.loop_len(),
                };

                // 87,20s user 5,64s system 98% cpu 1:34,47 total
                trace!("Adding to es cluster");
                let cloned_es = self.elastic_client.clone();
                let _handle = self.tokio_runtime.spawn(ExportMode::add_loop(cloned_es, loop_item));

            }
        }
    }

    impl ModeTrait for ExportMode {
        fn get_mode(&self) -> ModeEnum {
            self.mode
        }

        fn no_input_capable(&self) -> bool {
            false
        }

        fn parse_comment_line(&mut self, input: &str) {
            if let Some(index) = input.find(":") {
                let key = input[0..index].to_owned();
                let value = input[index + 1..].trim().to_owned();
                self.meta_info.insert(key, value);
            } else {
                info!("Ignoring invalid meta string {}", input);
            }
        }

        fn parse_string_line(&mut self, input: &str) {
            self.line_count += 1;
            if let Some(yarrp_line) = YarrpLine::new(input) {
                self.loop_analysis.add_ttl(yarrp_line);
            }
        }

        fn do_file_rotate(&mut self, _file_number: u64, _file_name: &str) {
            self.store_loops();
            self.loop_analysis.clear();
        }

        fn do_calculations(&mut self) {}

        fn print_output(&self) {}

        fn close(&mut self) {
            self.clear();
        }
    }
}