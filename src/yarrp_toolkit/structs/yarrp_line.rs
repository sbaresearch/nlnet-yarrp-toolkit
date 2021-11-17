pub mod yarrp_line {
    use log::error;
    use std::str::FromStr;

    // a yarrp output line is structured as following
    // target sec usec type code ttl hop rtt ipid psize rsize rttl rtos mpls count
    #[derive(Clone)]
    pub struct YarrpLine<T> {
        pub destination: T,
        pub hop: T,
        pub sec: i32,
        pub usec: i32,
        pub r_type: i32,
        pub r_code: i32,
        pub sent_ttl: u8,
        pub rtt: i32,
        pub ipid: i32,
        pub psize: i32,
        pub rsize: i32,
        pub received_ttl: i32,
        pub rtos: i32,
        pub mpls: String,
        pub count: i32
    }

    impl<T: FromStr> YarrpLine<T> {
        pub fn new(input: &str) -> Option<YarrpLine<T>> {
            let vec = input.split(' ').collect::<Vec<&str>>();
            if vec.len() != 15 {
                error!("Not enough arguments to parse");
                return None;
            }

            let destination;
            if let Ok(temp_value) = vec[0].parse() {
                destination = temp_value;
            } else {
                return None;
            }

            let hop;
            if let Ok(temp_value) = vec[6].parse() {
                hop = temp_value;
            } else {
                return None;
            }

            Some(YarrpLine {
                destination,
                hop,
                sec: vec[1].parse().unwrap(),
                usec: vec[2].parse().unwrap(),
                r_type: vec[3].parse().unwrap(),
                r_code: vec[4].parse().unwrap(),
                sent_ttl: vec[5].parse().unwrap(),
                rtt: vec[7].parse().unwrap(),
                ipid: vec[8].parse().unwrap(),
                psize: vec[9].parse().unwrap(),
                rsize: vec[10].parse().unwrap(),
                received_ttl: vec[11].parse().unwrap(),
                rtos: vec[12].parse().unwrap(),
                mpls: vec[13].to_string(),
                count: vec[14].parse().unwrap()
            })
        }
    }
}