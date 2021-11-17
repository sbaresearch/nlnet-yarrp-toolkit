pub mod yarrp_error {

    pub enum YarrpError {
        NotFoundError,
        CouldNotReadError,
        NotCompatibleError,
        CouldNotParseError,
        CouldNotSerializeError,
        ESError,
        CouldNotWriteError,
        CouldNotGlobError,
        TimeError
    }

    impl From<std::io::Error> for YarrpError{
        fn from(_: std::io::Error) -> Self {
            YarrpError::CouldNotReadError
        }
    }

    impl From<csv::Error> for YarrpError {
        fn from(_: csv::Error) -> Self {
            YarrpError::CouldNotReadError
        }
    }

    impl From<std::num::ParseIntError> for YarrpError {
        fn from(_: std::num::ParseIntError) -> Self {
            YarrpError::CouldNotParseError
        }
    }

    impl From<std::num::ParseFloatError> for YarrpError {
        fn from(_: std::num::ParseFloatError) -> Self {
            YarrpError::CouldNotParseError
        }
    }

    impl From<serde_json::Error> for YarrpError {
        fn from(_: serde_json::Error) -> Self {
            YarrpError::CouldNotSerializeError
        }
    }

    impl From<elasticsearch::Error> for YarrpError {
        fn from(_: elasticsearch::Error) -> Self {
            YarrpError::ESError
        }
    }

    impl From<std::net::AddrParseError> for YarrpError {
        fn from(_: std::net::AddrParseError) -> Self { YarrpError::CouldNotParseError }
    }

    impl From<ipnet::PrefixLenError> for YarrpError {
        fn from(_: ipnet::PrefixLenError) -> Self {
            YarrpError::CouldNotParseError
        }
    }

    impl From<ipnet::AddrParseError> for YarrpError {
        fn from (_: ipnet::AddrParseError) -> Self { YarrpError::CouldNotParseError }
    }

    impl From<glob::PatternError> for YarrpError {
        fn from (_: glob::PatternError) -> Self { YarrpError::CouldNotGlobError }
    }

    impl From<glob::GlobError> for YarrpError {
        fn from (_: glob::GlobError) -> Self { YarrpError::CouldNotGlobError }
    }

    impl From<std::time::SystemTimeError> for YarrpError {
        fn from (_: std::time::SystemTimeError) -> Self { YarrpError::TimeError }

    }

}
