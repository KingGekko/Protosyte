// Generated protobuf code
pub mod protosyte {
    pub mod core {
        pub mod v2 {
            pub use prost::Message;
            pub use prost_types::Timestamp;
            
            include!("protosyte.core.v2.rs");
        }
    }
}

// Re-export for convenience
pub use protosyte::core::v2::*;
