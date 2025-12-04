// Generated protobuf code
pub mod protosyte {
    pub mod core {
        pub mod v2 {
            // Use the generated code
            pub use super::super::super::protosyte_core_v2::*;
        }
    }
}

// Re-export for convenience
pub use protosyte::core::v2::*;

// Fallback manual definitions if build.rs hasn't run yet
#[allow(unused)]
mod protosyte_core_v2 {
    pub use prost::Message;
    pub use prost_types::Timestamp;
    
    include!("protosyte.core.v2.rs");
}

