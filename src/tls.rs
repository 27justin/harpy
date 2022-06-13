use pnet_macros::packet;
use pnet_macros_support::types::*;

#[packet]
pub struct Tls {
    pub content_type: u8,
    pub version: u16be,
    pub length: u16be,
    #[payload]
    pub payload: Vec<u8>
}

