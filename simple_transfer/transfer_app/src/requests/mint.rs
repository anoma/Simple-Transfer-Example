use crate::requests::resource::JsonResource;
use crate::Base64;
use k256::AffinePoint;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

#[serde_as]
#[derive(Deserialize, Serialize, Debug, PartialEq)]
pub struct CreateRequest {
    pub consumed_resource: JsonResource,
    pub created_resource: JsonResource,
    #[serde_as(as = "Base64")]
    pub latest_cm_tree_root: Vec<u8>,
    #[serde_as(as = "Base64")]
    pub consumed_nf_key: Vec<u8>,
    #[serde_as(as = "Base64")]
    pub forwarder_addr: Vec<u8>,
    #[serde_as(as = "Base64")]
    pub token_addr: Vec<u8>,
    #[serde_as(as = "Base64")]
    pub user_addr: Vec<u8>,
    #[serde_as(as = "Base64")]
    pub permit_nonce: Vec<u8>,
    #[serde_as(as = "Base64")]
    pub permit_deadline: Vec<u8>,
    #[serde_as(as = "Base64")]
    pub permit_sig: Vec<u8>,
    pub created_discovery_pk: AffinePoint,
    pub created_encryption_pk: AffinePoint,
}

pub fn parse_json_request(json_str: &str) -> Option<CreateRequest> {
    let create_request = serde_json::from_str::<CreateRequest>(json_str);
    match create_request {
        Ok(create_request) => Some(create_request),
        Err(_) => {
            println!("Failed to deserialize CreateRequest");
            None
        }
    }
}
