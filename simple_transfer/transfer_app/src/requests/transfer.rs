use crate::requests::resource::JsonResource;
use k256::AffinePoint;
use serde::{Deserialize, Serialize};
use serde_with::base64::Base64;
use serde_with::serde_as;

#[serde_as]
#[derive(Deserialize, Serialize, Debug, PartialEq)]
pub struct TransferRequest {
    pub transferred_resource: JsonResource,
    pub created_resource: JsonResource,
    #[serde_as(as = "Base64")]
    pub sender_nf_key: Vec<u8>,
    pub sender_verifying_key: AffinePoint,
    #[serde_as(as = "Base64")]
    pub auth_signature: Vec<u8>,
    pub receiver_discovery_pk: AffinePoint,
    pub receiver_encryption_pk: AffinePoint,
}

// these can be dead code because they're used for development.
#[allow(dead_code)]
pub fn parse_json_transfer_request(json_str: &str) -> Option<TransferRequest> {
    let create_request = serde_json::from_str::<TransferRequest>(json_str);
    match create_request {
        Ok(create_request) => Some(create_request),
        Err(_) => {
            println!("Failed to deserialize TransferRequest");
            None
        }
    }
}
