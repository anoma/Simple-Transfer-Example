// use crate::requests::resource::JsonResource;
// use k256::AffinePoint;
// use serde::{Deserialize, Serialize};
// use serde_with::base64::Base64;
// use serde_with::serde_as;
//
// #[serde_as]
// #[derive(Deserialize, Serialize, Debug, PartialEq)]
// pub struct SplitRequest {
//     pub resource_to_split: JsonResource,
//     pub padding_resource: JsonResource,
//     pub resource_to_transfer: JsonResource,
//     pub resource_to_keep: JsonResource, // A second resource with the remaining quantity will be created for the owner.
//     #[serde_as(as = "Base64")]
//     pub sender_nf_key: Vec<u8>,
//     pub sender_verifying_key: AffinePoint,
//     #[serde_as(as = "Base64")]
//     pub auth_signature: Vec<u8>,
//     pub owner_discovery_pk: AffinePoint,
//     pub owner_encryption_pk: AffinePoint,
//     pub receiver_discovery_pk: AffinePoint,
//     pub receiver_encryption_pk: AffinePoint,
// }
//
// // these can be dead code because they're used for development.
// #[allow(dead_code)]
// pub fn decode_split_request(json_str: &str) -> Option<SplitRequest> {
//     let create_request = serde_json::from_str::<SplitRequest>(json_str);
//     match create_request {
//         Ok(create_request) => Some(create_request),
//         Err(_) => {
//             println!("Failed to deserialize SplitRequest");
//             None
//         }
//     }
// }
