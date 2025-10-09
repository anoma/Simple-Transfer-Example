// use serde::{Deserialize, Serialize};
// use serde_with::base64::Base64;
// use serde_with::serde_as;
//
// /// Struct to hold the fields for an approval check request.
// #[serde_as]
// #[derive(Deserialize, Serialize, Debug, PartialEq)]
// pub struct CheckApproveRequest {
//     #[serde_as(as = "Base64")]
//     pub address: Vec<u8>,
// }
//
// // these can be dead code because they're used for development.
// #[allow(dead_code)]
// pub fn decode_approve_request(json_str: &str) -> Option<CheckApproveRequest> {
//     let approve_request = serde_json::from_str::<CheckApproveRequest>(json_str);
//     match approve_request {
//         Ok(approve_request) => Some(approve_request),
//         Err(_) => {
//             println!("Failed to deserialize CheckApproveRequest");
//             // None
//         }
//     }
// }
