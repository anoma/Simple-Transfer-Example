use serde::{Deserialize, Serialize};
use serde_with::base64::Base64;
use serde_with::serde_as;

/// Defines the payload sent to the API to check if a user's address is approved.
#[serde_as]
#[derive(Deserialize, Serialize, Debug, PartialEq)]
pub struct ApproveRequest {
    #[serde_as(as = "Base64")]
    pub user_addr: Vec<u8>,
}
