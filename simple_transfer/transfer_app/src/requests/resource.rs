use crate::requests::Expand;
use arm::nullifier_key::NullifierKeyCommitment;
use arm::resource::Resource;
use serde::{Deserialize, Serialize};
use serde_with::base64::Base64;
use serde_with::serde_as;

/// Defines teh shape of a resource sent via JSON to the API.
/// Implements functions
#[serde_as]
#[derive(Deserialize, Serialize, Debug, PartialEq)]
pub struct JsonResource {
    #[serde_as(as = "Base64")]
    pub logic_ref: Vec<u8>,
    #[serde_as(as = "Base64")]
    pub label_ref: Vec<u8>,
    pub quantity: u128,
    #[serde_as(as = "Base64")]
    pub value_ref: Vec<u8>,
    pub is_ephemeral: bool,
    #[serde_as(as = "Base64")]
    pub nonce: Vec<u8>,
    #[serde_as(as = "Base64")]
    pub nk_commitment: Vec<u8>,
    #[serde_as(as = "Base64")]
    pub rand_seed: Vec<u8>,
}

impl Expand for Resource {
    type Struct = JsonResource;

    fn simplify(&self) -> JsonResource {
        JsonResource {
            logic_ref: self.logic_ref.clone(),
            label_ref: self.label_ref.clone(),
            quantity: self.quantity,
            value_ref: self.value_ref.clone(),
            is_ephemeral: self.is_ephemeral,
            nonce: self.nonce.clone(),
            nk_commitment: self.nk_commitment.inner().to_vec(),
            rand_seed: self.rand_seed.clone(),
        }
    }

    fn expand(json_resource: JsonResource) -> Self {
        let nk_commitment = NullifierKeyCommitment::from(json_resource.nk_commitment);
        Resource {
            logic_ref: json_resource.logic_ref,
            label_ref: json_resource.label_ref,
            quantity: json_resource.quantity,
            value_ref: json_resource.value_ref,
            is_ephemeral: json_resource.is_ephemeral,
            nonce: json_resource.nonce,
            nk_commitment,
            rand_seed: json_resource.rand_seed,
        }
    }
}
