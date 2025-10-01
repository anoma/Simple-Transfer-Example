use arm::nullifier_key::NullifierKeyCommitment;
use arm::resource::Resource;
use serde::{Deserialize, Serialize};
use serde_with::base64::Base64;
use serde_with::serde_as;

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

pub fn request_resource_to_resource(resource: JsonResource) -> Resource {
    let nk_commitment = NullifierKeyCommitment::from(resource.nk_commitment);
    Resource {
        logic_ref: resource.logic_ref,
        label_ref: resource.label_ref,
        quantity: resource.quantity,
        value_ref: resource.value_ref,
        is_ephemeral: resource.is_ephemeral,
        nonce: resource.nonce,
        nk_commitment,
        rand_seed: resource.rand_seed,
    }
}

pub fn resource_to_request_resource(resource: Resource) -> JsonResource {
    JsonResource {
        logic_ref: resource.logic_ref,
        label_ref: resource.label_ref,
        quantity: resource.quantity,
        value_ref: resource.value_ref,
        is_ephemeral: resource.is_ephemeral,
        nonce: resource.nonce,
        nk_commitment: resource.nk_commitment.inner().to_vec(),
        rand_seed: resource.rand_seed,
    }
}
