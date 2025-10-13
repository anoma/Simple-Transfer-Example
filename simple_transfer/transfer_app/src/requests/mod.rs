use arm::Digest;

pub mod approve;
pub mod burn;
pub mod mint;
pub mod resource;
pub mod split;
pub mod transfer;

/// This trait converts from the simplified structs into their full equivalent.
/// For example, RequestResource to Resource.
pub trait Expand {
    type Struct;
    type Error;

    fn simplify(&self) -> Self::Struct;
    fn expand(json: Self::Struct) -> Result<Self, Self::Error>
    where
        Self: Sized;
}

fn to_array<const N: usize>(v: Vec<u8>, field: &str) -> Result<[u8; N], String> {
    v.try_into().map_err(|_| format!("{} invalid size", field))
}

fn to_digest(v: Vec<u8>, field: &str) -> Result<Digest, String> {
    v.try_into().map_err(|_| format!("{} invalid size", field))
}
