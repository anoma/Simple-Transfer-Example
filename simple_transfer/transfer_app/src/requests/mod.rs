pub mod approve;
pub mod mint;
pub mod resource;
pub mod split;
pub mod transfer;

/// This trait converts from the simplified structs into their full equivalent.
/// For example, RequestResource to Resource.
pub trait Expand {
    type Struct;

    fn simplify(&self) -> Self::Struct;
    fn expand(json: Self::Struct) -> Self;
}
