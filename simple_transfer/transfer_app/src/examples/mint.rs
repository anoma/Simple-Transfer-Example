use crate::examples::shared::value_ref;
use crate::user::Keychain;
use arm::evm::CallType;
use arm::Digest;

/// The value ref for an ephemeral resource in a minting transaction has to hold the calltype. A
/// minting transaction means you create a resource, and consume an ephemeral resource. Therefore
/// the consumed ephemeral resource needs to have the wrapping calltype.
pub fn value_ref_ephemeral_mint(minter: &Keychain) -> Digest {
    value_ref(CallType::Wrap, minter.evm_address.as_ref())
}
