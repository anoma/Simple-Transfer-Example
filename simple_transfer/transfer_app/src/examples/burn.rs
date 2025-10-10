use crate::examples::shared::value_ref;
use crate::user::Keychain;
use arm::evm::CallType;
use arm::Digest;

/// The value ref for an ephemeral resource in a burn transaction has to hold the calltype. A
/// burning transaction means you create an ephemeral resource, and consume an non-ephemeral
/// resource. Therefore, the created ephemeral resource needs to have the unwrapping calltype.
pub(crate) fn value_ref_ephemeral_burn(burner: &Keychain) -> Digest {
    value_ref(CallType::Unwrap, burner.evm_address.as_ref())
}
