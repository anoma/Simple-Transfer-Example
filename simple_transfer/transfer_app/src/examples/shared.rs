use crate::examples::mint::TransactionError;
use crate::examples::mint::TransactionError::VerificationFailure;
use crate::user::Keychain;
use alloy::primitives::{Signature, B256, U256};
use alloy::signers::local::PrivateKeySigner;
use arm::action_tree::MerkleTree;
use arm::evm::CallType;
use arm::transaction::Transaction;
use arm::utils::{hash_bytes, words_to_bytes};
use evm_protocol_adapter_bindings::permit2::permit_witness_transfer_from_signature;
use rand::Rng;
use std::env;
use crate::AnomaPayConfig;

/// Generates a random nonce. A nonce is an array of 32 8-byte integers.
pub fn random_nonce() -> [u8; 32] {
    let mut rng = rand::thread_rng();
    let nonce: [u8; 32] = rng.gen();
    nonce
}

/// Verifies a transaction. Returns an error if verification failed.
pub fn verify_transaction(transaction: Transaction) -> Result<(), TransactionError> {
    let verified = transaction.verify();
    if !verified {
        Err(VerificationFailure)
    } else {
        Ok(())
    }
}

/// The value ref for a created resource in a mint transaction needs to hold the verifying key of
/// the owner of the resource. This can be any persons' verifying key, but in this case we use
/// the verifying key of the person who mints the transaction.
///
/// The value ref for a created resource in a transfer transaction is the verifying key of the
/// receiver.
///
/// The intuition here is that the value ref defines the owner of the resource.
pub fn value_ref_created(keychain: &Keychain) -> Vec<u8> {
    hash_bytes(&keychain.auth_verifying_key().to_bytes())
}

/// The label ref for a resource in the AnomaPay backend uniquely identifies the resource. This
/// value allows us to distinguish between wrapped USDC or USDT tokens, for example. The
/// forwarder contract is used for multiple tokens, so the tuple (forwarder address, token
/// contract) uniquely identifies a resource.
pub fn label_ref(config : &AnomaPayConfig) -> Vec<u8> {
    hash_bytes(
        &[
            config.forwarder_address.to_vec(),
            config.token_address.to_vec(),
        ]
        .concat(),
    )
}

// these can be dead code because they're used for development.
#[allow(dead_code)]
pub fn read_private_key() -> PrivateKeySigner {
    let env_val: String = env::var("PRIVATE_KEY").expect("env var PRIVATE_KEY not found");
    let private_key: PrivateKeySigner = env_val.parse().expect("failed to parse PRIVATE_KEY");
    private_key
}

#[allow(dead_code)]
pub fn read_address() -> String {
    env::var("USER_ADDRESS").expect("env var USER_ADDRESS not found")
}

pub fn value_ref(call_type: CallType, user_addr: &[u8]) -> Vec<u8> {
    let mut data = vec![call_type as u8];
    data.extend_from_slice(user_addr);
    hash_bytes(&data)
}

pub async fn create_permit_signature(
    private_key: &PrivateKeySigner,
    action_tree: MerkleTree,
    nullifier: [u8; 32],
    amount: u128,
    config: &AnomaPayConfig
) -> Signature {

    let action_tree_root: Vec<u32> = action_tree.root();
    let action_tree_encoded: &[u8] = words_to_bytes(action_tree_root.as_slice());

    permit_witness_transfer_from_signature(
        private_key,
        config.token_address,
        U256::from(amount),
        U256::from_be_bytes(nullifier),
        U256::from(config.deadline),
        config.forwarder_address,
        B256::from_slice(action_tree_encoded), // Witness
    )
    .await
}
