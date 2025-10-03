use crate::{AMOUNT, DEADLINE, ERC20, FORWARDER_ADDRESS};
use alloy::primitives::{Signature, B256, U256};
use alloy::signers::local::PrivateKeySigner;
use arm::action_tree::MerkleTree;
use arm::evm::CallType;
use arm::utils::{hash_bytes, words_to_bytes};
use evm_protocol_adapter_bindings::permit2::permit_witness_transfer_from_signature;
use std::env;
use tokio::runtime::Runtime;

// these can be dead code because they're used for development.
#[allow(dead_code)]
pub fn read_private_key() -> PrivateKeySigner {
    let env_val: String = env::var("PRIVATE_KEY").expect("env var PRIVATE_KEY not found");
    let private_key: PrivateKeySigner = env_val.parse().expect("failed to parse PRIVATE_KEY");
    private_key
}

pub fn value_ref(call_type: CallType, user_addr: &[u8]) -> Vec<u8> {
    let mut data = vec![call_type as u8];
    data.extend_from_slice(user_addr);
    hash_bytes(&data)
}

pub fn create_permit_signature(
    private_key: PrivateKeySigner,
    action_tree: MerkleTree,
    nonce: [u8; 32],
) -> Signature {
    let action_tree_root: Vec<u32> = action_tree.root();
    let action_tree_encoded: &[u8] = words_to_bytes(action_tree_root.as_slice());

    let rt = Runtime::new().unwrap();
    rt.block_on(permit_witness_transfer_from_signature(
        &private_key,
        ERC20,
        U256::from(AMOUNT),
        U256::from_be_bytes(nonce),
        U256::from(DEADLINE),
        FORWARDER_ADDRESS,
        B256::from_slice(action_tree_encoded), // Witness
    ))
}
