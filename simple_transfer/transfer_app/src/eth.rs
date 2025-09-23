use arm::{
    merkle_path::MerklePath,
    transaction::Transaction,
    utils::bytes_to_words
};

use risc0_zkvm::sha::Digest;

use evm_protocol_adapter_bindings::call::protocol_adapter;
use evm_protocol_adapter_bindings::conversion::ProtocolAdapter;
use evm_protocol_adapter_bindings::conversion::ProtocolAdapter::ProtocolAdapterErrors;

pub async fn submit(transaction: Transaction) -> bool {
    let tx = ProtocolAdapter::Transaction::from(transaction);
    let result = protocol_adapter().execute(tx).send().await;

    match result {
        Ok(transactionbuilder) => {
            println!("transactionbuilder: {:?}", transactionbuilder);
            Some(transactionbuilder);
            true
        }
        Err(err) => {
            println!("{:?}", err);
            let decoded_err = err.as_decoded_interface_error::<ProtocolAdapterErrors>();
            println!("error: {:?}", decoded_err);
            false
        }
    }
}

pub async fn get_merkle_path(
    commitment: alloy::primitives::B256,
) -> Result<MerklePath, String> {
    let adapter = protocol_adapter();

    // First, let's check the latest root to see if the tree has been updated
    let latest_root = adapter
        .latestRoot()
        .call()
        .await
        .map_err(|e| format!("Failed to get latest root: {}", e))?;
    
    println!("Latest root: {:?}", latest_root);
    println!("Looking for commitment: {:?}", commitment);

    let res = adapter
        .merkleProof(commitment)
        .call()
        .await
        .map_err(|e| format!("Failed to call merkleProof: {}", e))?;

    let auth_path_vec: Vec<_> = res.siblings
        .into_iter()
        .enumerate()
        .map(|(i, sibling_b256)| {
            let sibling_digest = Digest::from_bytes(sibling_b256.0);
            let pa_sibling_is_left = !res.directionBits.bit(i as usize); 
            let arm_leaf_is_on_right = pa_sibling_is_left; 
            (sibling_digest, arm_leaf_is_on_right)
        })
        .collect();

    println!("Auth path length: {}", auth_path_vec.len());
    
    // Convert to the format expected by MerklePath::from_path
    let converted_path: Vec<(Vec<u32>, bool)> = auth_path_vec.into_iter().map(|(digest, bool_val)| {
        (bytes_to_words(digest.as_bytes()), bool_val)
    }).collect();

    Ok(MerklePath::from_path(&converted_path))
}
