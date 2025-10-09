use crate::evm::errors::EvmError;
use crate::evm::errors::EvmError::EvmSubmitError;
use alloy::network::Ethereum;
use alloy::primitives::B256;
use alloy::providers::PendingTransactionBuilder;
use arm::merkle_path::MerklePath;
use arm::transaction::Transaction;
use arm::utils::bytes_to_words;
use evm_protocol_adapter_bindings::call::protocol_adapter;
use evm_protocol_adapter_bindings::conversion::ProtocolAdapter;
use evm_protocol_adapter_bindings::conversion::ProtocolAdapter::merkleProofReturn;
use hex::ToHex;
use risc0_zkvm::Digest;
use std::time::Duration;

/// Submit a transaction to the protocol adapter, and wait for confirmation.
async fn pa_submit_transaction(
    transaction: Transaction,
) -> Result<PendingTransactionBuilder<Ethereum>, EvmError> {
    // convert the transaction to an EVM transaction struct.
    let tx = ProtocolAdapter::Transaction::from(transaction);

    // submit the transaction
    let builder = protocol_adapter()
        .execute(tx)
        .send()
        .await
        .map_err(|_| EvmSubmitError)?;

    println!(
        "submitted transaction {}",
        builder.tx_hash().encode_hex::<String>()
    );
    Ok(builder)
}

/// Submit the transaction and wait for confirmations
pub async fn pa_submit_and_await(transaction: Transaction) -> Result<String, EvmError> {
    let transaction_builder = pa_submit_transaction(transaction).await?;
    let tx_hash = &transaction_builder.tx_hash();
    tokio::time::sleep(Duration::from_secs(60)).await;
    Ok(tx_hash.0.encode_hex())
}

/// Calls out to the protocol adapter to obtain the merkle proof for a given resource commitment.
/// Fails if the resource does not exist, or the PA cannot be contacted.
pub async fn pa_merkle_proof(commitment: Digest) -> Result<merkleProofReturn, EvmError> {
    let commitment_bytes = B256::from_slice(commitment.as_bytes());

    protocol_adapter()
        .merkleProof(commitment_bytes)
        .call()
        .await
        .map_err(|_| EvmError::MerklePathError)
}

/// Given a commitment of a resource, looks up the merkle path for this resource.
pub async fn pa_merkle_path(commitment: Digest) -> Result<MerklePath, EvmError> {
    let merkle_proof: merkleProofReturn = pa_merkle_proof(commitment).await?;

    let auth_path_vec: Vec<(Vec<u32>, bool)> = merkle_proof
        .siblings
        .into_iter()
        .enumerate()
        .map(|(i, sibling_b256)| {
            let sibling_digest = Digest::from_bytes(sibling_b256.0);
            let sibling = bytes_to_words(sibling_digest.as_bytes());
            let pa_sibling_is_left = !merkle_proof.directionBits.bit(i);
            let arm_leaf_is_on_right = pa_sibling_is_left;
            (sibling, arm_leaf_is_on_right)
        })
        .collect();

    Ok(MerklePath::from_path(auth_path_vec.as_slice()))
}
