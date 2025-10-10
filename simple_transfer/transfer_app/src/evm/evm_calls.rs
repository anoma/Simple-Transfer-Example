use crate::evm::errors::EvmError;
use crate::evm::errors::EvmError::{EvmSubmitError, IndexerError};
use alloy::hex::ToHexExt;
use alloy::network::Ethereum;
use alloy::providers::PendingTransactionBuilder;
use arm::merkle_path::MerklePath;
use arm::transaction::Transaction;
use arm::Digest;
use evm_protocol_adapter_bindings::call::protocol_adapter;
use evm_protocol_adapter_bindings::conversion::ProtocolAdapter;
use futures::TryFutureExt;
use reqwest::Error;
use serde::Deserialize;
use serde_with::base64::Base64;
use serde_with::serde_as;
use std::time::Duration;

/// Submit a transaction to the protocol adapter, and wait for confirmation.
async fn pa_submit_transaction(
    transaction: Transaction,
) -> Result<PendingTransactionBuilder<Ethereum>, EvmError> {
    // convert the transaction to an EVM transaction struct.
    let tx = ProtocolAdapter::Transaction::from(transaction);

    // submit the transaction
    let builder = protocol_adapter().execute(tx).send().await.map_err(|err| {
        println!("Failed to submit transaction {:?}", err);
        EvmSubmitError
    })?;

    println!(
        "submitted transaction {}",
        ToHexExt::encode_hex(&builder.tx_hash())
    );
    Ok(builder)
}

/// Submit the transaction and wait for confirmations
pub async fn pa_submit_and_await(transaction: Transaction, wait: u64) -> Result<String, EvmError> {
    let transaction_builder = pa_submit_transaction(transaction).await?;
    let tx_hash = &transaction_builder.tx_hash();
    tokio::time::sleep(Duration::from_secs(wait)).await;
    Ok(ToHexExt::encode_hex(&tx_hash.0))
}

// /// Calls out to the protocol adapter to obtain the merkle proof for a given resource commitment.
// /// Fails if the resource does not exist, or the PA cannot be contacted.
// pub async fn pa_merkle_proof(commitment: Digest) -> Result<merkleProofReturn, EvmError> {
//     let commitment_bytes = B256::from_slice(commitment.as_bytes());
//
//     protocol_adapter()
//         .merkleProof(commitment_bytes)
//         .call()
//         .await
//         .map_err(|_| EvmError::MerklePathError)
// }

#[serde_as]
#[derive(Deserialize, Debug, PartialEq)]
struct ProofResponse {
    root: String,
    frontiers: Vec<Frontier>,
}

#[serde_as]
#[derive(Deserialize, Debug, PartialEq)]
struct Frontier {
    #[serde_as(as = "Base64")]
    neighbour: Vec<u8>,
    is_left: bool,
}

/// Fetches the merkle path from the indexer and returns its parsed response.
/// This still has to be converted into a real MerklePath struct.
async fn merkle_path_from_indexer(commitment: Digest) -> Result<ProofResponse, Error> {
    let hash = ToHexExt::encode_hex(&commitment);
    let url = format!("http://localhost:4000/generate_proof/0x{}", hash);
    let response = reqwest::get(&url).await?;
    response.json().await
}

/// Given a commitment of a resource, looks up the merkle path for this resource.
pub async fn pa_merkle_path(commitment: Digest) -> Result<MerklePath, EvmError> {
    let merkle_path_response = merkle_path_from_indexer(commitment)
        .map_err(|_| IndexerError)
        .await?;

    let merkle_path: Result<Vec<(Digest, bool)>, EvmError> = merkle_path_response
        .frontiers
        .into_iter()
        .map(|frontier| {
            println!("frontier: {:?}", frontier.neighbour);
            let bytes: [u8; 48] = frontier.neighbour.as_slice().try_into().map_err(|e| {
                println!("{:?}", e);
                IndexerError
            })?;
            let sibling = Digest::from_bytes(bytes);
            Ok((sibling, frontier.is_left))
        })
        .collect();
    let merkle_path = merkle_path?;

    Ok(MerklePath::from_path(merkle_path.as_slice()))
}
