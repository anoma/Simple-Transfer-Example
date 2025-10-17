use crate::evm::errors::EvmError;
use crate::evm::errors::EvmError::IndexerError;
use alloy::hex::ToHexExt;
use alloy::network::ReceiptResponse;
use alloy::rpc::types::TransactionReceipt;
use arm::merkle_path::MerklePath;
use arm::transaction::Transaction;
use arm::Digest;
use evm_protocol_adapter_bindings::call::protocol_adapter;
use evm_protocol_adapter_bindings::conversion::ProtocolAdapter;
use futures::TryFutureExt;
use reqwest::Error;
use serde::Deserialize;
use serde_with::hex::Hex;
use serde_with::serde_as;

/// Submit a transaction to the protocol adapter, and wait for the receipt
pub async fn pa_submit_transaction(
    transaction: Transaction,
) -> Result<TransactionReceipt, EvmError> {
    // convert the transaction to an EVM transaction struct.
    let tx = ProtocolAdapter::Transaction::from(transaction);

    // submit the transaction
    let receipt = protocol_adapter()
        .execute(tx)
        .send()
        .await
        .expect("Failed to submit transaction")
        .get_receipt()
        .await
        .expect("Failed to get receipt");

    println!("submitted transaction {}", receipt.transaction_hash());
    Ok(receipt)
}

#[serde_as]
#[derive(Deserialize, Debug, PartialEq)]
struct ProofResponse {
    root: String,
    frontiers: Vec<Frontier>,
}

#[serde_as]
#[derive(Deserialize, Debug, PartialEq)]
struct Frontier {
    #[serde_as(as = "Hex")]
    neighbour: Vec<u8>,
    is_left: bool,
}

/// Fetches the merkle path from the indexer and returns its parsed response.
/// This still has to be converted into a real MerklePath struct.
async fn merkle_path_from_indexer(commitment: Digest) -> Result<ProofResponse, Error> {
    let hash = ToHexExt::encode_hex(&commitment);
    let url = format!("http://localhost:4000/generate_proof/0x{}", hash);
    let response = reqwest::get(&url).await?;
    let json = response.json().await?;
    println!("{:?}", json);
    Ok(json)
}

/// Given a commitment of a resource, looks up the merkle path for this resource.
pub async fn pa_merkle_path(commitment: Digest) -> Result<MerklePath, EvmError> {
    let merkle_path_response = merkle_path_from_indexer(commitment)
        .map_err(|_| IndexerError)
        .await?;

    let x: Result<Vec<(Digest, bool)>, EvmError> = merkle_path_response
        .frontiers
        .into_iter()
        .map(|frontier| {
            let bytes: [u8; 32] = frontier
                .neighbour
                .as_slice()
                .try_into()
                .map_err(|_| IndexerError)?;
            println!("{:?}", bytes);
            let sibling_digest = Digest::from(bytes);
            Ok((sibling_digest, !frontier.is_left))
        })
        .collect();

    let merkle_path_vec = x?;

    Ok(MerklePath::from_path(merkle_path_vec.as_slice()))
}
