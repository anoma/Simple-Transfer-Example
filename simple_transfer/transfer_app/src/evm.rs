use alloy::hex::ToHexExt;
use alloy::primitives::B256;
use arm::merkle_path::MerklePath;
use arm::transaction::Transaction;
use arm::utils::bytes_to_words;
use evm_protocol_adapter_bindings::call::protocol_adapter;
use evm_protocol_adapter_bindings::conversion::ProtocolAdapter;
use evm_protocol_adapter_bindings::conversion::ProtocolAdapter::{
    merkleProofReturn, ProtocolAdapterErrors,
};
use risc0_zkvm::Digest;
use tokio::runtime::Runtime;

async fn pa_submit_transaction(
    transaction: Transaction,
) -> (Option<String>, Option<ProtocolAdapterErrors>) {
    let tx = ProtocolAdapter::Transaction::from(transaction);
    let result = protocol_adapter().execute(tx).send().await;
    match result {
        Ok(transaction_builder) => {
            let tx_hash = transaction_builder.tx_hash().encode_hex();
            println!(
                "submitted transaction https://sepolia.etherscan.io/tx/{}",
                tx_hash
            );
            // wait for 3 confirmations
            // transaction_builder
            //     .watch()
            //     .await
            //     .expect("failed to wait for confirmations");
            tokio::time::sleep(tokio::time::Duration::from_secs(15)).await;
            (Some(tx_hash), None)
        }
        Err(err) => {
            println!("submit error: {:?}", err);
            let decoded_err: Option<ProtocolAdapterErrors> =
                err.as_decoded_interface_error::<ProtocolAdapterErrors>();
            (None, decoded_err)
        }
    }
}

pub fn submit_transaction(transaction: Transaction) -> Option<String> {
    let rt = Runtime::new().unwrap();
    let (success, error) = rt.block_on(pa_submit_transaction(transaction));
    match (success, error) {
        (_, Some(error)) => {
            println!("submit_transaction error: {:?}", error);
            None
        }
        (Some(tx_hash), _) => Some(tx_hash),
        _ => None,
    }
}

// pub async fn pa_latest_root(commitment: Digest) {
//     protocol_adapter()
//         .latestRoot()
//         .call()
//         .await
//         .expect("failed to call latestRoot");
// }

pub async fn pa_merkle_proof(commitment: Digest) -> merkleProofReturn {
    let commitment_bytes = B256::from_slice(commitment.as_bytes());

    protocol_adapter()
        .merkleProof(commitment_bytes)
        .call()
        .await
        .map_err(|e| format!("Failed to call merkleProof: {}", e))
        .expect("failed to call merkleProof")
}

pub async fn pa_merkle_path(commitment: Digest) -> MerklePath {
    let merkle_proof: merkleProofReturn = pa_merkle_proof(commitment).await;

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

    MerklePath::from_path(auth_path_vec.as_slice())
}

pub fn get_merkle_path(commitment: Digest) -> MerklePath {
    let rt = tokio::runtime::Handle::current();
    rt.block_on(pa_merkle_path(commitment))
}
