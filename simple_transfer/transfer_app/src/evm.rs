use alloy::hex::ToHexExt;
use alloy::primitives::TxHash;
use alloy::providers::Provider;
use arm::transaction::Transaction;
use evm_protocol_adapter_bindings::call::protocol_adapter;
use evm_protocol_adapter_bindings::conversion::ProtocolAdapter;
use evm_protocol_adapter_bindings::conversion::ProtocolAdapter::ProtocolAdapterErrors;
use tokio::runtime::Runtime;

async fn submit(transaction: Transaction) -> (Option<String>, Option<ProtocolAdapterErrors>) {
    let tx = ProtocolAdapter::Transaction::from(transaction);
    let result = protocol_adapter().execute(tx).send().await;

    match result {
        Ok(transaction_builder) => {
            let tx_hash = transaction_builder.tx_hash().encode_hex();
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
    let (success, error) = rt.block_on(submit(transaction));
    match (success, error) {
        (_, Some(error)) => {
            println!("submit_transaction error: {:?}", error);
            None
        }
        (Some(tx_hash), _) => Some(tx_hash),
        _ => None,
    }
}

pub async fn wait_for_transaction_confirmations(tx_hash: String) {
    let tx: TxHash = tx_hash.parse().expect("failed to parse transaction hash");

    protocol_adapter()
        .provider()
        .get_transaction_receipt(tx)
        .await
        .expect("failed to get transaction receipt");
}

pub fn wait_for_transaction(tx_hash: String) {
    let rt = Runtime::new().unwrap();
    rt.block_on(wait_for_transaction_confirmations(tx_hash));
}
