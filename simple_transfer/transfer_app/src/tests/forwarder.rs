use alloy::network::EthereumWallet;
use alloy::primitives::{address, B256};
use alloy::providers::fillers::{
    BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller, WalletFiller,
};
use alloy::providers::layers::AnvilProvider;
use alloy::providers::{ProviderBuilder, RootProvider};
use alloy::{hex, sol};
use alloy::{node_bindings::Anvil, primitives::Address, signers::local::PrivateKeySigner};
use evm_protocol_adapter_bindings::conversion::ProtocolAdapter;
use eyre::WrapErr;

type MyProvider = FillProvider<
    JoinFill<
        JoinFill<
            alloy::providers::Identity,
            JoinFill<GasFiller, JoinFill<BlobGasFiller, JoinFill<NonceFiller, ChainIdFiller>>>,
        >,
        WalletFiller<EthereumWallet>,
    >,
    AnvilProvider<RootProvider>,
>;

sol!(
    #[allow(missing_docs)]
    #[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
    #[sol(rpc)]
    ERC20Forwarder,
    "../../contracts/out/ERC20Forwarder.sol/ERC20Forwarder.json"
);

/// Start a local Anvil that forks Sepolia and returns a provider + signer funded locally.
async fn start_sepolia_fork() -> eyre::Result<(MyProvider, Address)> {
    let fork_url = std::env::var("SEPOLIA_RPC_URL").wrap_err("Missing SEPOLIA_RPC_URL")?;

    let anvil = Anvil::new().chain_id(11155111).fork(&fork_url);
    let anvil_instance = &anvil.spawn();

    // This should give you: endpoint http://127.0.0.1:8545 and the first private key.
    let rpc_url = anvil_instance.endpoint();
    println!("Anvil RPC endpoint: {}", rpc_url);

    let sk = anvil_instance.keys()[0].clone(); // hex or bytes from helper
    let signer = PrivateKeySigner::from(&sk);

    // 2) Build provider and signer
    // Use the local Anvil endpoint to build the provider. Do not try to convert from RpcClient.
    let provider = ProviderBuilder::new().connect_anvil_with_wallet();

    let deployer = signer.address();

    Ok((provider, deployer))
}

#[tokio::test]
async fn sepolia_fork_deploy_and_test() -> eyre::Result<()> {
    let carrier_logic_ref = B256::from(hex!(
        "0x81f8104fe367f5018a4bb0b259531be9ab35d3f1d51dea46c204bee154d5ee9e"
    ));
    let pa_address = address!("0x375920798465eb6b845AC5BF8580d69ce0Bda34a");

    let (provider, deployer) = start_sepolia_fork().await?;

    let pa_instance = ProtocolAdapter::new(pa_address, &provider);

    let fwd_instance =
        ERC20Forwarder::deploy(&provider, pa_address, carrier_logic_ref, deployer).await?;

    assert_ne!(
        fwd_instance.address(),
        &address!("0000000000000000000000000000000000000000")
    );

    println!("Forwarder address: {}", fwd_instance.address());
    println!("Protocol adapter address: {}", pa_instance.address());

    println!("{}", pa_instance.nullifierCount().call().await?);

    // Example: call a view method or set some state, e.g.
    // let some_value = instance.someViewMethod().call().await?;
    // assert_eq!(some_value, expected);

    Ok(())
}
