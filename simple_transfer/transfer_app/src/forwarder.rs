use alloy::sol;

sol!(
    #[allow(missing_docs)]
    #[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
    #[sol(rpc)]
    ERC20Forwarder,
    "../../contracts/out/ERC20Forwarder.sol/ERC20Forwarder.json"
);
