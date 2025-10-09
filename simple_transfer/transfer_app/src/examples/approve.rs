use alloy::sol;
use std::error::Error;

use crate::AnomaPayConfig;
use alloy::primitives::Address;
use alloy::providers::ProviderBuilder;

// solidity interface code taken from
// https://sepolia.etherscan.io/address/0xda317c1d3e835dd5f1be459006471acaa1289068#code
sol! {
#[sol(rpc)]
interface IERC20 {
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address recipient, uint256 amount) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
}}

/// Checks if a given user address has approval for permit2
pub async fn is_address_approved(
    token_holder: Address,
    config: &AnomaPayConfig,
) -> Result<bool, Box<dyn Error>> {
    // rpc url of sepolia to talk to the contract
    let rpc_url_with_key = format!("{}/{}", config.ethereum_rpc, config.ethereum_rpc_api_key);

    // call the contract to check if the user approved
    let url = rpc_url_with_key.parse()?;
    let provider = ProviderBuilder::new().connect_http(url);

    // create a contract instance
    let contract = IERC20::new(config.token_address, provider.clone());

    let res = contract
        .allowance(token_holder, config.permit2_address)
        .call()
        .await?;

    println!("Approved: {:?}{}", res, res != 0);

    Ok(res != 0)
}
