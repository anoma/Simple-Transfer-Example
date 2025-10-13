//! Backend application for the Anomapay application.
//!
//! The backend serves a JSON api to handle requests.
//! The following api's are available:
//!  - minting
//!  - transferring
//!  - splitting
//!  - burning

mod errors;

mod evm;
mod examples;
mod permit2;
mod requests;
mod tests;
mod user;
mod webserver;

use crate::requests::mint::json_example_mint_request;
use crate::webserver::{
    all_options, burn, default_error, health, is_approved, mint, split, transfer, unprocessable,
    Cors,
};
use alloy::primitives::Address;
use rocket::serde::{Deserialize, Serialize};
use rocket::{catchers, launch, routes};
use std::env;
use std::error::Error;

#[derive(Debug, Deserialize, Serialize)]
struct AnomaPayConfig {
    // Address of the tokens that are being wrapped (e.g., USDC)
    token_address: Address,
    // Address of the permi2 contract (see https://docs.uniswap.org/contracts/v4/deployments)
    permit2_address: Address,
    // default amount to use in mint/transfer
    default_amount: u8,
    // TODO wth is this
    deadline: u32,
    // address of the anoma forwarder contract
    forwarder_address: Address,
    // url of the ethereum rpc
    ethereum_rpc: String,
    // api key for the ethereum rpc
    #[serde(skip_serializing)]
    ethereum_rpc_api_key: String,
    indexer_address: String,
}

/// Reads the environment for required values and sets them into the config.
fn load_config() -> Result<AnomaPayConfig, Box<dyn Error>> {
    let token_address = env::var("TOKEN_ADDRESS").map_err(|_| "TOKEN_ADDRESS not set")?;
    let token_address =
        Address::parse_checksummed(token_address, None).map_err(|_| "TOKEN_ADDRESS invalid")?;

    let permit2_address = env::var("PERMIT2_ADDRESS").map_err(|_| "USER_ADDRESS not set")?;
    let permit2_address =
        Address::parse_checksummed(permit2_address, None).map_err(|_| "PERMIT2_ADDRESS invalid")?;

    let default_amount = env::var("DEFAULT_AMOUNT").map_err(|_| "USER_ADDRESS not set")?;
    let default_amount: u8 = default_amount
        .parse()
        .map_err(|_| "DEFAULT_AMOUNT invalid")?;

    let deadline = env::var("DEADLINE").map_err(|_| "USER_ADDRESS not set")?;
    let deadline: u32 = deadline.parse().map_err(|_| "DEADLINE invalid")?;

    let forwarder_address = env::var("FORWARDER_ADDRESS").map_err(|_| "USER_ADDRESS not set")?;
    let forwarder_address = Address::parse_checksummed(forwarder_address, None)
        .map_err(|_| "FORWARDER_ADDRESS invalid")?;

    let ethereum_rpc = env::var("RPC_URL").map_err(|_| "RPC_URL not set")?;
    let indexer_address = env::var("INDEXER_ADDRESS").map_err(|_| "INDEXER_ADDRESS not set")?;
    let ethereum_rpc_api_key = env::var("API_KEY").map_err(|_| "API_KEY not set")?;

    Ok(AnomaPayConfig {
        token_address,
        permit2_address,
        default_amount,
        deadline,
        forwarder_address,
        ethereum_rpc,
        ethereum_rpc_api_key,
        indexer_address,
    })
}
#[launch]
async fn rocket() -> _ {
    // load the config
    let config: AnomaPayConfig = load_config().unwrap_or_else(|e| {
        eprintln!("Error loading config: {}", e);
        std::process::exit(1);
    });

    // read in cli arguments
    let args: Vec<String> = env::args().collect();

    // --mint-example produces an example json string for minting a transaction
    if args.contains(&"--minting-example".to_string()) {
        let Ok(json_str) = json_example_mint_request(&config).await else {
            println!("failed to create a json string example");
            std::process::exit(0);
        };
        println!("{}", json_str);
        std::process::exit(0);
    }

    rocket::build()
        .manage(config)
        .attach(Cors)
        .mount(
            "/",
            routes![
                health,
                is_approved,
                mint,
                transfer,
                burn,
                split,
                all_options
            ],
        )
        .register("/", catchers![default_error, unprocessable])
}
