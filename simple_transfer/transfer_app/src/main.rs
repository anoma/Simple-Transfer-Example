mod errors;
mod evm;
mod examples;
mod permit2;
mod requests;
mod tests;
mod user;
mod webserver;

use crate::evm::evm_calls::pa_merkle_path;
use crate::requests::mint::json_example_mint_request;
use crate::webserver::{
    all_options, burn, default_error, health, is_approved, mint, split, transfer, unprocessable,
    Cors,
};
use alloy::primitives::Address;
use risc0_zkvm::Digest;
use rocket::serde::{Deserialize, Serialize};
use rocket::{catchers, launch, routes};
use std::env;
use std::error::Error;

/// Configuration parameters for the Anomapay backend.
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

    let str = "0x40fb856e5f938fbddbba00c01c16ecd90e61405235986970708c4dd01e092e26";
    let bytes = str.strip_prefix("0x").unwrap_or(str);
    let bz = hex::decode(bytes).unwrap();
    let arr = bz.try_into().unwrap();
    let digest = Digest::from_bytes(arr);
    println!("{:?}", digest);
    let res = pa_merkle_path(digest).await;
    println!("{:?}", res);
    std::process::exit(0);

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
    //
    // // create keychains for all users
    // let private_key = read_private_key();
    // let address = read_address();
    // let alice = Keychain::alice(address, Some(private_key));
    //
    // let _bob = Keychain::bob(None);
    //
    // ////////////////////////////////////////////////////////////////////////////
    // // Mint
    // let (resource, transaction) = create_mint_transaction(alice.clone(), 2, &config)
    //     .await
    //     .unwrap_or_else(|e| {
    //         println!("Error creating mint transaction: {:?}", e);
    //         std::process::exit(1);
    //     });
    // println!("created mint transaction");
    // pa_submit_and_await(transaction).await.unwrap_or_else(|_| {
    //     println!("failed to submit the mint transaction");
    //     std::process::exit(1);
    // });

    ////////////////////////////////////////////////////////////////////////////
    // Transfer

    // let (_resource, transaction) = create_transfer_transaction(alice.clone(), bob.clone(), resource.clone())
    //     .await
    //     .unwrap_or_else(|e| {
    //         println!("Error creating transfer transaction: {:?}", e);
    //         std::process::exit(1);
    //     });
    //
    // pa_submit_and_await(transaction).await.unwrap_or_else(|_| {
    //     println!("failed to submit the transfer transaction");
    //     std::process::exit(1);
    // });

    ////////////////////////////////////////////////////////////////////////////
    // Split

    // let (_resource, _remainder, transaction) =
    //     create_split_transaction(alice.clone(), bob.clone(), resource.clone(), 1, &config)
    //         .await
    //         .unwrap_or_else(|e| {
    //             println!("Error creating split transaction: {:?}", e);
    //             std::process::exit(1);
    //         });
    //
    // pa_submit_and_await(transaction).await.unwrap_or_else(|_| {
    //     println!("failed to submit the split transaction");
    //     std::process::exit(1);
    // });

    ////////////////////////////////////////////////////////////////////////////
    // Burn

    // let (_resource, transaction) =
    //     create_burn_transaction(alice.clone(), resource.clone(), &config)
    //         .await
    //         .unwrap_or_else(|e| {
    //             println!("Error creating burn transaction: {:?}", e);
    //             std::process::exit(1);
    //         });
    //
    // pa_submit_and_await(transaction).await.unwrap_or_else(|_| {
    //     println!("failed to submit the burn transaction");
    //     std::process::exit(1);
    // });
}
