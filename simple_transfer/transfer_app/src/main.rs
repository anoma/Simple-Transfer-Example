mod errors;
mod evm;
mod examples;
mod requests;
mod tests;
mod user;
mod webserver;
use crate::requests::mint::json_example_mint_request;
use crate::webserver::{health, is_approved, mint, transfer};
use alloy::primitives::Address;
use rocket::serde::{Deserialize, Serialize};
use rocket::{launch, routes};
use std::env;
use std::error::Error;
// #[post("/api/minting", data = "<payload>")]
// async fn mint(payload: Json<CreateRequest>) -> Json<Value> {
//     let create_request = payload.into_inner();
//
//
//     let res = spawn_blocking(move || {
//         let (resource, transaction) = mint_from_json_request(create_request);
//         let submitted: Option<String> = submit_transaction(transaction.clone());
//         let response: Option<(String, Resource)> = match submitted {
//             None => {
//                 println!("failed to submit transaction");
//                 None
//             }
//             Some(tx_hash) => Some((tx_hash, resource)),
//         };
//         response
//     })
//     .await;
//
//     match res {
//         Ok(result) => match result {
//             Some((tx_hash, resource)) => {
//                 let json_resource = compact_resource(resource);
//
//                 Json(json!({"transaction_hash": tx_hash, "resource": json_resource}))
//             }
//             None => Json(json!({"error": "failed to submit transaction"})),
//         },
//         Err(_) => Json(json!({"error": "failed to submit transaction"})),
//     }
// }
//
// #[post("/api/transfer", data = "<payload>")]
// async fn transfer(payload: Json<TransferRequest>) -> Json<Value> {
//     let transfer_request = payload.into_inner();
//
//     let res = spawn_blocking(move || {
//         let transaction = transfer_from_json_request(transfer_request);
//         let submitted: Option<String> = submit_transaction(transaction.clone());
//         let response: Option<String> = match submitted {
//             None => {
//                 println!("failed to submit transaction");
//                 None
//             }
//             Some(tx_hash) => Some(tx_hash),
//         };
//         response
//     })
//     .await;
//
//     match res {
//         Ok(result) => match result {
//             Some(tx_hash) => Json(json!({"transaction_hash": tx_hash})),
//             None => Json(json!({"error": "failed to submit transaction"})),
//         },
//         Err(_) => Json(json!({"error": "failed to submit transaction"})),
//     }
// }

// #[post("/api/split", data = "<payload>")]
// async fn split(payload: Json<SplitRequest>) -> Json<Value> {
//     let split_request = payload.into_inner();
//
//     let res = spawn_blocking(move || {
//         let transaction = split_from_json_request(split_request);
//         let submitted: Option<String> = submit_transaction(transaction.clone());
//         let response: Option<String> = match submitted {
//             None => {
//                 println!("failed to submit transaction");
//                 None
//             }
//             Some(tx_hash) => Some(tx_hash),
//         };
//         response
//     })
//     .await;
//
//     match res {
//         Ok(result) => match result {
//             Some(tx_hash) => Json(json!({"transaction_hash": tx_hash})),
//             None => Json(json!({"error": "failed to submit transaction"})),
//         },
//         Err(_) => Json(json!({"error": "failed to submit transaction"})),
//     }
// }
//
// #[catch(422)]
// fn unprocessable(_req: &Request) -> Json<Value> {
//     Json(json!({"message": "error processing request. is the json valid?"}))
// }
//
// #[catch(default)]
// fn default_error(_req: &Request) -> Json<Value> {
//     Json(json!({"message": "error processing request"}))
// }
//
// /// Catches all OPTION requests in order to get the CORS related Fairing triggered.
// #[options("/<_..>")]
// fn all_options() {
//     /* Intentionally left empty */
// }
//
// pub struct Cors;
// #[rocket::async_trait]
// impl Fairing for Cors {
//     fn info(&self) -> Info {
//         Info {
//             name: "Cross-Origin-Resource-Sharing Fairing",
//             kind: Kind::Response,
//         }
//     }
//
//     async fn on_response<'r>(&self, _request: &'r Request<'_>, response: &mut Response<'r>) {
//         response.set_header(Header::new("Access-Control-Allow-Origin", "*"));
//         response.set_header(Header::new(
//             "Access-Control-Allow-Methods",
//             "POST, PATCH, PUT, DELETE, HEAD, OPTIONS, GET",
//         ));
//         response.set_header(Header::new("Access-Control-Allow-Headers", "*"));
//         response.set_header(Header::new("Access-Control-Allow-Credentials", "true"));
//     }
// }

// TODO
/*
#[launch]
fn rocket() -> _ {
    let args: Vec<String> = env::args().collect();

    if args.contains(&"--minting-example".to_string()) {
        let private_key = read_private_key();
        let address = read_address();
        let alice = Keychain::alice(address, Some(private_key));

        println!("{}", create_mint_json_string(alice));
        std::process::exit(0);
    }

    rocket::build()
        .attach(Cors)
        .mount("/", routes![minting, transfer, all_options])
        .register("/", catchers![default_error, unprocessable])
}
*/

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
    let ethereum_rpc_api_key = env::var("API_KEY").map_err(|_| "API_KEY not set")?;

    Ok(AnomaPayConfig {
        token_address,
        permit2_address,
        default_amount,
        deadline,
        forwarder_address,
        ethereum_rpc,
        ethereum_rpc_api_key,
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
        .mount("/", routes![health, is_approved, mint, transfer])
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
