mod evm;
mod examples;
mod requests;
mod tests;
mod user;

// constants
pub const ERC20: Address = address!("0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238");
pub const AMOUNT: u8 = 10;
pub const DEADLINE: u32 = 1893456000;
pub const FORWARDER_ADDRESS: Address = address!("0x09711e24A3748591624d2E575BB1bD87db87EFC8");

use crate::evm::submit_transaction;
use crate::examples::mint::mint_from_json_request;
use crate::examples::transfer::transfer_from_json_request;
use crate::requests::mint::CreateRequest;
use crate::requests::resource::resource_to_request_resource;
use crate::requests::transfer::TransferRequest;
use alloy::primitives::{address, Address};
use arm::resource::Resource;
use rocket::{catch, catchers, launch, post, routes, serde::json::Json, Request};
use serde_json::{json, Value};
use tokio::task::spawn_blocking;

#[post("/api/mint", data = "<payload>")]
async fn mint(payload: Json<CreateRequest>) -> Json<Value> {
    let create_request = payload.into_inner();

    let res = spawn_blocking(move || {
        let (resource, transaction) = mint_from_json_request(create_request);
        let submitted: Option<String> = submit_transaction(transaction.clone());
        let response: Option<(String, Resource)> = match submitted {
            None => {
                println!("failed to submit transaction");
                None
            }
            Some(tx_hash) => Some((tx_hash, resource)),
        };
        response
    })
    .await;

    match res {
        Ok(result) => match result {
            Some((tx_hash, resource)) => {
                let json_resource = resource_to_request_resource(resource);

                Json(json!({"transaction_hash": tx_hash, "resource": json_resource}))
            }
            None => Json(json!({"error": "failed to submit transaction"})),
        },
        Err(_) => Json(json!({"error": "failed to submit transaction"})),
    }
}

#[post("/api/transfer", data = "<payload>")]
async fn transfer(payload: Json<TransferRequest>) -> Json<Value> {
    let transfer_request = payload.into_inner();

    let res = spawn_blocking(move || {
        let transaction = transfer_from_json_request(transfer_request);
        let submitted: Option<String> = submit_transaction(transaction.clone());
        let response: Option<String> = match submitted {
            None => {
                println!("failed to submit transaction");
                None
            }
            Some(tx_hash) => Some(tx_hash),
        };
        response
    })
    .await;

    match res {
        Ok(result) => match result {
            Some(tx_hash) => Json(json!({"transaction_hash": tx_hash})),
            None => Json(json!({"error": "failed to submit transaction"})),
        },
        Err(_) => Json(json!({"error": "failed to submit transaction"})),
    }
}

#[catch(422)]
fn unprocessable(_req: &Request) -> Json<Value> {
    Json(json!({"message": "error processing request. is the json valid?"}))
}

#[catch(default)]
fn default_error(_req: &Request) -> Json<Value> {
    Json(json!({"message": "error processing request"}))
}

#[launch]
fn rocket() -> _ {
    rocket::build()
        .mount("/", routes![mint, transfer])
        .register("/", catchers![default_error, unprocessable])
}
