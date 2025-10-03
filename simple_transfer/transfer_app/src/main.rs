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

use crate::examples::mint::mint_from_json_request;
use crate::examples::shared::read_private_key;
use crate::examples::transfer::transfer_from_json_request;
use crate::requests::mint::CreateRequest;
use crate::requests::resource::resource_to_request_resource;
use crate::requests::transfer::TransferRequest;
use crate::user::Keychain;
use crate::{evm::submit_transaction, examples::mint::create_mint_json_string};
use alloy::primitives::{address, Address};
use arm::resource::Resource;
use rocket::fairing::{Fairing, Info, Kind};
use rocket::http::Header;
use rocket::{
    catch, catchers, launch, options, post, routes, serde::json::Json, Request, Response,
};
use serde_json::{json, Value};
use std::env;
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

/// Catches all OPTION requests in order to get the CORS related Fairing triggered.
#[options("/<_..>")]
fn all_options() {
    /* Intentionally left empty */
}

pub struct Cors;
#[rocket::async_trait]
impl Fairing for Cors {
    fn info(&self) -> Info {
        Info {
            name: "Cross-Origin-Resource-Sharing Fairing",
            kind: Kind::Response,
        }
    }

    async fn on_response<'r>(&self, _request: &'r Request<'_>, response: &mut Response<'r>) {
        response.set_header(Header::new("Access-Control-Allow-Origin", "*"));
        response.set_header(Header::new(
            "Access-Control-Allow-Methods",
            "POST, PATCH, PUT, DELETE, HEAD, OPTIONS, GET",
        ));
        response.set_header(Header::new("Access-Control-Allow-Headers", "*"));
        response.set_header(Header::new("Access-Control-Allow-Credentials", "true"));
    }
}

#[launch]
fn rocket() -> _ {
    let args: Vec<String> = env::args().collect();

    if args.contains(&"--mint-example".to_string()) {
        let private_key = read_private_key();
        let alice = Keychain::alice(Some(private_key));

        println!("{}", create_mint_json_string(alice));
        std::process::exit(0);
    }

    rocket::build()
        .attach(Cors)
        .mount("/", routes![mint, transfer, all_options])
        .register("/", catchers![default_error, unprocessable])
}
