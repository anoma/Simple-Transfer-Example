use crate::evm::approve::is_address_approved;
use crate::evm::evm_calls::pa_submit_transaction;
use crate::examples::shared::parse_address;
use crate::requests::approve::ApproveRequest;
use crate::requests::burn::{burn_from_request, BurnRequest};
use crate::requests::mint::{mint_from_request, CreateRequest};
use crate::requests::split::{split_from_request, SplitRequest};
use crate::requests::transfer::{transfer_from_request, TransferRequest};
use crate::requests::Expand;
use crate::AnomaPayConfig;

use rocket::fairing::{Fairing, Info, Kind};
use rocket::http::Header;
use rocket::serde::json::{json, to_value, Json};
use rocket::{catch, get, options, post, Request, Response, State};
use serde_json::Value;

/// Return the health status
#[get("/health")]
pub fn health(config: &State<AnomaPayConfig>) -> Json<Value> {
    let config: &AnomaPayConfig = config.inner();
    let Ok(config_json) = to_value(config) else {
        return Json(json!({"error": "failed to serialize configuration"}));
    };
    Json(json!({
        "ok": config_json
    }))
}

/// Returns whether the given address is approved for transfers.
#[post("/api/is-approved", data = "<payload>")]
pub async fn is_approved(
    payload: Json<ApproveRequest>,
    config: &State<AnomaPayConfig>,
) -> Json<Value> {
    let config: &AnomaPayConfig = config.inner();

    let approve_request = payload.into_inner();
    let Some(address) = parse_address(approve_request.user_addr) else {
        return Json(json!({"error": "failed to submit transaction"}));
    };

    match is_address_approved(address, config).await {
        Ok(is_approved) => Json(json!({"success": is_approved})),
        Err(_) => Json(json!({"error": "failed to check approval"})),
    }
}

/// Handles a request from the user to mint.
#[post("/api/mint", data = "<payload>")]
pub async fn mint(payload: Json<CreateRequest>, config: &State<AnomaPayConfig>) -> Json<Value> {
    let config: &AnomaPayConfig = config.inner();
    let request = payload.into_inner();

    // create the transaction
    let Ok((created_resource, transaction)) = mint_from_request(request, config) else {
        return Json(json!({"error": "failed to create mint transaction"}));
    };

    // submit the transaction
    let Ok(tx_hash) = pa_submit_transaction(transaction).await else {
        return Json(json!({"error": "failed to submit mint transaction"}));
    };

    // create the response
    Json(json!({"transaction_hash": tx_hash, "resource": created_resource.simplify()}))
}

/// Handles a request from the user to mint.
#[post("/api/transfer", data = "<payload>")]
pub async fn transfer(payload: Json<TransferRequest>) -> Json<Value> {
    let request = payload.into_inner();

    // create the transaction
    let Ok((created_resource, transaction)) = transfer_from_request(request).await else {
        return Json(json!({"error": "failed to create transfer transaction"}));
    };

    // submit the transaction
    let Ok(receipt) = pa_submit_transaction(transaction).await else {
        return Json(json!({"error": "failed to submit transfer transaction"}));
    };

    // create the response
    Json(json!({"receipt": receipt, "resource": created_resource.simplify()}))
}

/// Handles a request from the user to burn a resource.
#[post("/api/burn", data = "<payload>")]
pub async fn burn(payload: Json<BurnRequest>, config: &State<AnomaPayConfig>) -> Json<Value> {
    let config: &AnomaPayConfig = config.inner();

    let request = payload.into_inner();

    // create the transaction
    let Ok(transaction) = burn_from_request(request, config).await else {
        return Json(json!({"error": "failed to create burn transaction"}));
    };

    // submit the transaction
    let Ok(receipt) = pa_submit_transaction(transaction).await else {
        return Json(json!({"error": "failed to submit burn transaction"}));
    };

    // create the response
    Json(json!({"receipt": receipt}))
}

/// Handles a request from the user to split a resource.
#[post("/api/split", data = "<payload>")]
pub async fn split(payload: Json<SplitRequest>) -> Json<Value> {
    let request = payload.into_inner();

    // create the transaction
    let Ok(transaction) = split_from_request(request).await else {
        return Json(json!({"error": "failed to create split transaction"}));
    };

    // submit the transaction
    let Ok(receipt) = pa_submit_transaction(transaction).await else {
        return Json(json!({"error": "failed to submit split transaction"}));
    };

    // create the response
    Json(json!({"receipt": receipt}))
}

#[catch(422)]
pub fn unprocessable(_req: &Request) -> Json<Value> {
    Json(json!({"message": "error processing request. is the json valid?"}))
}

#[catch(default)]
pub fn default_error(_req: &Request) -> Json<Value> {
    Json(json!({"message": "error processing request"}))
}

/// Catches all OPTION requests in order to get the CORS related Fairing triggered.
#[options("/<_..>")]
pub fn all_options() {
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
