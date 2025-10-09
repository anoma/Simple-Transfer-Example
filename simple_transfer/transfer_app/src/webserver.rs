use crate::evm::approve::is_address_approved;
use crate::evm::evm::pa_submit_and_await;
use crate::examples::shared::parse_address;
use crate::requests::approve::ApproveRequest;
use crate::requests::mint::{mint_from_request, CreateRequest};
use crate::requests::Expand;
use crate::AnomaPayConfig;
use alloy::primitives::Address;
use rocket::serde::json::{json, to_value, Json};
use rocket::{get, launch, post, routes, Build, Rocket, State};
use serde_json::Value;
use std::error::Error;
use std::str::FromStr;

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
#[post("/api/minting", data = "<payload>")]
async fn mint(payload: Json<CreateRequest>, config: &State<AnomaPayConfig>) -> Json<Value> {
    let config: &AnomaPayConfig = config.inner();
    let create_request = payload.into_inner();

    // create the transaction
    let Ok((created_resource, transaction)) = mint_from_request(create_request, config) else {
        return Json(json!({"error": "failed to create transaction"}));
    };

    // submit the transaction
    let Ok(tx_hash) = pa_submit_and_await(transaction).await else {
        return Json(json!({"error": "failed to submit transaction"}));
    };

    // create the response
    Json(json!({"transaction_hash": tx_hash, "resource": created_resource.simplify()}))
}
