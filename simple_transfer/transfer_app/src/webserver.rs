use crate::evm::approve::is_address_approved;
use crate::evm::evm_calls::pa_submit_and_await;
use crate::examples::shared::parse_address;
use crate::requests::approve::ApproveRequest;
use crate::requests::burn::{burn_from_request, BurnRequest};
use crate::requests::mint::{mint_from_request, CreateRequest};
use crate::requests::transfer::{transfer_from_request, TransferRequest};
use crate::requests::Expand;
use crate::AnomaPayConfig;
use rocket::serde::json::{json, to_value, Json};
use rocket::{get, post, State};
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
    let Ok(tx_hash) = pa_submit_and_await(transaction, 0).await else {
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
    let Ok(tx_hash) = pa_submit_and_await(transaction, 0).await else {
        return Json(json!({"error": "failed to submit transfer transaction"}));
    };

    // create the response
    Json(json!({"transaction_hash": tx_hash, "resource": created_resource.simplify()}))
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
    let Ok(tx_hash) = pa_submit_and_await(transaction, 0).await else {
        return Json(json!({"error": "failed to submit burn transaction"}));
    };

    // create the response
    Json(json!({"transaction_hash": tx_hash}))
}
