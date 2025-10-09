use rocket::serde::json::{json, Json};
use rocket::{get, launch, routes, Build, Rocket};
use serde_json::Value;

#[get("/health")]
fn health() -> Json<Value> {
    Json(json!({"msg": "hello world"}))
}

#[launch]
pub fn server() -> _ {
    rocket::build().mount("/", routes![health])
}
