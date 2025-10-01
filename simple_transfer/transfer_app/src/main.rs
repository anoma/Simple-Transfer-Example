mod evm;
mod examples;
mod requests;
mod tests;
mod user;

use crate::evm::{submit_transaction, wait_for_transaction};
use crate::examples::mint::{create_mint_json_request, mint_from_json_request};
use crate::examples::shared::read_private_key;
use crate::requests::mint::parse_json_request;
use crate::requests::mint::CreateRequest;
use crate::user::Keychain;
use alloy::primitives::{address, Address};
use arm::resource::Resource;
use arm::transaction::Transaction;
use serde_with::base64::Base64;
use std::process::exit;

// constants
pub const ERC20: Address = address!("0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238");
pub const AMOUNT: u8 = 10;
pub const DEADLINE: u32 = 1893456000;
pub const FORWARDER_ADDRESS: Address = address!("0x09711e24A3748591624d2E575BB1bD87db87EFC8");
// pub const NONCE: u32 = 123;

fn main() {
    // create alice keychain
    let alice_private_key = read_private_key();
    let alice = Keychain::new(
        "0x26aBD8C363f6Aa7FC4db989Ba4F34E7Bd5573A16",
        Some(alice_private_key),
    );

    ////////////////////////////////////////////////////////////////////////////
    // Create a mint transaction

    // Create all the values that a request for minting would require and create
    // a json string for it.
    let request_example: CreateRequest = create_mint_json_request(alice);
    let json_string = serde_json::to_string(&request_example).unwrap();

    // given the json from above, parse it into a request and create the transaction.
    // decode the json string into a request
    let create_request =
        parse_json_request(json_string.as_str()).expect("Failed to parse CreateRequest");

    // Create the minting transaction
    let (minted_resource, transaction): (Resource, Transaction) =
        mint_from_json_request(create_request);

    // Submit the mint transaction to the protocol adapter
    let submitted = submit_transaction(transaction);
    match submitted {
        None => {
            println!("failed to submit transaction");
            exit(1)
        }
        Some(tx_hash) => {
            println!("waiting for transaction {} to be confirmed", tx_hash);
            wait_for_transaction(tx_hash);
        }
    }
    println!("Transaction submitted successfully!");
}
