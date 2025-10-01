mod evm;
mod examples;
mod requests;
mod tests;
mod user;

use crate::evm::submit_transaction;
use crate::examples::mint::{create_mint_json_request, mint_from_json_request};
use crate::examples::shared::read_private_key;
use crate::examples::transfer::{create_transfer_json_request, transfer_from_json_request};
use crate::requests::mint::parse_json_request;
use crate::requests::mint::CreateRequest;
use crate::requests::transfer::{parse_json_transfer_request, TransferRequest};
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

fn mint(alice: Keychain, _bob: Keychain) -> Resource {
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
    let submitted = submit_transaction(transaction.clone());
    match submitted {
        None => {
            println!("failed to submit transaction");
            exit(1)
        }
        Some(_tx_hash) => {
            println!("Transaction submitted successfully!");
        }
    }

    minted_resource
}

fn transfer(alice: Keychain, bob: Keychain, transferred_resource: Resource) {
    let transfer_example: TransferRequest =
        create_transfer_json_request(bob, alice, transferred_resource);
    let json_string = serde_json::to_string(&transfer_example).unwrap();

    // given the json from above, parse it into a request and create the transaction.
    // decode the json string into a request
    let transfer_request =
        parse_json_transfer_request(json_string.as_str()).expect("Failed to parse TransferRequest");

    // Create the transfer transaction
    let transaction: Transaction = transfer_from_json_request(transfer_request);

    // Submit the mint transaction to the protocol adapter
    let submitted = submit_transaction(transaction);
    match submitted {
        None => {
            println!("Failed to submit transaction");
            exit(1)
        }
        Some(_tx_hash) => {
            println!("Transaction submitted successfully!");
        }
    }
}
fn main() {
    // create keychains.
    // note: these are based on hardcoded values to be consistent between runs.
    let alice_private_key = read_private_key();
    let alice: Keychain = Keychain::alice(Some(alice_private_key.clone()));
    let bob: Keychain = Keychain::bob(None);

    ////////////////////////////////////////////////////////////////////////////
    // Create a mint transaction

    let minted_resource: Resource = mint(alice.clone(), bob.clone());

    ////////////////////////////////////////////////////////////////////////////
    // Create a transfer transaction

    transfer(alice, bob, minted_resource);
}
