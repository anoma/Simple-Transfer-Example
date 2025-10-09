#![cfg(test)]

use crate::examples::shared::{read_address, read_private_key};
use crate::user::Keychain;

/// Helper function to create the keychain for alice.
/// Alice has a private key and can create minting transactions.
/// The address and private key for alice are read from the environment to test actual submission
/// to sepolia.
pub fn alice_keychain() -> Keychain {
    let private_key = read_private_key();
    let address = read_address();
    let keychain = Keychain::alice(address, Some(private_key));
    keychain
}

/// Helper function to geneate the keychain for bob.
/// Bob has no private key and is always the recipient of resources.
///
/// bob also has a fixed address, as opposed to alice.
/// Alice her address is read from the environment as it is used to submit tranasctions to sepolia.
pub fn bob_keychain() -> Keychain {
    Keychain::bob(None)
}

// /// Helper function to create a transfer transaction.
// pub fn create_transfer_tx(sender: Keychain, receiver: Keychain) -> (Resource, Transaction) {
//     // First a mint needs to happen to obtain a resource to transfer.
//     let (resource, transaction) = create_mint_tx(sender.clone());
//     create_transfer_transaction(sender, receiver, resource).unwrap()
// }
