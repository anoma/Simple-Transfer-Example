use crate::{resource::construct_persistent_resource, utils::authorize_the_action};
use arm::{
    action_tree::MerkleTree,
    authorization::{AuthorizationSigningKey, AuthorizationVerifyingKey},
    encryption::{random_keypair, Ciphertext},
    merkle_path::MerklePath,
    nullifier_key::NullifierKey, transaction::Transaction,
};
use eth::submit;
use runtime::Builder;
use tokio::runtime;

mod resource;
mod utils;
mod transfer;
mod mint;
mod burn;
#[cfg(test)]
mod end_to_end_test;
mod eth;

fn simple_mint_test() -> Transaction {
    use crate::resource::{construct_ephemeral_resource, construct_persistent_resource};
    use arm::{
        authorization::{AuthorizationSigningKey, AuthorizationVerifyingKey},
        compliance::INITIAL_ROOT,
        encryption::random_keypair,
        evm::CallType,
        nullifier_key::NullifierKey,
    };

    let forwarder_addr = vec![1u8; 20];
    let token_addr = vec![2u8; 20];
    let user_addr = vec![3u8; 20];
    let quantity = 100;

    // Construct the consumed resource
    let (consumed_nf_key, consumed_nf_cm) = NullifierKey::random_pair();
    let consumed_resource = construct_ephemeral_resource(
        &forwarder_addr,
        &token_addr,
        quantity,
        vec![4u8; 32], // nonce
        consumed_nf_cm,
        vec![5u8; 32], // rand_seed
        CallType::Wrap,
        &user_addr,
    );
    let consumed_nf = consumed_resource.nullifier(&consumed_nf_key).unwrap();
    // Fetch the latest cm tree root from the chain
    let latest_cm_tree_root = INITIAL_ROOT.as_words().to_vec();

    // Generate the created resource
    let (_created_nf_key, created_nf_cm) = NullifierKey::random_pair();
    let created_auth_sk = AuthorizationSigningKey::new();
    let created_auth_pk = AuthorizationVerifyingKey::from_signing_key(&created_auth_sk);
    let (_created_discovery_sk, created_discovery_pk) = random_keypair();
    let (_created_encryption_sk, created_encryption_pk) = random_keypair();
    let created_resource = construct_persistent_resource(
        &forwarder_addr,
        &token_addr,
        quantity,
        consumed_nf.as_bytes().to_vec(), // nonce
        created_nf_cm,
        vec![6u8; 32], // rand_seed
        &created_auth_pk,
    );

    // Fetch the permit signature somewhere
    let permit_nonce = vec![7u8; 32];
    let permit_deadline = vec![8u8; 32];
    let permit_sig = vec![9u8; 65];

    // Construct the mint transaction
    let tx_start_timer = std::time::Instant::now();
    let tx = mint::construct_mint_tx(
        consumed_resource,
        latest_cm_tree_root,
        consumed_nf_key,
        forwarder_addr,
        token_addr,
        user_addr,
        permit_nonce,
        permit_deadline,
        permit_sig,
        created_resource,
        created_discovery_pk,
        created_encryption_pk,
    );
    println!("Tx build duration time: {:?}", tx_start_timer.elapsed());

    // Verify the transaction
    if tx.clone().verify() {
        println!("Transaction verified");
    } else {
        println!("Transaction not verified");
    }
    tx
}

fn create_test_transfer() -> Transaction {
    let forwarder_addr = vec![1u8; 20];
    let token_addr = vec![2u8; 20];
    let quantity = 100;
    // Obtain the consumed resource data
    let consumed_auth_sk = AuthorizationSigningKey::new();
    let consumed_auth_pk = AuthorizationVerifyingKey::from_signing_key(&consumed_auth_sk);
    let (consumed_nf_key, consumed_nf_cm) = NullifierKey::random_pair();
    let (consumed_discovery_sk, consumed_discovery_pk) = random_keypair();
    let (consumed_encryption_sk, consumed_encryption_pk) = random_keypair();
    let consumed_resource = construct_persistent_resource(
        &forwarder_addr, // forwarder_addr
        &token_addr,     // token_addr
        quantity,
        vec![4u8; 32], // nonce
        consumed_nf_cm,
        vec![5u8; 32], // rand_seed
        &consumed_auth_pk,
    );
    let consumed_nf = consumed_resource.nullifier(&consumed_nf_key).unwrap();

    // Create the created resource data
    let created_auth_sk = AuthorizationSigningKey::new();
    let created_auth_pk = AuthorizationVerifyingKey::from_signing_key(&created_auth_sk);
    let (_created_nf_key, created_nf_cm) = NullifierKey::random_pair();
    let (_created_discovery_sk, created_discovery_pk) = random_keypair();
    let (_created_encryption_sk, created_encryption_pk) = random_keypair();
    let created_resource = construct_persistent_resource(
        &forwarder_addr, // forwarder_addr
        &token_addr,     // token_addr
        quantity,
        consumed_nf.as_bytes().to_vec(), // nonce
        created_nf_cm,
        vec![7u8; 32], // rand_seed
        &created_auth_pk,
    );
    let created_cm = created_resource.commitment();

    // Get the authorization signature, it can be from external signing(e.g. wallet)
    let action_tree = MerkleTree::new(vec![consumed_nf, created_cm]);
    let auth_sig = authorize_the_action(&consumed_auth_sk, &action_tree);

    // Construct the transfer transaction
    let merkle_path = MerklePath::default(); // mock a path

    let tx_start_timer = std::time::Instant::now();
    let tx = transfer::construct_transfer_tx(
        consumed_resource.clone(),
        merkle_path.clone(),
        consumed_nf_key.clone(),
        consumed_auth_pk,
        auth_sig,
        created_resource.clone(),
        created_discovery_pk,
        created_encryption_pk,
    );
    println!("Tx build duration time: {:?}", tx_start_timer.elapsed());

    // check the discovery ciphertexts
    let discovery_ciphertext = Ciphertext::from_words(
        &tx.actions[0].logic_verifier_inputs[0]
            .app_data
            .discovery_payload[0]
            .blob,
    );
    discovery_ciphertext
        .decrypt(&consumed_discovery_sk)
        .unwrap();

    // check the encryption ciphertexts
    let encryption_ciphertext = Ciphertext::from_words(
        &tx.actions[0].logic_verifier_inputs[0]
            .app_data
            .resource_payload[0]
            .blob,
    );
    let decrypted_resource = encryption_ciphertext
        .decrypt(&consumed_encryption_sk)
        .unwrap();
    assert_eq!(decrypted_resource, consumed_resource.to_bytes());

    // Verify the transaction
    assert!(tx.clone().verify(), "Transaction verification failed");
    tx
}

pub fn submit_transaction(transaction: Transaction) {
    let rt = Builder::new_current_thread().enable_all().build().unwrap();

    let _ = rt.block_on(async { submit(transaction).await });
}

fn main() {
    let tx = simple_mint_test();
    // let tx = create_test_transfer();
    println!("Tx: {:?}", tx);
    // let _ = submit_transaction(tx);
    println!("Yippie");
}