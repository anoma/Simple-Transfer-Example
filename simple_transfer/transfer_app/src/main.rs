use crate::{resource::{construct_ephemeral_resource, construct_persistent_resource}, utils::authorize_the_action};
use arm::{
    action_tree::MerkleTree,
    authorization::{AuthorizationSigningKey, AuthorizationVerifyingKey},
    compliance::INITIAL_ROOT,
    encryption::{random_keypair, AffinePoint, SecretKey},
    evm::CallType,
    nullifier_key::{NullifierKey, NullifierKeyCommitment},
    resource::Resource,
    transaction::Transaction,
    utils::{words_to_bytes},
};
use alloy::primitives::{Address, B256, U256, address};
use alloy::signers::local::PrivateKeySigner;
use evm_protocol_adapter_bindings::permit2::permit_witness_transfer_from_signature;
use std::env;
use rand::Rng;
use eth::{get_merkle_path, submit};

mod resource;
mod utils;
mod transfer;
mod mint;
mod burn;
mod eth;

#[derive(Clone)]
pub struct SetUp {
    pub signer: PrivateKeySigner,
    pub erc20: Address,
    pub amount: U256,
    pub nonce: U256,
    pub deadline: U256,
    pub spender: Address,
}

pub fn default_values() -> SetUp {
    let mut rng = rand::thread_rng();
    let random_nonce: u32 = rng.gen();
    SetUp {
        signer: env::var("PRIVATE_KEY")
            .expect("Couldn't read PRIVATE_KEY")
            .parse()
            .expect("should parse private key"),
        erc20: address!("0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238"), // USDC
        amount: U256::from(10),
        nonce: U256::from(random_nonce),
        deadline: U256::from(1893456000),
        spender: address!("0x09711e24A3748591624d2E575BB1bD87db87EFC8"), // deployed 2025-09-23
    }
}

#[allow(dead_code)]
#[derive(Clone)]
pub struct KeyChain {
    auth_signing_key: AuthorizationSigningKey,
    nf_key: NullifierKey,
    discovery_sk: SecretKey,
    discovery_pk: AffinePoint,
    encryption_sk: SecretKey,
    encryption_pk: AffinePoint,
    evm_address: Address,
}

impl KeyChain {
    fn auth_verifying_key(&self) -> AuthorizationVerifyingKey {
        AuthorizationVerifyingKey::from_signing_key(&self.auth_signing_key)
    }

    fn nullifier_key_commitment(&self) -> NullifierKeyCommitment {
        self.nf_key.commit()
    }
}

fn create_keychain(evm_address: Address) -> KeyChain {
    let (discovery_sk, discovery_pk) = random_keypair();
    let (encryption_sk, encryption_pk) = random_keypair();

    let auth_signing_key: AuthorizationSigningKey = AuthorizationSigningKey::new();
    let nf_key: NullifierKey = NullifierKey::random_pair().0;

    KeyChain {
        auth_signing_key,
        nf_key,
        discovery_sk,
        discovery_pk,
        encryption_sk,
        encryption_pk,
        evm_address,
    }
}

async fn simple_mint_test(
    data: &SetUp,
    keychain: &KeyChain
) -> (Transaction, Resource) {
    let mut rng = rand::thread_rng();
    let random_nonce: [u8; 32] = rng.gen();
    
    let consumed_resource = construct_ephemeral_resource(
        &data.spender.to_vec(),
        &data.erc20.to_vec(),
        data.amount.try_into().unwrap(),
        random_nonce.to_vec(), // random 32-byte nonce
        keychain.nf_key.commit(),
        vec![7u8; 32], // rand_seed
        CallType::Wrap,
        &data.signer.address().to_vec(),
    );

    // let (consumed_nf_key, consumed_nf_cm) = NullifierKey::random_pair();
    let consumed_nf = consumed_resource.nullifier(&keychain.nf_key).unwrap();

    // Fetch the latest cm tree root from the chain
    let latest_cm_tree_root = INITIAL_ROOT.as_words().to_vec();

    // Generate the created resource
    let created_resource = construct_persistent_resource(
        &data.spender.to_vec(),
        &data.erc20.to_vec(),
        data.amount.try_into().unwrap(),
        consumed_nf.as_bytes().to_vec(), // nonce
        keychain.nf_key.commit(),
        vec![6u8; 32], // rand_seed
        &keychain.auth_verifying_key(),
    );

    let created_cm = created_resource.commitment();
    let action_tree = MerkleTree::new(vec![consumed_nf, created_cm]);

    let permit_sig = permit_witness_transfer_from_signature(
        &data.signer,
        data.erc20,
        data.amount,
        data.nonce,
        data.deadline,
        data.spender,
        B256::from_slice(words_to_bytes(action_tree.root().as_slice())), // Witness
    ).await;

    // Construct the mint transaction (run in blocking thread to avoid runtime conflicts)
    let created_resource_clone = created_resource.clone();
    let keychain_clone = keychain.clone();
    let data_clone = data.clone();
    let tx = tokio::task::spawn_blocking(move || {
        mint::construct_mint_tx(
            consumed_resource,
            latest_cm_tree_root,
            keychain_clone.nf_key.clone(),
            data_clone.spender.to_vec(),
            data_clone.erc20.to_vec(),
            data_clone.signer.address().to_vec(),
            data_clone.nonce.to_be_bytes_vec(),
            data_clone.deadline.to_be_bytes_vec(),
            permit_sig.as_bytes().to_vec(),
            created_resource_clone,
            keychain_clone.discovery_pk,
            keychain_clone.encryption_pk
        )
    }).await.unwrap();

    // Verify the transaction
    if tx.clone().verify() {
        println!("Transaction verified");
    } else {
        println!("Transaction not verified");
    }
    (tx, created_resource)
}

async fn create_test_transfer(
    data: &SetUp,
    keychain_alice: &KeyChain,
    keychain_bob: &KeyChain,
    resource_to_transfer: &Resource,
) -> (Transaction, Resource) {
    let consumed_nf = resource_to_transfer.nullifier(&keychain_alice.nf_key).unwrap();
    
    // Create the created resource data
    let created_resource = construct_persistent_resource(
        &data.spender.to_vec(), // forwarder_addr
        &data.erc20.to_vec(),     // token_addr
        data.amount.try_into().unwrap(),
        consumed_nf.as_bytes().to_vec(), // nonce
        keychain_bob.nullifier_key_commitment(),
        vec![7u8; 32], // rand_seed
        &keychain_bob.auth_verifying_key(),
    );
    let created_cm = created_resource.commitment();

    // Get the authorization signature, it can be from external signing(e.g. wallet)
    let action_tree = MerkleTree::new(vec![consumed_nf, created_cm]);
    let auth_sig = authorize_the_action(&keychain_alice.auth_signing_key, &action_tree);

    // Construct the transfer transaction
    // let is_left = false;
    // let path: &[(Vec<u32>, bool)] = &[(bytes_to_words(empty_leaf_hash().as_slice()), is_left)];
    // let merkle_path = MerklePath::from_path(path);

    // Get Merkle proof for the consumed resource (the one being transferred)
    println!("resource_to_transfer commitment: {:?}\n", resource_to_transfer.commitment());
    let consumed_commitment_b256 = alloy::primitives::B256::from_slice(resource_to_transfer.commitment().as_bytes());
    let merkle_path = get_merkle_path(consumed_commitment_b256).await.unwrap();
    println!("Merkle path for resource_to_transfer: {:?}\n", merkle_path);

    // let merkle_path = merkle_path.map_err(|e| format!("Failed to get merkle path: {}", e))?;
    
    let keychain_alice_clone = keychain_alice.clone();
    let keychain_bob_clone = keychain_bob.clone();
    let resource_to_transfer_clone = resource_to_transfer.clone();
    let created_resource_clone = created_resource.clone();
    let merkle_path_clone = merkle_path.clone();
    let tx = tokio::task::spawn_blocking(move || {
        transfer::construct_transfer_tx(
            resource_to_transfer_clone,
            merkle_path_clone,
            keychain_alice_clone.nf_key.clone(),
            keychain_alice_clone.auth_verifying_key(),
            auth_sig,
            created_resource_clone,
            keychain_bob_clone.discovery_pk,
            keychain_bob_clone.encryption_pk,
        )
    }).await.unwrap();

    // Verify the transaction
    if tx.clone().verify() {
        println!("Transaction verified");
    } else {
        println!("Transaction not verified");
    }
    (tx, created_resource)
}

async fn create_test_burn(
    data: &SetUp,
    keychain: &KeyChain,
    resource_to_burn: &Resource,
) -> Transaction {
    let consumed_nf = resource_to_burn.nullifier(&keychain.nf_key).unwrap();
    
    let created_resource = construct_ephemeral_resource(
        &data.spender.to_vec(), // forwarder_addr
        &data.erc20.to_vec(),     // token_addr
        resource_to_burn.quantity.try_into().unwrap(),
        consumed_nf.as_bytes().to_vec(), // nonce
        keychain.nullifier_key_commitment(),
        vec![8u8; 32], // rand_seed
        CallType::Unwrap,
        &keychain.evm_address.to_vec(),
    );
    let created_cm = created_resource.commitment();

    // Get the authorization signature, it can be from external signing(e.g. wallet)
    let action_tree = MerkleTree::new(vec![consumed_nf, created_cm]);
    let auth_sig = authorize_the_action(&keychain.auth_signing_key, &action_tree);

    // Construct the burn transaction
    // Get Merkle proof for the consumed resource (the one being burned)
    println!("resource_to_burn commitment: {:?}\n", resource_to_burn.commitment());
    let consumed_commitment_b256 = alloy::primitives::B256::from_slice(resource_to_burn.commitment().as_bytes());
    let merkle_path = get_merkle_path(consumed_commitment_b256).await.unwrap();
    println!("Merkle path for resource_to_burn: {:?}\n", merkle_path);

    let keychain_clone = keychain.clone();
    let resource_to_burn_clone = resource_to_burn.clone();
    let created_resource_clone = created_resource.clone();
    let merkle_path_clone = merkle_path.clone();
    let data_clone = data.clone();
    let tx = tokio::task::spawn_blocking(move || {
        burn::construct_burn_tx(
            resource_to_burn_clone,
            merkle_path_clone,
            keychain_clone.nf_key.clone(),
            keychain_clone.auth_verifying_key(),
            auth_sig,
            created_resource_clone,
            data_clone.spender.to_vec(),
            data_clone.erc20.to_vec(),
            keychain_clone.evm_address.to_vec(),
        )
    }).await.unwrap();

    // Verify the transaction
    if tx.clone().verify() {
        println!("Burn transaction verified");
    } else {
        println!("Burn transaction not verified");
    }
    tx
}

pub async fn submit_transaction(transaction: Transaction) -> bool {
    submit(transaction).await
}

#[tokio::main]
async fn main() {

    let data: SetUp = default_values();
    let keychain_alice: KeyChain = create_keychain(address!("0x26aBD8C363f6Aa7FC4db989Ba4F34E7Bd5573A16"));
    let keychain_bob: KeyChain = create_keychain(address!("0x44B73CbC3C2E902cD0768854c2ff914DD44a325F"));

    let (mint_tx, minted_resource) = simple_mint_test(&data, &keychain_alice).await;
    println!("Mint tx: {:?}\n", mint_tx);
    println!("Minted resource: {:?}\n", minted_resource);
    
    let mint_success = submit_transaction(mint_tx).await;
    
    // Wait for the mint transaction to be confirmed on-chain
    if !mint_success {
        println!("Mint transaction failed, aborting...");
        return;
    }
    println!("Waiting 60 seconds for mint transaction to be confirmed...");
    tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
    println!("Done waiting, proceeding with transfer...");

    let (transfer_tx, transferred_resource) = create_test_transfer(&data, &keychain_alice, &keychain_bob, &minted_resource).await;
    println!("Transfer tx: {:?}\n", transfer_tx);
    let transfer_success = submit_transaction(transfer_tx).await;
    
    // Wait for the transfer transaction to be confirmed on-chain
    if !transfer_success {
        println!("Transfer transaction failed, aborting...");
        return;
    }
    println!("Waiting 60 seconds for transfer transaction to be confirmed...");
    tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
    println!("Done waiting, proceeding with burn...");

    // Step 3: Burn the transferred resource
    let burn_tx = create_test_burn(&data, &keychain_bob, &transferred_resource).await;
    println!("Burn tx: {:?}\n", burn_tx);
    let _ = submit_transaction(burn_tx).await;

    println!("Yippie");
}