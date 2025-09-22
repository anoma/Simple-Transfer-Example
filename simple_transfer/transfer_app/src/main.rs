use crate::{resource::{construct_ephemeral_resource, construct_persistent_resource}, utils::authorize_the_action};
use arm::{
    action_tree::MerkleTree,
    authorization::{AuthorizationSigningKey, AuthorizationVerifyingKey},
    compliance::INITIAL_ROOT,
    encryption::{random_keypair, Ciphertext, AffinePoint, SecretKey},
    evm::CallType,
    merkle_path::MerklePath,
    nullifier_key::{NullifierKey, NullifierKeyCommitment},
    resource::Resource,
    transaction::Transaction,
    utils::{bytes_to_words, words_to_bytes},
};
use evm_protocol_adapter_bindings::permit2::permit_witness_transfer_from_signature;
use alloy::primitives::{Address, B256, U256, address};
use alloy::signers::local::PrivateKeySigner;
use alloy::hex;
use std::env;

use eth::submit;
use tokio::runtime;

mod resource;
mod utils;
mod transfer;
mod mint;
mod burn;
mod eth;

pub struct SetUp {
    pub signer: PrivateKeySigner,
    pub erc20: Address,
    pub amount: U256,
    pub nonce: U256,
    pub deadline: U256,
    pub spender: Address,
}

fn empty_leaf_hash() -> B256 {
    B256::from(hex!(
        "cc1d2f838445db7aec431df9ee8a871f40e7aa5e064fc056633ef8c60fab7b06"
    ))
}

pub fn default_values() -> SetUp {
    SetUp {
        signer: env::var("PRIVATE_KEY")
            .expect("Couldn't read PRIVATE_KEY")
            .parse()
            .expect("should parse private key"),
        erc20: address!("0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238"), // USDC
        amount: U256::from(10),
        nonce: U256::from(1),
        deadline: U256::from(1893456000),
        spender: address!("0xc797A7708655b0e0907DABCb2246e07De91F7AF8"), // deployed for new logic-ref
    }
}

#[allow(dead_code)]
pub struct KeyChain {
    auth_signing_key: AuthorizationSigningKey,
    nf_key: NullifierKey,
    discovery_sk: SecretKey,
    discovery_pk: AffinePoint,
    encryption_sk: SecretKey,
    encryption_pk: AffinePoint,
}

impl KeyChain {
    fn auth_verifying_key(&self) -> AuthorizationVerifyingKey {
        AuthorizationVerifyingKey::from_signing_key(&self.auth_signing_key)
    }

    fn nullifier_key_commitment(&self) -> NullifierKeyCommitment {
        self.nf_key.commit()
    }
}

fn example_keychain() -> KeyChain {
    let (discovery_sk, discovery_pk) = random_keypair();
    let (encryption_sk, encryption_pk) = random_keypair();

    KeyChain {
        auth_signing_key: AuthorizationSigningKey::from_bytes(&vec![15u8; 32]),
        nf_key: NullifierKey::from_bytes(&vec![13u8; 32]),
        discovery_sk,
        discovery_pk,
        encryption_sk,
        encryption_pk,
    }
}

fn simple_mint_test(
    data: &SetUp,
    keychain: &KeyChain
) -> (Transaction, Resource) {
    let consumed_resource = construct_ephemeral_resource(
        &data.spender.to_vec(),
        &data.erc20.to_vec(),
        data.amount.try_into().unwrap(),
        vec![4u8; 32], // nonce
        keychain.nf_key.commit(),
        vec![5u8; 32], // rand_seed
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

    let rt = runtime::Runtime::new().unwrap();
    let permit_sig = rt.block_on(permit_witness_transfer_from_signature(
        &data.signer,
        data.erc20,
        data.amount,
        data.nonce,
        data.deadline,
        data.spender,
        B256::from_slice(words_to_bytes(action_tree.root().as_slice())), // Witness
    ));

    // Construct the mint transaction
    let tx = mint::construct_mint_tx(
        consumed_resource,
        latest_cm_tree_root,
        keychain.nf_key.clone(),
        data.spender.to_vec(),
        data.erc20.to_vec(),
        data.signer.address().to_vec(),
        data.nonce.to_be_bytes_vec(),
        data.deadline.to_be_bytes_vec(),
        permit_sig.as_bytes().to_vec(),
        created_resource.clone(),
        keychain.discovery_pk,
        keychain.encryption_pk
    );

    // Verify the transaction
    if tx.clone().verify() {
        println!("Transaction verified");
    } else {
        println!("Transaction not verified");
    }
    (tx, created_resource)
}

fn create_test_transfer(
    data: &SetUp,
    keychain: &KeyChain,
    resource_to_transfer: &Resource,
) -> Transaction {
    let consumed_nf = resource_to_transfer.nullifier(&keychain.nf_key).unwrap();
    
    // Create the created resource data
    let created_resource = construct_persistent_resource(
        &data.spender.to_vec(), // forwarder_addr
        &data.erc20.to_vec(),     // token_addr
        data.amount.try_into().unwrap(),
        consumed_nf.as_bytes().to_vec(), // nonce
        keychain.nullifier_key_commitment(),
        vec![7u8; 32], // rand_seed
        &keychain.auth_verifying_key(),
    );
    let created_cm = created_resource.commitment();

    // Get the authorization signature, it can be from external signing(e.g. wallet)
    let action_tree = MerkleTree::new(vec![consumed_nf, created_cm]);
    let auth_sig = authorize_the_action(&keychain.auth_signing_key, &action_tree);

    // Construct the transfer transaction
    let is_left = false;
    let path: &[(Vec<u32>, bool)] = &[(bytes_to_words(empty_leaf_hash().as_slice()), is_left)];
    let merkle_path = MerklePath::from_path(path);

    let tx = transfer::construct_transfer_tx(
        resource_to_transfer.clone(),
        merkle_path.clone(),
        keychain.nf_key.clone(),
        keychain.auth_verifying_key(),
        auth_sig,
        created_resource.clone(),
        keychain.discovery_pk,
        keychain.encryption_pk,
    );

    // Verify the transaction
    if tx.clone().verify() {
        println!("Transaction verified");
    } else {
        println!("Transaction not verified");
    }
    tx
}

pub fn submit_transaction(transaction: Transaction) {
    let rt = runtime::Runtime::new().unwrap();

    let _ = rt.block_on(async { submit(transaction).await });
}

fn main() {

    let data: SetUp = default_values();
    let keychain: KeyChain = example_keychain();

    let (mint_tx, minted_resource) = simple_mint_test(&data, &keychain);
    println!("Mint tx: {:?}", mint_tx);
    println!("Minted resource: {:?}", minted_resource);
    let _ = submit_transaction(mint_tx);

    let transfer_tx = create_test_transfer(&data, &keychain, &minted_resource);
    println!("Transfer tx: {:?}", transfer_tx);
    let _ = submit_transaction(transfer_tx);

    println!("Yippie");
}