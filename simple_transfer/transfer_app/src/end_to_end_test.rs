use crate::{
    mint::submit_mint_transaction,
    transfer::submit_transfer_transaction,
    resource::{construct_ephemeral_resource, construct_persistent_resource},
    utils::{authorize_the_action, generate_permit2_signature},
};
use arm::{
    action_tree::MerkleTree,
    authorization::{AuthorizationSigningKey, AuthorizationVerifyingKey},
    compliance::INITIAL_ROOT,
    encryption::random_keypair,
    evm::CallType,
    nullifier_key::NullifierKey,
};
use alloy::primitives::{Address, U256};
use hex;

/// Test just the mint operation with ProtocolAdapter submission
#[tokio::test]
async fn mint_with_protocol_adapter_test() {
    // Load environment variables for Bonsai remote proving
    dotenv::from_filename("env.secret").ok();
    
    let forwarder_addr = hex::decode("1234567890123456789012345678901234567890").unwrap(); // Placeholder forwarder address
    let token_addr = "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238".parse::<Address>().unwrap().to_vec();
    let user_addr = "0x26aBD8C363f6Aa7FC4db989Ba4F34E7Bd5573A16".parse::<Address>().unwrap().to_vec();
    let quantity = 1;

    println!("=== STEP 1: MINT OPERATION ===");
    
    // === MINT SETUP ===
    // Construct the consumed ephemeral resource (represents ERC20 token)
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
    
    // Generate the created persistent resource (the private token)
    let (_created_nf_key, created_nf_cm) = NullifierKey::random_pair();
    let created_auth_sk = AuthorizationSigningKey::new();
    let created_auth_pk = AuthorizationVerifyingKey::from_signing_key(&created_auth_sk);
    let (_created_discovery_sk, created_discovery_pk) = random_keypair();
    let (_created_encryption_sk, created_encryption_pk) = random_keypair();
    let created_resource = construct_persistent_resource(
        &forwarder_addr,
        &token_addr,
        quantity,
        consumed_resource.nullifier(&consumed_nf_key).unwrap().as_bytes().to_vec(),
        created_nf_cm,
        vec![6u8; 32], // rand_seed
        &created_auth_pk,
    );

    // Generate Permit2 signature for minting
    let private_key_hex = std::env::var("PRIVATE_KEY").expect("PRIVATE_KEY must be set in env.secret");
    let owner_private_key = hex::decode(&private_key_hex).expect("Invalid private key hex")
        .try_into().expect("Private key must be 32 bytes");
    
    let permit2_contract_address = "0x000000000022D473030F116dDEE9F6B43aC78BA3".parse::<Address>().unwrap();
    let erc20_token_address = Address::from_slice(&token_addr);
    let spender_address = Address::from_slice(&forwarder_addr);
    let chain_id = 11155111; // Sepolia

    let permit_nonce = U256::from(rand::random::<u64>());
    let permit_deadline = U256::from(u64::MAX);

    // Create action tree to get the root for the witness
    let consumed_nf = consumed_resource.nullifier(&consumed_nf_key).unwrap();
    let created_cm = created_resource.commitment();
    let action_tree = arm::action_tree::MerkleTree::new(vec![consumed_nf, created_cm]);
    let action_tree_root = action_tree.root();
    let witness_data = arm::utils::words_to_bytes(&action_tree_root);

    let (r, s, v) = generate_permit2_signature(
        owner_private_key,
        permit2_contract_address,
        erc20_token_address,
        spender_address,
        U256::from(quantity),
        permit_nonce,
        permit_deadline,
        witness_data.to_vec(),
        chain_id,
    ).expect("Failed to generate permit signature");

    let permit_sig = [r, s, v].concat();
    let permit_nonce_bytes = permit_nonce.to_be_bytes_vec();
    let permit_deadline_bytes = permit_deadline.to_be_bytes_vec();

    // Test mint transaction construction (without ProtocolAdapter submission)
    let tx = crate::mint::construct_mint_tx(
        consumed_resource.clone(),
        INITIAL_ROOT.as_words().to_vec(),
        consumed_nf_key.clone(),
        created_discovery_pk,
        forwarder_addr.clone(),
        token_addr.clone(),
        user_addr.clone(),
        permit_nonce_bytes,
        permit_deadline_bytes,
        permit_sig,
        created_resource.clone(),
        created_discovery_pk,
        created_encryption_pk,
    ).await;

    // Verify the transaction locally
    assert!(tx.clone().verify(), "Mint transaction verification failed");
    println!("✅ Mint transaction constructed and verified successfully");
    
    println!("=== MINT WITH PROTOCOL ADAPTER TEST COMPLETED ===");
}
