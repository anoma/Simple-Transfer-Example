use crate::examples::mint::TransactionError::{ActionTreeError, InvalidKeyChain, MerklePathError};
use crate::examples::shared::{
    create_permit_signature, label_ref, random_nonce, value_ref, value_ref_created,
    verify_transaction,
};
use crate::user::Keychain;
use alloy::primitives::U256;
use arm::action::Action;
use arm::action_tree::MerkleTree;
use arm::compliance::{ComplianceWitness, INITIAL_ROOT};
use arm::compliance_unit::ComplianceUnit;
use arm::delta_proof::DeltaWitness;
use arm::evm::CallType;
use arm::logic_proof::LogicProver;
use arm::resource::Resource;
use arm::transaction::{Delta, Transaction};
use arm::Digest;
use std::thread;
use transfer_library::TransferLogic;
use crate::AnomaPayConfig;

/// An error struct to signal an error occurred during the creation of a transaction.
#[derive(Debug, Clone)]
pub enum TransactionError {
    InvalidKeyChain,
    MerklePathError,
    ActionTreeError,
    VerificationFailure,
    MerkleProofError,
    InvalidAmount,
}

/// The value ref for an ephemeral resource in a minting transaction has to hold the calltype. A
/// minting transaction means you create a resource, and consume an ephemeral resource. Therefore
/// the consumed ephemeral resource needs to have the wrapping calltype.
fn value_ref_ephemeral_mint(minter: &Keychain) -> Vec<u8> {
    value_ref(CallType::Wrap, minter.evm_address.as_ref())
}

pub async fn create_mint_transaction(
    minter: Keychain,
    amount: u128,
    config: &AnomaPayConfig
) -> Result<(Resource, Transaction), TransactionError> {
    // A minting transaction does not consume existing resources, so there is no need to get the
    // commitment tree root for anything, and the initial root can be used.
    let latest_commitment_tree_root: Vec<u32> = INITIAL_ROOT.as_words().to_vec();

    ////////////////////////////////////////////////////////////////////////////
    // Construct the ephemeral resource

    let nonce = random_nonce();
    let consumed_resource = Resource {
        logic_ref: TransferLogic::verifying_key_as_bytes(),
        label_ref: label_ref(config),
        quantity: amount,
        value_ref: value_ref_ephemeral_mint(&minter),
        is_ephemeral: true,
        nonce: nonce.to_vec(),
        nk_commitment: minter.nf_key.commit(),
        rand_seed: random_nonce().to_vec(),
    };

    // create the nullifier for the created resource.
    // why do we use the nullifier based on the nullifier key from the minter here?
    // I presume because we used the commitment based off of this key for the ephemeral resource.
    // therefore the nullifier for the ephemeral resource is also derived from the nullifier key?
    let consumed_resource_nullifier = consumed_resource
        .nullifier(&minter.nf_key)
        .ok_or(InvalidKeyChain)?;

    ////////////////////////////////////////////////////////////////////////////
    // Construct the created resource

    // The nonce for the created resource must be the consumed resource's nullifier. The consumed
    // resource is the ephemeral resource that was created above.
    let nonce = consumed_resource_nullifier.as_bytes().to_vec();

    let created_resource = Resource {
        logic_ref: TransferLogic::verifying_key_as_bytes(),
        label_ref: label_ref(config),
        quantity: amount,
        value_ref: value_ref_created(&minter),
        is_ephemeral: false,
        nonce: nonce.clone(),
        nk_commitment: minter.nf_key.commit(),
        rand_seed: vec![6u8; 32],
    };

    let created_resource_commitment: Digest = created_resource.commitment();

    ////////////////////////////////////////////////////////////////////////////
    // Create the action tree

    let action_tree: MerkleTree = MerkleTree::new(vec![
        consumed_resource_nullifier,
        created_resource_commitment,
    ]);

    ////////////////////////////////////////////////////////////////////////////
    // Create the permit signature

    let minter_private_key = minter.private_key.ok_or(InvalidKeyChain)?;

    let nullifier: [u8; 32] = consumed_resource_nullifier.into();

    let permit_signature =
        create_permit_signature(&minter_private_key, action_tree.clone(), nullifier, amount, config)
            .await;

    ////////////////////////////////////////////////////////////////////////////
    // Create the action tree

    let action_tree: MerkleTree = MerkleTree::new(vec![
        consumed_resource_nullifier,
        created_resource_commitment,
    ]);

    ////////////////////////////////////////////////////////////////////////////
    // Create compliance proof

    let compliance_witness = ComplianceWitness::from_resources(
        consumed_resource.clone(),
        latest_commitment_tree_root,
        minter.nf_key.clone(),
        created_resource.clone(),
    );

    // generate the proof in a separate thread
    let compliance_witness_clone = compliance_witness.clone();
    let compliance_unit =
        thread::spawn(move || ComplianceUnit::create(&compliance_witness_clone.clone()))
            .join()
            .unwrap();

    ////////////////////////////////////////////////////////////////////////////
    // Create logic proof

    let consumed_resource_path = action_tree
        .generate_path(&consumed_resource_nullifier)
        .ok_or(MerklePathError)?;

    let consumed_logic_witness: TransferLogic = TransferLogic::mint_resource_logic_with_permit(
        consumed_resource.clone(),
        consumed_resource_path,
        minter.nf_key.clone(),
        config.forwarder_address.to_vec(),
        config.token_address.to_vec(),
        minter.evm_address.to_vec(),
        nonce.to_vec(),
        U256::from(config.deadline).to_be_bytes_vec(),
        permit_signature.as_bytes().to_vec(),
    );

    // generate the proof in a separate thread
    let consumed_logic_witness_clone = consumed_logic_witness.clone();
    let consumed_logic_proof = thread::spawn(move || consumed_logic_witness_clone.prove())
        .join()
        .unwrap();

    let created_resource_path = action_tree
        .generate_path(&created_resource_commitment)
        .ok_or(ActionTreeError)?;

    let created_logic_witness = TransferLogic::create_persistent_resource_logic(
        created_resource.clone(),
        created_resource_path,
        &minter.discovery_pk,
        minter.encryption_pk,
    );

    // generate the proof in a separate thread
    // this is due to bonsai being non-blocking or something. there is a feature flag for bonsai
    // that allows it to be non-blocking or vice versa, but this is to figure out.
    let created_logic_witness_clone = created_logic_witness.clone();
    let created_logic_proof = thread::spawn(move || created_logic_witness_clone.prove())
        .join()
        .unwrap();

    ////////////////////////////////////////////////////////////////////////////
    // Create actions for transaction

    let action: Action = Action::new(
        vec![compliance_unit],
        vec![consumed_logic_proof, created_logic_proof],
    );

    let delta_witness = DeltaWitness::from_bytes(&compliance_witness.rcv);
    let mut transaction = Transaction::create(vec![action], Delta::Witness(delta_witness));
    transaction.generate_delta_proof();

    verify_transaction(transaction.clone())?;
    Ok((created_resource, transaction))
}
// pub fn mint_from_json_request(create_request: CreateRequest) -> (Resource, Transaction) {
//     let config = CONFIG.get().expect("config not set");
//
//     let consumed_resource = expand_resource(create_request.consumed_resource);
//     let created_resource = expand_resource(create_request.created_resource);
//     let latest_commitment_tree_root = bytes_to_words(create_request.latest_cm_tree_root.as_slice());
//     let consumed_nf_key: NullifierKey =
//         NullifierKey::from_bytes(create_request.consumed_nf_key.as_slice());
//     let created_discovery_pk: AffinePoint = create_request.created_discovery_pk;
//     let created_encryption_pk: AffinePoint = create_request.created_encryption_pk;
//     let user_address = create_request.user_addr;
//     let signature = create_request.permit_sig;
//
//     let nonce = create_request.permit_nonce;
//
//     ////////////////////////////////////////////////////////////////////////////
//     // Create the action tree
//
//     let consumed_nf: Digest = consumed_resource
//         .nullifier(&consumed_nf_key)
//         .expect("failed to compute nullifier from nf key of minter");
//     let created_cm: Digest = created_resource.commitment();
//
//     let action_tree: MerkleTree = MerkleTree::new(vec![consumed_nf, created_cm]);
//
//     ////////////////////////////////////////////////////////////////////////////
//     // Create compliance proof
//
//     let compliance_witness = ComplianceWitness::from_resources(
//         consumed_resource.clone(),
//         latest_commitment_tree_root,
//         consumed_nf_key.clone(),
//         created_resource.clone(),
//     );
//
//     let compliance_unit = ComplianceUnit::create(&compliance_witness);
//
//     ////////////////////////////////////////////////////////////////////////////
//     // Create logic proof
//
//     let consumed_resource_path = action_tree
//         .generate_path(&consumed_nf)
//         .expect("failed to generate path for consumed resource");
//
//     let consumed_logic_witness: TransferLogic = TransferLogic::mint_resource_logic_with_permit(
//         consumed_resource.clone(),
//         consumed_resource_path,
//         consumed_nf_key.clone(),
//         config.forwarder_address.to_vec(),
//         config.token_address.to_vec(),
//         user_address,
//         nonce,
//         U256::from(config.deadline).to_be_bytes_vec(),
//         signature,
//     );
//
//     let consumed_logic_proof: LogicVerifier = consumed_logic_witness.prove();
//
//     let created_resource_path = action_tree
//         .generate_path(&created_cm)
//         .expect("failed to generate path for created resource");
//
//     let created_logic_witness = TransferLogic::create_persistent_resource_logic(
//         created_resource.clone(),
//         created_resource_path,
//         &created_discovery_pk,
//         created_encryption_pk,
//     );
//
//     let created_logic_proof = created_logic_witness.prove();
//
//     ////////////////////////////////////////////////////////////////////////////
//     // Create actions for transaction
//
//     let action: Action = Action::new(
//         vec![compliance_unit],
//         vec![consumed_logic_proof, created_logic_proof],
//     );
//
//     let delta_witness: DeltaWitness = DeltaWitness::from_bytes(&compliance_witness.rcv);
//     let mut tx: Transaction = Transaction::create(vec![action], Delta::Witness(delta_witness));
//     tx.generate_delta_proof();
//
//     assert!(tx.clone().verify(), "Transaction verification failed");
//     if tx.clone().verify() {
//         println!("IT VERIFIED 🥳💸💸💸💸💸💸💸💸")
//     }
//     (created_resource, tx)
// }
//
// // these can be dead code because they're used for development.
// #[allow(dead_code)]
// pub fn create_mint_json_request(minter: Keychain) -> CreateRequest {
//     let config = CONFIG.get().expect("config not set");
//
//     let initial_commitment_root: Vec<u32> = INITIAL_ROOT.as_words().to_vec();
//
//     let mut rng = rand::thread_rng();
//     let nonce: [u8; 32] = rng.gen();
//
//     ////////////////////////////////////////////////////////////////////////////
//     // Construct the ephemeral resource
//
//     let label_ref = hash_bytes(
//         &[
//             config.forwarder_address.to_vec(),
//             config.token_address.to_vec(),
//         ]
//         .concat(),
//     );
//     let value_ref = value_ref(CallType::Wrap, minter.evm_address.as_ref());
//
//     let consumed_resource = Resource::create(
//         TransferLogic::verifying_key_as_bytes(),
//         label_ref.clone(),
//         config.default_amount as u128,
//         value_ref.clone(),
//         true,
//         nonce.to_vec(),
//         minter.nf_key.commit(),
//     );
//     ////////////////////////////////////////////////////////////////////////////
//     // Construct the created resource
//
//     // create the nullifier for the created resource.
//     // why do we use the nullifier based on the nullifier key from the minter here?
//     // I presume because we used the commitment based off of this key for the ephemeral resource.
//     // therefore the nullifier for the ephemeral resource is also derived from the nullifier key?
//     let consumed_nf: Digest = consumed_resource
//         .nullifier(&minter.nf_key)
//         .expect("failed to compute nullifier from nf key of minter");
//
//     let created_resource = Resource {
//         logic_ref: TransferLogic::verifying_key_as_bytes(),
//         label_ref: label_ref.clone(),
//         quantity: config.default_amount as u128,
//         value_ref: hash_bytes(&minter.auth_verifying_key().to_bytes()),
//         is_ephemeral: false,
//         nonce: consumed_nf.clone().as_bytes().to_vec(),
//         nk_commitment: minter.nf_key.commit(),
//         rand_seed: vec![6u8; 32],
//     };
//
//     let created_cm: Digest = created_resource.commitment();
//
//     ////////////////////////////////////////////////////////////////////////////
//     // Create the action tree
//
//     let action_tree: MerkleTree = MerkleTree::new(vec![consumed_nf, created_cm]);
//
//     ////////////////////////////////////////////////////////////////////////////
//     // Create the permit signature
//
//     let private_key = minter
//         .private_key
//         .expect("private key for minter cannot be empty");
//
//     let permit_signature = create_permit_signature(&private_key, action_tree.clone(), nonce,
//                                                    config.default_amount as u128);
//
//     CreateRequest {
//         consumed_resource: compact_resource(consumed_resource),
//         created_resource: compact_resource(created_resource),
//         latest_cm_tree_root: words_to_bytes(initial_commitment_root.as_slice()).to_vec(),
//         consumed_nf_key: minter.nf_key.inner().to_vec(),
//         forwarder_addr: config.forwarder_address.to_vec(),
//         token_addr: config.token_address.to_vec(),
//         user_addr: minter.evm_address.to_vec(),
//         permit_nonce: nonce.to_vec(),
//         permit_deadline: U256::from(config.deadline).to_be_bytes_vec(),
//         permit_sig: permit_signature.as_bytes().to_vec(),
//         created_discovery_pk: minter.discovery_pk,
//         created_encryption_pk: minter.encryption_pk,
//     }
// }
//
// pub fn create_mint_json_string(minter: Keychain) -> String {
//     let create_request = create_mint_json_request(minter);
//     serde_json::to_string(&create_request).unwrap()
// }
