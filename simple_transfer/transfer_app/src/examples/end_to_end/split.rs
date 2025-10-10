use crate::errors::TransactionError;
use crate::errors::TransactionError::{
    ActionError, ComplianceUnitCreateError, DeltaProofCreateError, InvalidAmount, InvalidKeyChain,
    InvalidNullifierSizeError, LogicProofCreateError, MerklePathError, MerkleProofError,
};
use crate::evm::evm_calls::pa_merkle_path;
use crate::examples::shared::{label_ref, random_nonce, value_ref_created, verify_transaction};
use crate::user::Keychain;
use crate::AnomaPayConfig;
use arm::action::Action;
use arm::action_tree::MerkleTree;
use arm::authorization::AuthorizationSignature;
use arm::compliance::ComplianceWitness;
use arm::compliance_unit::ComplianceUnit;
use arm::delta_proof::DeltaWitness;
use arm::logic_proof::LogicProver;
use arm::merkle_path::MerklePath;
use arm::nullifier_key::NullifierKey;
use arm::resource::Resource;
use arm::resource_logic::TrivialLogicWitness;
use arm::transaction::{Delta, Transaction};
use arm::Digest;
use std::thread;
use transfer_library::TransferLogic;

/// Splitting a resource means creating two resources out of 1 resource, but having the same
/// total quantity.
///            ┌─────────┐
///      ┌────►│remainder│
///      │     └─────────┘
///      │
/// ┌────┼─────┐
/// │ to_split │
/// └────┬─────┘
///      │      ┌────────┐
///      └─────►│created │
///             └────────┘
// these can be dead code because they're used for development.
#[allow(dead_code)]
pub async fn create_split_transaction(
    sender: Keychain,
    receiver: Keychain,
    to_split_resource: Resource,
    amount: u128,
    config: &AnomaPayConfig,
) -> Result<(Resource, Resource, Transaction), TransactionError> {
    // ensure the amount is enough to split
    if to_split_resource.quantity <= amount {
        return Err(InvalidAmount);
    };
    let remainder = to_split_resource.quantity - amount;

    // In a split, we need a balanced transaction. That means if we create two resources, we have
    // to consume two as well. This empty resource is called a padding resource.
    // This resource does not need the resource logic of the simple transfer either, so we use
    // the trivial logic.
    let padding_resource = Resource {
        logic_ref: TrivialLogicWitness::verifying_key(),
        label_ref: Digest::default(),
        quantity: 0,
        value_ref: Digest::default(),
        is_ephemeral: true,
        nonce: random_nonce(),
        nk_commitment: NullifierKey::default().commit(),
        rand_seed: [0u8; 32],
    };

    let padding_resource_nullifier = padding_resource
        .nullifier(&NullifierKey::default())
        .map_err(|_| InvalidKeyChain)?;

    let to_split_resource_nullifier = to_split_resource
        .nullifier(&sender.nf_key)
        .map_err(|_| InvalidKeyChain)?;

    ////////////////////////////////////////////////////////////////////////////
    // Construct the resource for the receiver

    let nonce = to_split_resource_nullifier
        .as_bytes()
        .try_into()
        .map_err(|_| InvalidNullifierSizeError)?;

    let created_resource = Resource {
        logic_ref: TransferLogic::verifying_key(),
        label_ref: label_ref(config),
        quantity: amount,
        value_ref: value_ref_created(&receiver),
        is_ephemeral: false,
        nonce,
        nk_commitment: receiver.nf_key.commit(),
        rand_seed: [7u8; 32],
    };

    let created_resource_commitment = created_resource.commitment();

    ////////////////////////////////////////////////////////////////////////////
    // Construct the remainder resource

    let nonce = padding_resource_nullifier
        .as_bytes()
        .try_into()
        .map_err(|_| InvalidNullifierSizeError)?;

    let remainder_resource = Resource {
        quantity: remainder,
        nonce,
        ..to_split_resource
    };

    let remainder_resource_commitment = remainder_resource.commitment();

    ////////////////////////////////////////////////////////////////////////////
    // Create the action tree

    let action_tree: MerkleTree = MerkleTree::new(vec![
        to_split_resource_nullifier,
        created_resource_commitment,
        padding_resource_nullifier,
        remainder_resource_commitment,
    ]);

    ////////////////////////////////////////////////////////////////////////////
    // Create the permit signature

    let action_tree_root: Digest = action_tree.root();
    let auth_signature: AuthorizationSignature =
        sender.auth_signing_key.sign(action_tree_root.as_bytes());

    ////////////////////////////////////////////////////////////////////////////
    // Get the merkle proof for the resource being split and the padding resource.

    let merkle_proof_to_split = pa_merkle_path(to_split_resource.commitment())
        .await
        .map_err(|_| MerkleProofError)?;

    ////////////////////////////////////////////////////////////////////////////
    // Create compliance proof

    let compliance_witness_created = ComplianceWitness::from_resources_with_path(
        to_split_resource,
        sender.nf_key.clone(),
        merkle_proof_to_split,
        created_resource,
    );

    // generate the proof in a separate thread
    let compliance_witness_created_clone = compliance_witness_created.clone();
    let compliance_unit_created =
        thread::spawn(move || ComplianceUnit::create(&compliance_witness_created_clone.clone()))
            .join()
            .map_err(|e| {
                println!("prove thread panic: {:?}", e);
                ComplianceUnitCreateError
            })?
            .map_err(|e| {
                println!("proving error: {:?}", e);
                ComplianceUnitCreateError
            })?;

    let compliance_witness_remainder_resource = ComplianceWitness::from_resources_with_path(
        padding_resource,
        NullifierKey::default(),
        MerklePath::default(),
        remainder_resource,
    );

    // generate the proof in a separate thread
    let compliance_witness_remainder_resource_clone = compliance_witness_remainder_resource.clone();
    let compliance_unit_remainder = thread::spawn(move || {
        ComplianceUnit::create(&compliance_witness_remainder_resource_clone.clone())
    })
    .join()
    .unwrap()
    .map_err(|_| ComplianceUnitCreateError)?;

    ////////////////////////////////////////////////////////////////////////////
    // Create logic proof

    //--------------------------------------------------------------------------
    // to_split proof

    let to_split_resource_path = action_tree
        .generate_path(&to_split_resource_nullifier)
        .map_err(|_| MerklePathError)?;

    let to_split_logic_witness: TransferLogic = TransferLogic::consume_persistent_resource_logic(
        to_split_resource,
        to_split_resource_path.clone(),
        sender.nf_key.clone(),       //TODO ! // sender_nf_key.clone(),
        sender.auth_verifying_key(), //TODO ! // sender_verifying_key,
        auth_signature,
    );

    // generate the proof in a separate thread
    let to_split_logic_proof = thread::spawn(move || to_split_logic_witness.prove())
        .join()
        .map_err(|e| {
            println!("prove thread panic: {:?}", e);
            LogicProofCreateError
        })?
        .map_err(|e| {
            println!("proving error: {:?}", e);
            LogicProofCreateError
        })?;

    //--------------------------------------------------------------------------
    // padding proof

    let padding_resource_path = action_tree
        .generate_path(&padding_resource_nullifier)
        .map_err(|_| MerklePathError)?;

    let padding_logic_witness = TrivialLogicWitness::new(
        padding_resource,
        padding_resource_path.clone(),
        NullifierKey::default(),
        true,
    );

    let padding_logic_proof = thread::spawn(move || padding_logic_witness.prove())
        .join()
        .map_err(|e| {
            println!("prove thread panic: {:?}", e);
            LogicProofCreateError
        })?
        .map_err(|e| {
            println!("proving error: {:?}", e);
            LogicProofCreateError
        })?;

    //--------------------------------------------------------------------------
    // created proof

    let created_resource_path = action_tree
        .generate_path(&created_resource_commitment)
        .map_err(|_| MerklePathError)?;

    let created_logic_witness = TransferLogic::create_persistent_resource_logic(
        created_resource,
        created_resource_path,
        &receiver.discovery_pk,
        receiver.encryption_pk,
    );

    let created_logic_proof = thread::spawn(move || created_logic_witness.prove())
        .join()
        .map_err(|e| {
            println!("prove thread panic: {:?}", e);
            LogicProofCreateError
        })?
        .map_err(|e| {
            println!("proving error: {:?}", e);
            LogicProofCreateError
        })?;

    //--------------------------------------------------------------------------
    // remainder proof

    let remainder_resource_path = action_tree
        .generate_path(&remainder_resource_commitment)
        .map_err(|_| MerklePathError)?;

    let remainder_logic_witness = TransferLogic::create_persistent_resource_logic(
        remainder_resource,
        remainder_resource_path,
        &receiver.discovery_pk,
        receiver.encryption_pk,
    );

    let remainder_logic_proof = thread::spawn(move || remainder_logic_witness.prove())
        .join()
        .map_err(|e| {
            println!("prove thread panic: {:?}", e);
            LogicProofCreateError
        })?
        .map_err(|e| {
            println!("proving error: {:?}", e);
            LogicProofCreateError
        })?;

    ////////////////////////////////////////////////////////////////////////////
    // Create actions for transaction

    let action: Action = Action::new(
        vec![compliance_unit_created, compliance_unit_remainder],
        vec![
            to_split_logic_proof,
            created_logic_proof,
            padding_logic_proof,
            remainder_logic_proof,
        ],
    )
    .map_err(|_| ActionError)?;

    let delta_witness: DeltaWitness = DeltaWitness::from_bytes_vec(&[
        compliance_witness_created.rcv,
        compliance_witness_remainder_resource.rcv,
    ])
    .map_err(|_| LogicProofCreateError)?;

    let transaction = Transaction::create(vec![action], Delta::Witness(delta_witness));

    let transaction = transaction
        .generate_delta_proof()
        .map_err(|_| DeltaProofCreateError)?;
    verify_transaction(transaction.clone())?;

    Ok((created_resource, remainder_resource, transaction))
}
