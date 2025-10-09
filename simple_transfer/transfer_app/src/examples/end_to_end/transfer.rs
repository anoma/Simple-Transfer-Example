use crate::errors::TransactionError;
use crate::errors::TransactionError::{ActionTreeError, InvalidKeyChain, MerkleProofError};
use crate::evm::evm_calls::pa_merkle_path;
use crate::examples::shared::{label_ref, value_ref_created, verify_transaction};
use crate::user::Keychain;
use crate::AnomaPayConfig;
use arm::action::Action;
use arm::action_tree::MerkleTree;
use arm::authorization::AuthorizationSignature;
use arm::compliance::ComplianceWitness;
use arm::compliance_unit::ComplianceUnit;
use arm::delta_proof::DeltaWitness;
use arm::logic_proof::LogicProver;
use arm::resource::Resource;
use arm::transaction::{Delta, Transaction};
use arm::utils::words_to_bytes;
use std::thread;
use transfer_library::TransferLogic;

/// To transfer a resource, we have to create a new resource, and consume the resource that is
/// being transferred.
// these can be dead code because they're used for development.
#[allow(dead_code)]
pub async fn create_transfer_transaction(
    sender: Keychain,
    receiver: Keychain,
    transferred_resource: Resource,
    config: &AnomaPayConfig,
) -> Result<(Resource, Transaction), TransactionError> {
    // to transfer a resource, we need the nullifier of that resource.
    let transferred_resource_nullifier = transferred_resource
        .nullifier(&sender.nf_key)
        .ok_or(InvalidKeyChain)?;

    ////////////////////////////////////////////////////////////////////////////
    // Construct the resource for the receiver

    let created_resource = Resource {
        logic_ref: TransferLogic::verifying_key_as_bytes(),
        label_ref: label_ref(config),
        quantity: transferred_resource.quantity,
        value_ref: value_ref_created(&receiver),
        is_ephemeral: false,
        nonce: transferred_resource_nullifier.clone().as_bytes().to_vec(),
        nk_commitment: receiver.nf_key.commit(),
        rand_seed: vec![7u8; 32],
    };

    let created_resource_commitment = created_resource.commitment();

    ////////////////////////////////////////////////////////////////////////////
    // Create the action tree

    let action_tree: MerkleTree = MerkleTree::new(vec![
        transferred_resource_nullifier,
        created_resource_commitment,
    ]);

    let action_tree_root: Vec<u32> = action_tree.root();

    ////////////////////////////////////////////////////////////////////////////
    // Create the permit signature

    let auth_signature: AuthorizationSignature = sender
        .auth_signing_key
        .sign(words_to_bytes(&action_tree_root));

    ////////////////////////////////////////////////////////////////////////////
    // Get the merkle proof for the resource being transferred

    let transferred_resource_commitment = transferred_resource.commitment();

    let merkle_proof = pa_merkle_path(transferred_resource_commitment)
        .await
        .map_err(|_| MerkleProofError)?;

    ////////////////////////////////////////////////////////////////////////////
    // Create compliance proof

    let compliance_witness = ComplianceWitness::from_resources_with_path(
        transferred_resource.clone(),
        sender.nf_key.clone(),
        merkle_proof,
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
        .generate_path(&transferred_resource_nullifier)
        .ok_or(ActionTreeError)?;

    let transferred_logic_witness: TransferLogic = TransferLogic::consume_persistent_resource_logic(
        transferred_resource.clone(),
        consumed_resource_path,
        sender.nf_key.clone(),
        sender.auth_verifying_key(),
        auth_signature,
    );

    // generate the proof in a separate thread
    // this is due to bonsai being non-blocking or something. there is a feature flag for bonsai
    // that allows it to be non-blocking or vice versa, but this is to figure out.
    let transferred_logic_witness_clone = transferred_logic_witness.clone();
    let transferred_logic_proof = thread::spawn(move || transferred_logic_witness_clone.prove())
        .join()
        .unwrap();

    let created_resource_path = action_tree
        .generate_path(&created_resource_commitment)
        .ok_or(ActionTreeError)?;

    let created_logic_witness: TransferLogic = TransferLogic::create_persistent_resource_logic(
        created_resource.clone(),
        created_resource_path,
        &receiver.discovery_pk,
        receiver.encryption_pk,
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
        vec![transferred_logic_proof, created_logic_proof],
    );

    ////////////////////////////////////////////////////////////////////////////
    // Create delta proof

    let delta_witness = DeltaWitness::from_bytes(&compliance_witness.rcv);
    let mut transaction = Transaction::create(vec![action], Delta::Witness(delta_witness));
    transaction.generate_delta_proof();

    verify_transaction(transaction.clone())?;
    Ok((created_resource, transaction))
}
