use crate::errors::TransactionError;
use crate::errors::TransactionError::{ActionTreeError, InvalidKeyChain, MerkleProofError};
use crate::evm::evm_calls::pa_merkle_path;
use crate::examples::shared::verify_transaction;
use crate::requests::resource::JsonResource;
use crate::requests::Expand;
use arm::action::Action;
use arm::action_tree::MerkleTree;
use arm::authorization::{AuthorizationSignature, AuthorizationVerifyingKey};
use arm::compliance::ComplianceWitness;
use arm::compliance_unit::ComplianceUnit;
use arm::delta_proof::DeltaWitness;
use arm::logic_proof::LogicProver;
use arm::nullifier_key::NullifierKey;
use arm::resource::Resource;
use arm::transaction::{Delta, Transaction};
use k256::AffinePoint;
use serde::{Deserialize, Serialize};
use serde_with::base64::Base64;
use serde_with::serde_as;
use std::thread;
use transfer_library::TransferLogic;

/// Struct to hold the fields for a transfer request to the api.
#[serde_as]
#[derive(Deserialize, Serialize, Debug, PartialEq)]
pub struct TransferRequest {
    pub transferred_resource: JsonResource,
    pub created_resource: JsonResource,
    #[serde_as(as = "Base64")]
    pub sender_nf_key: Vec<u8>,
    pub sender_verifying_key: AffinePoint,
    #[serde_as(as = "Base64")]
    pub auth_signature: Vec<u8>,
    pub receiver_discovery_pk: AffinePoint,
    pub receiver_encryption_pk: AffinePoint,
}

/// Handles an incoming transfer request
pub async fn transfer_from_request(
    request: TransferRequest,
) -> Result<(Resource, Transaction), TransactionError> {
    // convert some bytes into their proper data structure from the request.
    let transferred_resource: Resource = Expand::expand(request.transferred_resource);
    let created_resource: Resource = Expand::expand(request.created_resource);
    let sender_nf_key: NullifierKey = NullifierKey::from_bytes(request.sender_nf_key.as_slice());
    let sender_auth_verifying_key: AuthorizationVerifyingKey =
        AuthorizationVerifyingKey::from_affine(request.sender_verifying_key);
    let auth_signature: AuthorizationSignature =
        AuthorizationSignature::from_bytes(request.auth_signature.as_slice());
    let receiver_discovery_pk = request.receiver_discovery_pk;
    let receiver_encryption_pk = request.receiver_encryption_pk;

    let transferred_resource_commitment = transferred_resource.commitment();

    let merkle_proof = pa_merkle_path(transferred_resource_commitment)
        .await
        .map_err(|_| MerkleProofError)?;

    let transferred_resource_nullifier = transferred_resource
        .nullifier(&sender_nf_key)
        .ok_or(InvalidKeyChain)?;

    let created_resource_commitment = created_resource.commitment();

    ////////////////////////////////////////////////////////////////////////////
    // Create the action tree

    let action_tree: MerkleTree = MerkleTree::new(vec![
        transferred_resource_nullifier,
        created_resource_commitment,
    ]);

    ////////////////////////////////////////////////////////////////////////////
    // Create compliance proof

    let compliance_witness = ComplianceWitness::from_resources_with_path(
        transferred_resource.clone(),
        sender_nf_key.clone(),
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
        sender_nf_key.clone(),
        sender_auth_verifying_key,
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
        &receiver_discovery_pk,
        receiver_encryption_pk,
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
