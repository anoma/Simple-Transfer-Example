use crate::errors::TransactionError;
use crate::errors::TransactionError::{InvalidKeyChain, MerklePathError, MerkleProofError};
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
use arm::merkle_path::MerklePath;
use arm::nullifier_key::NullifierKey;
use arm::resource::Resource;
use arm::resource_logic::TrivialLogicWitness;
use arm::transaction::{Delta, Transaction};
use k256::AffinePoint;
use serde::{Deserialize, Serialize};
use serde_with::base64::Base64;
use serde_with::serde_as;
use std::thread;
use transfer_library::TransferLogic;

#[serde_as]
#[derive(Deserialize, Serialize, Debug, PartialEq)]
pub struct SplitRequest {
    pub to_split_resource: JsonResource,
    pub created_resource: JsonResource,
    pub remainder_resource: JsonResource, // A second resource with the remaining quantity will be created for the owner.
    pub padding_resource: JsonResource, // A second resource with the remaining quantity will be created for the owner.
    #[serde_as(as = "Base64")]
    pub sender_nf_key: Vec<u8>,
    pub sender_verifying_key: AffinePoint,
    #[serde_as(as = "Base64")]
    pub auth_signature: Vec<u8>,
    pub owner_discovery_pk: AffinePoint,
    pub owner_encryption_pk: AffinePoint,
    pub receiver_discovery_pk: AffinePoint,
    pub receiver_encryption_pk: AffinePoint,
}

/// Execute a burn transaction from a burn request.
pub async fn split_from_request(request: SplitRequest) -> Result<Transaction, TransactionError> {
    let to_split_resource: Resource = Expand::expand(request.to_split_resource);
    let created_resource: Resource = Expand::expand(request.created_resource);
    let padding_resource: Resource = Expand::expand(request.padding_resource);
    let remainder_resource: Resource = Expand::expand(request.remainder_resource);
    let receiver_discovery_pk = request.receiver_discovery_pk;
    let receiver_encryption_pk = request.receiver_encryption_pk;
    let sender_nf_key: NullifierKey = NullifierKey::from_bytes(request.sender_nf_key.as_slice());
    let sender_auth_verifying_key: AuthorizationVerifyingKey =
        AuthorizationVerifyingKey::from_affine(request.sender_verifying_key);

    let auth_signature: AuthorizationSignature =
        AuthorizationSignature::from_bytes(request.auth_signature.as_slice());

    ////////////////////////////////////////////////////////////////////////////
    // Create the action tree

    let padding_resource_nullifier = padding_resource
        .nullifier(&NullifierKey::default())
        .ok_or(InvalidKeyChain)?;

    let to_split_resource_nullifier = to_split_resource
        .nullifier(&sender_nf_key)
        .ok_or(InvalidKeyChain)?;

    let created_resource_commitment = created_resource.commitment();

    let remainder_resource_commitment = remainder_resource.commitment();

    let action_tree: MerkleTree = MerkleTree::new(vec![
        to_split_resource_nullifier,
        created_resource_commitment,
        padding_resource_nullifier,
        remainder_resource_commitment,
    ]);

    ////////////////////////////////////////////////////////////////////////////
    // Get the merkle proof for the resource being split and the padding resource.

    let merkle_proof_to_split = pa_merkle_path(to_split_resource.commitment())
        .await
        .map_err(|_| MerkleProofError)?;

    ////////////////////////////////////////////////////////////////////////////
    // Create compliance proof

    let compliance_witness_created = ComplianceWitness::from_resources_with_path(
        to_split_resource.clone(),
        sender_nf_key.clone(),
        merkle_proof_to_split,
        created_resource.clone(),
    );

    // generate the proof in a separate thread
    let compliance_witness_created_clone = compliance_witness_created.clone();
    let compliance_unit_created =
        thread::spawn(move || ComplianceUnit::create(&compliance_witness_created_clone.clone()))
            .join()
            .unwrap();

    let compliance_witness_remainder_resource = ComplianceWitness::from_resources_with_path(
        padding_resource.clone(),
        NullifierKey::default(),
        MerklePath::default(),
        remainder_resource.clone(),
    );

    // generate the proof in a separate thread
    let compliance_witness_remainder_resource_clone = compliance_witness_remainder_resource.clone();
    let compliance_unit_remainder = thread::spawn(move || {
        ComplianceUnit::create(&compliance_witness_remainder_resource_clone.clone())
    })
    .join()
    .unwrap();

    ////////////////////////////////////////////////////////////////////////////
    // Create logic proof

    //--------------------------------------------------------------------------
    // to_split proof

    let to_split_resource_path = action_tree
        .generate_path(&to_split_resource_nullifier)
        .ok_or(MerklePathError)?;

    let to_split_logic_witness: TransferLogic = TransferLogic::consume_persistent_resource_logic(
        to_split_resource.clone(),
        to_split_resource_path.clone(),
        sender_nf_key.clone(),
        sender_auth_verifying_key,
        auth_signature,
    );

    // generate the proof in a separate thread
    let to_split_logic_proof = thread::spawn(move || to_split_logic_witness.prove())
        .join()
        .unwrap();

    //--------------------------------------------------------------------------
    // padding proof

    let padding_resource_path = action_tree
        .generate_path(&padding_resource_nullifier)
        .ok_or(MerklePathError)?;

    let padding_logic_witness = TrivialLogicWitness::new(
        padding_resource.clone(),
        padding_resource_path.clone(),
        NullifierKey::default(),
        true,
    );

    let padding_logic_proof = thread::spawn(move || padding_logic_witness.prove())
        .join()
        .unwrap();

    //--------------------------------------------------------------------------
    // created proof

    let created_resource_path = action_tree
        .generate_path(&created_resource_commitment)
        .ok_or(MerklePathError)?;

    let created_logic_witness = TransferLogic::create_persistent_resource_logic(
        created_resource.clone(),
        created_resource_path,
        &receiver_discovery_pk,
        receiver_encryption_pk,
    );

    let created_logic_proof = thread::spawn(move || created_logic_witness.prove())
        .join()
        .unwrap();

    //--------------------------------------------------------------------------
    // remainder proof

    let remainder_resource_path = action_tree
        .generate_path(&remainder_resource_commitment)
        .ok_or(MerklePathError)?;

    let remainder_logic_witness = TransferLogic::create_persistent_resource_logic(
        remainder_resource.clone(),
        remainder_resource_path,
        &receiver_discovery_pk,
        receiver_encryption_pk,
    );

    let remainder_logic_proof = thread::spawn(move || remainder_logic_witness.prove())
        .join()
        .unwrap();

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
    );

    let delta_witness: DeltaWitness = DeltaWitness::from_bytes_vec(&[
        compliance_witness_created.rcv,
        compliance_witness_remainder_resource.rcv,
    ]);
    let mut transaction = Transaction::create(vec![action], Delta::Witness(delta_witness));
    transaction.generate_delta_proof();

    verify_transaction(transaction.clone())?;
    Ok(transaction)
}
