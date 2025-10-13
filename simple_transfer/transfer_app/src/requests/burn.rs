use crate::errors::TransactionError;
use crate::errors::TransactionError::{
    ActionError, ActionTreeError, ComplianceUnitCreateError, DecodingError, DeltaProofCreateError,
    EncodingError, InvalidKeyChain, InvalidNullifierSizeError, LogicProofCreateError,
    MerkleProofError,
};
use crate::evm::evm_calls::pa_merkle_path;
use crate::examples::shared::{label_ref, random_nonce, value_ref, verify_transaction};
use crate::requests::resource::JsonResource;
use crate::requests::Expand;
use crate::AnomaPayConfig;
use arm::action::Action;
use arm::action_tree::MerkleTree;
use arm::authorization::{AuthorizationSignature, AuthorizationVerifyingKey};
use arm::compliance::ComplianceWitness;
use arm::compliance_unit::ComplianceUnit;
use arm::delta_proof::DeltaWitness;
use arm::evm::CallType;
use arm::logic_proof::LogicProver;
use arm::nullifier_key::NullifierKey;
use arm::resource::Resource;
use arm::transaction::{Delta, Transaction};
use arm::Digest;
use k256::AffinePoint;
use rocket::serde::{Deserialize, Serialize};
use serde_with::base64::Base64;
use serde_with::serde_as;
use std::thread;
use transfer_library::TransferLogic;

/// Defines the payload sent to the API to execute a burn request on /api/burn.
#[serde_as]
#[derive(Deserialize, Serialize, Debug, PartialEq)]
pub struct BurnRequest {
    pub burned_resource: JsonResource,
    #[serde_as(as = "Base64")]
    pub burner_nf_key: Vec<u8>,
    pub burner_verifying_key: AffinePoint,
    #[serde_as(as = "Base64")]
    pub burner_address: Vec<u8>,
    #[serde_as(as = "Base64")]
    pub auth_signature: Vec<u8>,
}

pub async fn burn_from_request(
    request: BurnRequest,
    config: &AnomaPayConfig,
) -> Result<Transaction, TransactionError> {
    let burned_resource: Resource =
        Expand::expand(request.burned_resource).map_err(|_| DecodingError)?;
    let burner_nf_key: NullifierKey = NullifierKey::from_bytes(request.burner_nf_key.as_slice());
    let burner_auth_verifying_key: AuthorizationVerifyingKey =
        AuthorizationVerifyingKey::from_affine(request.burner_verifying_key);
    let burned_resource_commitment = burned_resource.commitment();

    let merkle_proof = pa_merkle_path(burned_resource_commitment)
        .await
        .map_err(|_| MerkleProofError)?;
    let burner_address = request.burner_address;

    let burned_resource_nullifier: Digest = burned_resource
        .nullifier(&burner_nf_key)
        .map_err(|_| InvalidKeyChain)?;

    let auth_signature: AuthorizationSignature =
        AuthorizationSignature::from_bytes(request.auth_signature.as_slice())
            .map_err(|_| EncodingError)?;
    ////////////////////////////////////////////////////////////////////////////
    // Construct the ephemeral resource to create

    let nonce = burned_resource_nullifier
        .as_bytes()
        .try_into()
        .map_err(|_| InvalidNullifierSizeError)?;

    let created_resource = Resource {
        logic_ref: TransferLogic::verifying_key(),
        label_ref: label_ref(config),
        quantity: burned_resource.quantity,
        value_ref: value_ref(CallType::Unwrap, burner_address.as_ref()),
        is_ephemeral: true,
        nonce,
        nk_commitment: burner_nf_key.commit(),
        rand_seed: random_nonce(),
    };

    let created_resource_commitment = created_resource.commitment();

    ////////////////////////////////////////////////////////////////////////////
    // Create the action tree

    let action_tree: MerkleTree =
        MerkleTree::new(vec![burned_resource_nullifier, created_resource_commitment]);

    ////////////////////////////////////////////////////////////////////////////
    // Create compliance proof

    let compliance_witness = ComplianceWitness::from_resources_with_path(
        burned_resource,
        burner_nf_key.clone(),
        merkle_proof,
        created_resource,
    );

    // generate the proof in a separate thread
    let compliance_witness_clone = compliance_witness.clone();
    let compliance_unit =
        thread::spawn(move || ComplianceUnit::create(&compliance_witness_clone.clone()))
            .join()
            .map_err(|e| {
                println!("prove thread panic: {:?}", e);
                ComplianceUnitCreateError
            })?
            .map_err(|e| {
                println!("proving error: {:?}", e);
                ComplianceUnitCreateError
            })?;

    ////////////////////////////////////////////////////////////////////////////
    // Create logic proof

    let created_resource_path = action_tree
        .generate_path(&created_resource_commitment)
        .map_err(|_| ActionTreeError)?;

    let burned_resource_path = action_tree
        .generate_path(&burned_resource_nullifier)
        .map_err(|_| ActionTreeError)?;

    let created_logic_witness: TransferLogic = TransferLogic::consume_persistent_resource_logic(
        burned_resource,
        burned_resource_path,
        burner_nf_key.clone(),
        burner_auth_verifying_key,
        auth_signature,
    );

    // generate the proof in a separate thread
    // this is due to bonsai being non-blocking or something. there is a feature flag for bonsai
    // that allows it to be non-blocking or vice versa, but this is to figure out.
    let created_logic_witness_clone = created_logic_witness.clone();
    let created_logic_proof = thread::spawn(move || created_logic_witness_clone.prove())
        .join()
        .map_err(|e| {
            println!("prove thread panic: {:?}", e);
            LogicProofCreateError
        })?
        .map_err(|e| {
            println!("proving error: {:?}", e);
            LogicProofCreateError
        })?;

    let burned_logic_witness: TransferLogic = TransferLogic::burn_resource_logic(
        created_resource,
        created_resource_path,
        config.forwarder_address.to_vec(),
        config.token_address.to_vec(),
        burner_address.to_vec(),
    );

    // generate the proof in a separate thread
    // this is due to bonsai being non-blocking or something. there is a feature flag for bonsai
    // that allows it to be non-blocking or vice versa, but this is to figure out.
    let burned_resource_logic_clone = burned_logic_witness.clone();
    let burned_logic_proof = thread::spawn(move || burned_resource_logic_clone.prove())
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
        vec![compliance_unit],
        vec![burned_logic_proof, created_logic_proof],
    )
    .map_err(|_| ActionError)?;

    let delta_witness =
        DeltaWitness::from_bytes(&compliance_witness.rcv).map_err(|_| LogicProofCreateError)?;
    let transaction = Transaction::create(vec![action], Delta::Witness(delta_witness));

    let transaction = transaction
        .generate_delta_proof()
        .map_err(|_| DeltaProofCreateError)?;

    verify_transaction(transaction.clone())?;
    Ok(transaction)
}
