use crate::errors::TransactionError;
use crate::errors::TransactionError::{
    ActionError, ActionTreeError, ComplianceUnitCreateError, DecodingError, DeltaProofCreateError,
    EncodingError, InvalidKeyChain, InvalidNullifierSizeError, LogicProofCreateError,
    MerklePathError,
};
use crate::examples::mint::value_ref_ephemeral_mint;
use crate::examples::shared::{
    create_permit_signature, label_ref, random_nonce, read_address, read_private_key,
    value_ref_created, verify_transaction,
};
use crate::requests::resource::JsonResource;
use crate::requests::Expand;
use crate::user::Keychain;
use crate::AnomaPayConfig;
use alloy::primitives::U256;
use arm::action::Action;
use arm::action_tree::MerkleTree;
use arm::compliance::{ComplianceWitness, INITIAL_ROOT};
use arm::compliance_unit::ComplianceUnit;
use arm::delta_proof::DeltaWitness;
use arm::logic_proof::LogicProver;
use arm::nullifier_key::NullifierKey;
use arm::resource::Resource;
use arm::transaction::{Delta, Transaction};
use arm::utils::{bytes_to_words, words_to_bytes};
use arm::Digest;
use k256::AffinePoint;
use serde::{Deserialize, Serialize};
use serde_json::to_string_pretty;
use serde_with::base64::Base64;
use serde_with::serde_as;
use std::thread;
use transfer_library::TransferLogic;

/// Defines the payload sent to the API to execute a minting request on /api/minting.
#[serde_as]
#[derive(Deserialize, Serialize, Debug, PartialEq)]
pub struct CreateRequest {
    pub consumed_resource: JsonResource,
    pub created_resource: JsonResource,
    #[serde_as(as = "Base64")]
    pub latest_cm_tree_root: Vec<u8>,
    #[serde_as(as = "Base64")]
    pub consumed_nf_key: Vec<u8>,
    #[serde_as(as = "Base64")]
    pub forwarder_addr: Vec<u8>,
    #[serde_as(as = "Base64")]
    pub token_addr: Vec<u8>,
    #[serde_as(as = "Base64")]
    pub user_addr: Vec<u8>,
    #[serde_as(as = "Base64")]
    pub permit_nonce: Vec<u8>,
    #[serde_as(as = "Base64")]
    pub permit_deadline: Vec<u8>,
    #[serde_as(as = "Base64")]
    pub permit_sig: Vec<u8>,
    pub created_discovery_pk: AffinePoint,
    pub created_encryption_pk: AffinePoint,
}

/// Creates a json string for a mint request example.
pub async fn json_example_mint_request(
    config: &AnomaPayConfig,
) -> Result<String, TransactionError> {
    let private_key = read_private_key();
    let address = read_address();
    let alice = Keychain::alice(address, Some(private_key));

    let create_request = mint_request_example(alice, config.default_amount as u128, config).await?;
    let json_str = to_string_pretty(&create_request).map_err(|_| EncodingError)?;
    Ok(json_str)
}

/// Creates an example of a mint request
pub async fn mint_request_example(
    minter: Keychain,
    amount: u128,
    config: &AnomaPayConfig,
) -> Result<CreateRequest, TransactionError> {
    // A minting transaction does not consume existing resources, so there is no need to get the
    // commitment tree root for anything, and the initial root can be used.
    let latest_commitment_tree_root: Vec<u32> = INITIAL_ROOT.as_words().to_vec();

    ////////////////////////////////////////////////////////////////////////////
    // Construct the ephemeral resource

    let nonce = random_nonce();
    let consumed_resource = Resource {
        logic_ref: TransferLogic::verifying_key(),
        label_ref: label_ref(config),
        quantity: amount,
        value_ref: value_ref_ephemeral_mint(&minter),
        is_ephemeral: true,
        nonce,
        nk_commitment: minter.nf_key.commit(),
        rand_seed: random_nonce(),
    };

    // create the nullifier for the created resource.
    // why do we use the nullifier based on the nullifier key from the minter here?
    // I presume because we used the commitment based off of this key for the ephemeral resource.
    // therefore the nullifier for the ephemeral resource is also derived from the nullifier key?
    let consumed_resource_nullifier = consumed_resource
        .nullifier(&minter.nf_key)
        .map_err(|_| InvalidKeyChain)?;

    ////////////////////////////////////////////////////////////////////////////
    // Construct the created resource

    // The nonce for the created resource must be the consumed resource's nullifier. The consumed
    // resource is the ephemeral resource that was created above.
    let nonce = consumed_resource_nullifier
        .as_bytes()
        .try_into()
        .map_err(|_| InvalidNullifierSizeError)?;

    let created_resource = Resource {
        logic_ref: TransferLogic::verifying_key(),
        label_ref: label_ref(config),
        quantity: amount,
        value_ref: value_ref_created(&minter),
        is_ephemeral: false,
        nonce,
        nk_commitment: minter.nf_key.commit(),
        rand_seed: [6u8; 32],
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

    let permit_signature = create_permit_signature(
        &minter_private_key,
        action_tree.clone(),
        nullifier,
        amount,
        config,
    )
    .await;

    Ok(CreateRequest {
        consumed_resource: consumed_resource.simplify(),
        created_resource: created_resource.simplify(),
        latest_cm_tree_root: words_to_bytes(latest_commitment_tree_root.as_slice()).to_vec(),
        consumed_nf_key: minter.nf_key.inner().to_vec(),
        forwarder_addr: config.forwarder_address.to_vec(),
        token_addr: config.token_address.to_vec(),
        user_addr: minter.evm_address.to_vec(),
        permit_nonce: nonce.to_vec(),
        permit_deadline: U256::from(config.deadline).to_be_bytes_vec(),
        permit_sig: permit_signature.as_bytes().to_vec(),
        created_discovery_pk: minter.discovery_pk,
        created_encryption_pk: minter.encryption_pk,
    })
}

/// Hanldes a mint request
pub fn mint_from_request(
    request: CreateRequest,
    config: &AnomaPayConfig,
) -> Result<(Resource, Transaction), TransactionError> {
    let created_resource: Resource =
        Expand::expand(request.created_resource).map_err(|_| DecodingError)?;
    let consumed_resource: Resource =
        Expand::expand(request.consumed_resource).map_err(|_| DecodingError)?;
    let consumed_nf_key: NullifierKey =
        NullifierKey::from_bytes(request.consumed_nf_key.as_slice());

    let created_resource_commitment = created_resource.commitment();
    let consumed_resource_nullifier: Digest = consumed_resource
        .nullifier(&consumed_nf_key)
        .map_err(|_| InvalidKeyChain)?;

    let latest_commitment_tree_root: Digest =
        bytes_to_words(request.latest_cm_tree_root.as_slice())
            .try_into()
            .map_err(|_| DecodingError)?;

    let user_address = request.user_addr;
    let nonce = request.permit_nonce;

    let permit_signature = request.permit_sig;
    let discovery_pk: AffinePoint = request.created_discovery_pk;
    let encryption_pk: AffinePoint = request.created_encryption_pk;

    ////////////////////////////////////////////////////////////////////////////
    // Create the action tree

    let action_tree: MerkleTree = MerkleTree::new(vec![
        consumed_resource_nullifier,
        created_resource_commitment,
    ]);

    ////////////////////////////////////////////////////////////////////////////
    // Create compliance proof

    let compliance_witness = ComplianceWitness::from_resources(
        consumed_resource,
        latest_commitment_tree_root,
        consumed_nf_key.clone(),
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

    let consumed_resource_path = action_tree
        .generate_path(&consumed_resource_nullifier)
        .map_err(|_| MerklePathError)?;

    let consumed_logic_witness: TransferLogic = TransferLogic::mint_resource_logic_with_permit(
        consumed_resource,
        consumed_resource_path,
        consumed_nf_key,
        config.forwarder_address.to_vec(),
        config.token_address.to_vec(),
        user_address,
        nonce.to_vec(),
        U256::from(config.deadline).to_be_bytes_vec(),
        permit_signature,
    );

    // generate the proof in a separate thread
    let consumed_logic_witness_clone = consumed_logic_witness.clone();
    let consumed_logic_proof = thread::spawn(move || consumed_logic_witness_clone.prove())
        .join()
        .map_err(|e| {
            println!("prove thread panic: {:?}", e);
            LogicProofCreateError
        })?
        .map_err(|e| {
            println!("proving error: {:?}", e);
            LogicProofCreateError
        })?;

    let created_resource_path = action_tree
        .generate_path(&created_resource_commitment)
        .map_err(|_| ActionTreeError)?;

    let created_logic_witness = TransferLogic::create_persistent_resource_logic(
        created_resource,
        created_resource_path,
        &discovery_pk,
        encryption_pk,
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

    ////////////////////////////////////////////////////////////////////////////
    // Create actions for transaction

    let action: Action = Action::new(
        vec![compliance_unit],
        vec![consumed_logic_proof, created_logic_proof],
    )
    .map_err(|_| ActionError)?;

    let delta_witness =
        DeltaWitness::from_bytes(&compliance_witness.rcv).map_err(|_| LogicProofCreateError)?;
    let transaction = Transaction::create(vec![action], Delta::Witness(delta_witness));

    let transaction = transaction
        .generate_delta_proof()
        .map_err(|_| DeltaProofCreateError)?;

    verify_transaction(transaction.clone())?;
    Ok((created_resource, transaction))
}
