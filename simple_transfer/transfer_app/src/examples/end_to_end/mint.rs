use crate::errors::TransactionError;
use crate::errors::TransactionError::{ActionTreeError, InvalidKeyChain, MerklePathError};
use crate::examples::mint::value_ref_ephemeral_mint;
use crate::examples::shared::{
    create_permit_signature, label_ref, random_nonce, value_ref_created, verify_transaction,
};
use crate::user::Keychain;
use crate::AnomaPayConfig;
use alloy::primitives::U256;
use arm::action::Action;
use arm::action_tree::MerkleTree;
use arm::compliance::{ComplianceWitness, INITIAL_ROOT};
use arm::compliance_unit::ComplianceUnit;
use arm::delta_proof::DeltaWitness;
use arm::logic_proof::LogicProver;
use arm::resource::Resource;
use arm::transaction::{Delta, Transaction};
use arm::Digest;
use std::thread;
use transfer_library::TransferLogic;

// these can be dead code because they're used for development.
#[allow(dead_code)]
pub async fn create_mint_transaction(
    minter: Keychain,
    amount: u128,
    config: &AnomaPayConfig,
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

    let permit_signature = create_permit_signature(
        &minter_private_key,
        action_tree.clone(),
        nullifier,
        amount,
        config,
    )
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
