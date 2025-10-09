use crate::evm::pa_merkle_path;
use crate::examples::mint::TransactionError;
use crate::examples::mint::TransactionError::{ActionTreeError, InvalidKeyChain, MerkleProofError};
use crate::examples::shared::{label_ref, random_nonce, value_ref, verify_transaction};
use crate::user::Keychain;
use crate::AnomaPayConfig;
use arm::action::Action;
use arm::action_tree::MerkleTree;
use arm::authorization::AuthorizationSignature;
use arm::compliance::ComplianceWitness;
use arm::compliance_unit::ComplianceUnit;
use arm::delta_proof::DeltaWitness;
use arm::evm::CallType;
use arm::logic_proof::LogicProver;
use arm::resource::Resource;
use arm::transaction::{Delta, Transaction};
use arm::utils::words_to_bytes;
use std::thread;
use transfer_library::TransferLogic;

/// The value ref for an ephemeral resource in a burn transaction has to hold the calltype. A
/// burning transaction means you create an ephemeral resource, and consume an non-ephemeral
/// resource. Therefore, the created ephemeral resource needs to have the unwrapping calltype.
fn value_ref_ephemeral_burn(burner: &Keychain) -> Vec<u8> {
    value_ref(CallType::Unwrap, burner.evm_address.as_ref())
}

// these can be dead code because they're used for development.
#[allow(dead_code)]
pub async fn create_burn_transaction(
    burner: Keychain,
    burned_resource: Resource,
    config: &AnomaPayConfig,
) -> Result<(Resource, Transaction), TransactionError> {
    // to burn a resource, we need the nullifier of that resource.
    let burned_resource_nullifier = burned_resource
        .nullifier(&burner.nf_key)
        .ok_or(InvalidKeyChain)?;

    ////////////////////////////////////////////////////////////////////////////
    // Construct the ephemeral resource to create

    let created_resource = Resource {
        logic_ref: TransferLogic::verifying_key_as_bytes(),
        label_ref: label_ref(config),
        quantity: burned_resource.quantity,
        value_ref: value_ref_ephemeral_burn(&burner),
        is_ephemeral: true,
        nonce: burned_resource_nullifier.clone().as_bytes().to_vec(),
        nk_commitment: burner.nf_key.commit(),
        rand_seed: random_nonce().to_vec(),
    };

    let created_resource_commitment = created_resource.commitment();

    ////////////////////////////////////////////////////////////////////////////
    // Create the action tree

    let action_tree: MerkleTree =
        MerkleTree::new(vec![burned_resource_nullifier, created_resource_commitment]);

    let action_tree_root: Vec<u32> = action_tree.root();

    ////////////////////////////////////////////////////////////////////////////
    // Create the permit signature

    let auth_signature: AuthorizationSignature = burner
        .auth_signing_key
        .sign(words_to_bytes(&action_tree_root));

    ////////////////////////////////////////////////////////////////////////////
    // Get the merkle proof for the resource being transferred

    let burned_resource_commitment = burned_resource.commitment();

    let merkle_proof = pa_merkle_path(burned_resource_commitment)
        .await
        .map_err(|_| MerkleProofError)?;

    ////////////////////////////////////////////////////////////////////////////
    // Create compliance proof

    let compliance_witness = ComplianceWitness::from_resources_with_path(
        burned_resource.clone(),
        burner.nf_key.clone(),
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

    let created_resource_path = action_tree
        .generate_path(&created_resource_commitment)
        .ok_or(ActionTreeError)?;

    let burned_resource_path = action_tree
        .generate_path(&burned_resource_nullifier)
        .ok_or(ActionTreeError)?;

    let created_logic_witness: TransferLogic = TransferLogic::consume_persistent_resource_logic(
        burned_resource.clone(),
        burned_resource_path,
        burner.nf_key.clone(),
        burner.auth_verifying_key(),
        auth_signature,
    );

    // generate the proof in a separate thread
    // this is due to bonsai being non-blocking or something. there is a feature flag for bonsai
    // that allows it to be non-blocking or vice versa, but this is to figure out.
    let created_logic_witness_clone = created_logic_witness.clone();
    let created_logic_proof = thread::spawn(move || created_logic_witness_clone.prove())
        .join()
        .unwrap();

    let burned_logic_witness: TransferLogic = TransferLogic::burn_resource_logic(
        created_resource.clone(),
        created_resource_path,
        config.forwarder_address.to_vec(),
        config.token_address.to_vec(),
        burner.evm_address.to_vec(),
    );

    // generate the proof in a separate thread
    // this is due to bonsai being non-blocking or something. there is a feature flag for bonsai
    // that allows it to be non-blocking or vice versa, but this is to figure out.
    let burned_resource_logic_clone = burned_logic_witness.clone();
    let burned_logic_proof = thread::spawn(move || burned_resource_logic_clone.prove())
        .join()
        .unwrap();

    ////////////////////////////////////////////////////////////////////////////
    // Create actions for transaction

    let action: Action = Action::new(
        vec![compliance_unit],
        vec![burned_logic_proof, created_logic_proof],
    );

    let delta_witness = DeltaWitness::from_bytes(&compliance_witness.rcv);
    let mut transaction = Transaction::create(vec![action], Delta::Witness(delta_witness));
    transaction.generate_delta_proof();

    verify_transaction(transaction.clone())?;
    Ok((created_resource, transaction))
}
