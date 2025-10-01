use crate::evm::get_merkle_path;
use crate::requests::resource::{request_resource_to_resource, resource_to_request_resource};
use crate::requests::transfer::TransferRequest;
use crate::user::Keychain;
use crate::{AMOUNT, ERC20, FORWARDER_ADDRESS};
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
use arm::utils::{hash_bytes, words_to_bytes};
use transfer_library::TransferLogic;

pub fn create_transfer_json_request(
    bob: Keychain,
    alice: Keychain,
    consumed_resource: Resource,
) -> TransferRequest {
    // the nullifier of the resource is necessary to transfer it.
    let consumed_nf = consumed_resource
        .nullifier(&alice.nf_key)
        .expect("failed to create nullifier from alice's key");

    // create a resource for bob
    let label_ref = hash_bytes(&[FORWARDER_ADDRESS.to_vec(), ERC20.to_vec()].concat());

    let created_resource = Resource {
        logic_ref: TransferLogic::verifying_key_as_bytes(),
        label_ref: label_ref.clone(),
        quantity: AMOUNT as u128,
        value_ref: hash_bytes(&bob.auth_verifying_key().to_bytes()),
        is_ephemeral: false,
        nonce: consumed_nf.clone().as_bytes().to_vec(),
        nk_commitment: bob.nf_key.commit(),
        rand_seed: vec![7u8; 32],
    };

    let created_cm = created_resource.commitment();

    ////////////////////////////////////////////////////////////////////////////
    // Create the action tree

    let action_tree: MerkleTree = MerkleTree::new(vec![consumed_nf, created_cm]);

    ////////////////////////////////////////////////////////////////////////////
    // Create the permit signature

    let action_tree_root: Vec<u32> = action_tree.root();
    let auth_signature: AuthorizationSignature = alice
        .auth_signing_key
        .sign(words_to_bytes(&action_tree_root));

    TransferRequest {
        transferred_resource: resource_to_request_resource(consumed_resource),
        created_resource: resource_to_request_resource(created_resource),
        sender_nf_key: alice.nf_key.inner().to_vec(),
        sender_verifying_key: alice.auth_verifying_key().as_affine().clone(),
        auth_signature: auth_signature.to_bytes().to_vec(),
        receiver_discovery_pk: bob.discovery_pk,
        receiver_encryption_pk: bob.encryption_pk,
    }
}

pub fn transfer_from_json_request(transfer_request: TransferRequest) -> Transaction {
    // convert some bytes into their proper data structure from the request.
    let consumed_resource = request_resource_to_resource(transfer_request.transferred_resource);

    let created_resource = request_resource_to_resource(transfer_request.created_resource);

    let sender_nf_key: NullifierKey =
        NullifierKey::from_bytes(transfer_request.sender_nf_key.as_slice());

    let sender_verifying_key: AuthorizationVerifyingKey =
        AuthorizationVerifyingKey::from_affine(transfer_request.sender_verifying_key);

    let auth_signature: AuthorizationSignature =
        AuthorizationSignature::from_bytes(transfer_request.auth_signature.as_slice());

    let receiver_discovery_pk = transfer_request.receiver_discovery_pk;

    let receiver_encryption_pk = transfer_request.receiver_encryption_pk;

    ////////////////////////////////////////////////////////////////////////////
    // Get the merkle proof for the resource being transferred

    let merkle_proof = get_merkle_path(consumed_resource.commitment());

    ////////////////////////////////////////////////////////////////////////////
    // Create compliance proof

    let compliance_witness = ComplianceWitness::from_resources_with_path(
        consumed_resource.clone(),
        sender_nf_key.clone(),
        merkle_proof,
        created_resource.clone(),
    );
    let compliance_unit = ComplianceUnit::create(&compliance_witness);

    ////////////////////////////////////////////////////////////////////////////
    // Create the action tree
    let consumed_nf = consumed_resource
        .nullifier(&sender_nf_key)
        .expect("failed to create nullifier from sender's key");

    let created_cm = created_resource.commitment();
    let action_tree: MerkleTree = MerkleTree::new(vec![consumed_nf, created_cm]);

    ////////////////////////////////////////////////////////////////////////////
    // Create logic proof

    let consumed_resource_path = action_tree
        .generate_path(&consumed_nf)
        .expect("failed to generate path for consumed resource");

    let consumed_logic_witness: TransferLogic = TransferLogic::consume_persistent_resource_logic(
        consumed_resource.clone(),
        consumed_resource_path,
        sender_nf_key.clone(),
        sender_verifying_key,
        auth_signature,
    );

    let consumed_logic_proof = consumed_logic_witness.prove();

    let created_resource_path = action_tree
        .generate_path(&created_cm)
        .expect("failed to generate path for resource");

    let created_logic_witness: TransferLogic = TransferLogic::create_persistent_resource_logic(
        created_resource.clone(),
        created_resource_path,
        &receiver_discovery_pk,
        receiver_encryption_pk,
    );

    let created_logic_proof = created_logic_witness.prove();

    ////////////////////////////////////////////////////////////////////////////
    // Create actions for transaction

    let action: Action = Action::new(
        vec![compliance_unit],
        vec![consumed_logic_proof, created_logic_proof],
    );

    let delta_witness: DeltaWitness = DeltaWitness::from_bytes(&compliance_witness.rcv);
    let mut tx: Transaction = Transaction::create(vec![action], Delta::Witness(delta_witness));
    tx.generate_delta_proof();

    tx
}
