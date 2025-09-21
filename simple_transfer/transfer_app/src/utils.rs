use arm::{
    action_tree::MerkleTree,
    authorization::{AuthorizationSignature, AuthorizationSigningKey},
    utils::words_to_bytes,
};

pub fn authorize_the_action(
    auth_sk: &AuthorizationSigningKey,
    action_tree: &MerkleTree,
) -> AuthorizationSignature {
    let action_tree_root = action_tree.root();
    auth_sk.sign(words_to_bytes(&action_tree_root))
}


use alloy::primitives::{Address, U256, keccak256};
use alloy::sol_types::{Eip712Domain, SolStruct};
use k256::ecdsa::SigningKey;
use sha3::{Digest, Keccak256};

// Define the Permit2 structs for EIP-712
alloy::sol! {
    #[derive(Debug)]
    struct PermitTransferFrom {
        address token;
        uint256 amount;
        uint256 nonce;
        uint256 deadline;
        address spender;
    }
    
    /// EIP-712 PermitWitnessTransferFrom struct
    struct PermitWitnessTransferFrom {
        address spender;
        address token;
        uint256 amount;
        uint256 nonce;
        uint256 deadline;
        bytes32 witness; // This is the fixed function selector hash
        bytes data; // Your custom data, i.e., the action_tree_root
    }
}

pub fn generate_permit2_signature(
    private_key: [u8; 32],
    permit2_address: Address,
    token_address: Address,
    spender_address: Address,
    amount: U256,
    nonce: U256,
    deadline: U256,
    witness_data: Vec<u8>, // Action tree root as witness
    chain_id: u64,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
    // 1. Create the domain separator
    let domain = Eip712Domain {
        name: Some("Permit2".into()),
        version: Some("1".into()),
        chain_id: Some(U256::from(chain_id)),
        verifying_contract: Some(permit2_address),
        salt: None,
    };

    // 2. Create the permit witness struct with action tree root as witness
    let permit_witness = PermitWitnessTransferFrom {
        spender: spender_address,
        token: token_address,
        amount,
        nonce,
        deadline,
        witness: keccak256("witnessTransferFrom(address,address,uint256)"), // Fixed witness hash
        data: witness_data.into(), // Action tree root as data
    };

    // 3. Calculate the EIP-712 hash
    let struct_hash = permit_witness.eip712_hash_struct();
    let domain_hash = domain.hash_struct();
    
    let mut hasher = Keccak256::new();
    hasher.update(b"\x19\x01");
    hasher.update(domain_hash);
    hasher.update(struct_hash);
    let digest = hasher.finalize();

    // 4. Sign the hash with recovery
    let signing_key = SigningKey::from_bytes(&private_key.into())?;
    let (signature, recovery_id) = signing_key.sign_prehash_recoverable(&digest)?;

    // 5. Extract r, s, v components
    let r_bytes = signature.r().to_bytes();
    let s_bytes = signature.s().to_bytes();
    
    // Calculate v (recovery ID + 27 for EIP-155)
    let v = recovery_id.to_byte() + 27;

    Ok((r_bytes.to_vec(), s_bytes.to_vec(), vec![v]))
}

