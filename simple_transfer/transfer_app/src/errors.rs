/// An error struct to signal an error occurred during the creation of a transaction.
#[derive(Debug, Clone)]
pub enum TransactionError {
    InvalidKeyChain,
    MerklePathError,
    ActionTreeError,
    VerificationFailure,
    MerkleProofError,
    InvalidAmount,
    EncodingError,
    DecodingError,
    ActionError,
    ComplianceUnitCreateError,
    LogicProofCreateError,
    DeltaProofCreateError,
    InvalidNullifierSizeError,
}
