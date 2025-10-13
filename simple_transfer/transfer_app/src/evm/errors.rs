/// An error struct to signal an error occurred during the creation of a transaction.
#[derive(Debug, Clone)]
pub enum EvmError {
    EvmSubmitError,
    IndexerError,
}
