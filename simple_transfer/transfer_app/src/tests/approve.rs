#[cfg(test)]
mod tests {
    use alloy::primitives::address;
    use crate::examples::approve::is_address_approved;
    use crate::load_config;

    /// Given an address that should not be approved on the permit2 contract, verify that it
    /// returns false.
    ///
    /// Should this test fail, make sure that the allowance is indeed 0.
    /// For the sepolia testnet look at the read proxy for the contract here:
    /// https://sepolia.etherscan.io/address/0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238#readProxyContract
    /// The owner is `unapproved_address` and the spender is the permit2 contract address.
    #[tokio::test]
    async fn test_unapproved() {
        let config = load_config().expect("failed to load config in test");
        // create a keychain with a private key
        let unapproved_address = address!("0x44B73CbC3C2E902cD0768854c2ff914DD44a325F");

        // assert this address is unapproved.
        let is_approved = is_address_approved(unapproved_address, &config).await;
        assert!(is_approved.is_ok());
        let is_approved = is_approved.unwrap();

        assert_ne!(is_approved, true);
    }

    /// Given an address that should be approved on the permit2 contract, verify that it
    /// returns true.
    #[tokio::test]
    async fn test_approved() {
        let config = load_config().expect("failed to load config in test");
        let approved_address = address!("0x26aBD8C363f6Aa7FC4db989Ba4F34E7Bd5573A16");

        // assert this address is unapproved.
        let is_approved = is_address_approved(approved_address, &config).await;
        assert!(is_approved.is_ok());
        let is_approved = is_approved.unwrap();

        assert!(is_approved);
    }
}
