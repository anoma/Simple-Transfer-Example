#[cfg(test)]
mod tests {
    use crate::evm::evm_calls::pa_submit_and_await;
    use crate::examples::end_to_end::burn::create_burn_transaction;
    use crate::examples::end_to_end::mint::create_mint_transaction;
    use crate::examples::end_to_end::split::create_split_transaction;
    use crate::examples::end_to_end::transfer::create_transfer_transaction;
    use crate::tests::fixtures::alice_keychain;
    use crate::user::Keychain;
    use crate::{load_config, AnomaPayConfig};
    use evm_protocol_adapter_bindings::ProtocolAdapter;

    use alloy::network::EthereumWallet;
    use alloy::node_bindings::Anvil;
    use alloy::primitives::address;
    use alloy::providers::{Provider, ProviderBuilder};
    use alloy::signers::local::PrivateKeySigner;
    use arm::resource::Resource;
    use arm::transaction::Transaction;
    use reqwest::Url;

    // time to wait for a transaction to be confirmed

    /// Run all the scenarios in sequence.
    /// Rust tests run in parallel by default and this gums up the works.
    /// This functions forces the tests to run in sequence.
    #[tokio::test]
    async fn run_scenarios() {
        let config = load_config().expect("failed to load config in test");

        let fork_url: Url = (config.ethereum_rpc.clone() + config.ethereum_rpc_api_key.as_str())
            .parse()
            .unwrap();

        let anvil = Anvil::new().fork(fork_url).spawn();
        let wallet: EthereumWallet = PrivateKeySigner::from(anvil.keys()[0].clone()).into();

        let anvil_provider = ProviderBuilder::new()
            .wallet(&wallet)
            .connect_http(anvil.endpoint().parse().unwrap());

        // TODO Add protocol adapter address to config.
        let pa_instance = ProtocolAdapter::new(
            address!("0x375920798465eb6b845AC5BF8580d69ce0Bda34a"),
            &anvil_provider,
        );

        // TODO Use this forwarder instead of the one in the config.
        /*let fwd_instance = ERC20Forwarder::deploy(
            &anvil_provider,
            *pa_instance.address(),
            B256::from_slice(SIMPLE_TRANSFER_ID.as_bytes()),
            wallet.default_signer().address(),
        )
        .await
        .unwrap();*/

        // create a keychain with a private key
        let alice = alice_keychain();

        // test a simple mint transfer
        test_mint(&config, &alice, &pa_instance).await;

        // Note: Commented out because they don't work without the indexer.
        // let bob = bob_keychain();
        // test a mint and transfer
        //test_mint_and_transfer(&config, &alice, &bob).await;

        // test minting and then splitting
        //test_mint_and_split(&config, &alice, &bob).await;

        // test minting and burning
        //test_mint_and_burn(&config, &alice).await;

        // test mint, split and then burn
        //test_mint_and_split_and_burn(&config, &alice, &bob).await;
    }

    ////////////////////////////////////////////////////////////////////////////
    // Scenarios

    /// Create a mint transaction, and then transfer the resource to another user.
    async fn test_mint(
        config: &AnomaPayConfig,
        alice: &Keychain,
        pa_instance: &ProtocolAdapter::ProtocolAdapterInstance<impl Provider>,
    ) {
        // create a test mint transaction for alice
        let (minted_resource, tx) = create_test_mint_transaction(&config, &alice).await;
        println!("Resource: {:?}", minted_resource);
        println!("Commitment: {:?}", minted_resource.commitment());

        // submit the transaction
        let receipt = pa_instance
            .execute(tx.into())
            .send()
            .await
            .expect("failed to submit transaction")
            .get_receipt()
            .await
            .expect("failed to get receipt");

        println!("receipt {:?}", receipt);
    }

    /// Create a mint transaction, and then transfer the resource to another user.
    async fn test_mint_and_transfer(config: &AnomaPayConfig, alice: &Keychain, bob: &Keychain) {
        // create a test mint transaction for alice
        let (minted_resource, transaction) = create_test_mint_transaction(&config, &alice).await;
        // try and submit the transaction
        submit_test_transaction(transaction, WAIT_TIME).await;

        // create a test transfer function from bob to alice
        let transaction =
            create_test_transfer_transaction(&config, alice, bob, minted_resource).await;
        // try and submit the transaction
        submit_test_transaction(transaction, 0).await;
    }

    /// Create a mint transaction, and then split the resource between the minter and another
    /// person.
    async fn test_mint_and_split(config: &AnomaPayConfig, alice: &Keychain, bob: &Keychain) {
        // create a test mint transaction for alice
        let (minted_resource, transaction) = create_test_mint_transaction(&config, &alice).await;
        // try and submit the transaction
        submit_test_transaction(transaction, WAIT_TIME).await;

        // create a test split transaction function from bob to alice.
        // alice gets 1, and bob gets 1 too.
        let (_resource, _remainder_resource, transaction) =
            create_test_split_transaction(&config, &alice, &bob, minted_resource, 1).await;
        // try and submit the transaction
        submit_test_transaction(transaction, 0).await;
    }

    /// Create a mint transaction, and then split the resource between the minter and another
    /// person. Burn the remainder resource afterward.
    async fn test_mint_and_split_and_burn(
        config: &AnomaPayConfig,
        alice: &Keychain,
        bob: &Keychain,
    ) {
        // create a test mint transaction for alice
        let (minted_resource, transaction) = create_test_mint_transaction(&config, &alice).await;
        // try and submit the transaction
        submit_test_transaction(transaction, WAIT_TIME).await;

        // create a test split transaction from bob to alice
        let (_resource, remainder_resource, transaction) =
            create_test_split_transaction(&config, &alice, &bob, minted_resource, 1).await;
        // try and submit the transaction
        submit_test_transaction(transaction, WAIT_TIME).await;

        // create a burn transfer for alice's remainder resource.
        let transaction = create_test_burn_transaction(&config, &alice, remainder_resource).await;
        // try and submit the transaction
        submit_test_transaction(transaction, 0).await;
    }

    /// Create a mint transaction, and then burn the resource.
    async fn test_mint_and_burn(config: &AnomaPayConfig, alice: &Keychain) {
        // create a test mint transaction for alice
        let (minted_resource, transaction) = create_test_mint_transaction(&config, &alice).await;
        // try and submit the transaction
        submit_test_transaction(transaction, WAIT_TIME).await;

        // create a test burn transaction
        let transaction = create_test_burn_transaction(&config, &alice, minted_resource).await;
        // try and submit the transaction
        submit_test_transaction(transaction, 0).await;
    }

    ////////////////////////////////////////////////////////////////////////////
    // Helpers

    /// Create a new transfer transaction, transferring the resource from sender to receiver.
    async fn create_test_transfer_transaction(
        config: &AnomaPayConfig,
        sender: &Keychain,
        receiver: &Keychain,
        resource: Resource,
    ) -> Transaction {
        // create a transfer transaction
        let result = create_transfer_transaction(
            sender.clone(),
            receiver.clone(),
            resource.clone(),
            &config,
        )
        .await;
        assert!(result.is_ok());

        let (_transferred_resource, transaction) = result.unwrap();
        transaction
    }

    /// Creates a mint transaction for the given keychain and verifies it.
    async fn create_test_mint_transaction(
        config: &AnomaPayConfig,
        minter: &Keychain,
    ) -> (Resource, Transaction) {
        // create the transaction and assert it did not fail.
        let result = create_mint_transaction(minter.clone(), 2, &config).await;
        println!("{:?}", result);
        assert!(result.is_ok());

        // assert the created transaction verifies
        let (minted_resource, transaction) = result.unwrap();
        assert!(transaction.clone().verify().is_ok());
        (minted_resource, transaction)
    }

    /// Create a burn transaction for the given resource.
    async fn create_test_burn_transaction(
        config: &AnomaPayConfig,
        burner: &Keychain,
        resource: Resource,
    ) -> Transaction {
        // create the transaction and assert it did not fail.
        let result = create_burn_transaction(burner.clone(), resource, &config).await;
        assert!(result.is_ok());

        // assert the created transaction verifies
        let (_burned_resource, transaction) = result.unwrap();
        assert!(transaction.clone().verify().is_ok());
        transaction
    }

    /// Creates a mint transaction for the given keychain and verifies it.
    async fn create_test_split_transaction(
        config: &AnomaPayConfig,
        sender: &Keychain,
        receiver: &Keychain,
        resource: Resource,
        amount: u128,
    ) -> (Resource, Resource, Transaction) {
        // create the transaction and assert it did not fail.
        let result =
            create_split_transaction(sender.clone(), receiver.clone(), resource, amount, &config)
                .await;
        assert!(result.is_ok());

        // assert the created transaction verifies
        let (sent_resource, created_resource, transaction) = result.unwrap();
        assert!(transaction.clone().verify().is_ok());
        (sent_resource, created_resource, transaction)
    }

    /// Given a transaction, submits it to the PA and waits for it to complete.
    async fn submit_test_transaction(transaction: Transaction, wait: u64) {
        let result = pa_submit_and_await(transaction, wait).await;
        println!("{:?}", result);
        assert!(result.is_ok());
    }
}
