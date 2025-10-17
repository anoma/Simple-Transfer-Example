#[cfg(test)]
mod tests {
    use crate::evm::evm_calls::pa_submit_transaction;
    use crate::examples::end_to_end::burn::create_burn_transaction;
    use crate::examples::end_to_end::mint::create_mint_transaction;
    use crate::examples::end_to_end::split::create_split_transaction;
    use crate::examples::end_to_end::transfer::create_transfer_transaction;
    use crate::tests::fixtures::{alice_keychain, bob_keychain};
    use crate::user::Keychain;
    use crate::{load_config, AnomaPayConfig};
    use arm::resource::Resource;
    use arm::transaction::Transaction;
    use serial_test::serial;
    use std::thread::sleep;
    use std::time::Duration;
    ////////////////////////////////////////////////////////////////////////////
    // Scenarios

    #[tokio::test]
    #[serial]
    /// Create a mint transaction, and then transfer the resource to another user.
    async fn test_mint() {
        let config = load_config().expect("failed to load config in test");
        // create a keychain with a private key
        let alice = alice_keychain();

        // create a test mint transaction for alice
        let (minted_resource, transaction) = create_test_mint_transaction(&config, &alice).await;
        println!("{:?}", minted_resource);
        println!("{:?}", minted_resource.commitment());

        pa_submit_transaction(transaction)
            .await
            .expect("failed to submit mint transaction");
    }

    #[tokio::test]
    #[serial]
    /// Create a mint transaction, and then transfer the resource to another user.
    async fn test_mint_and_transfer() {
        let config = load_config().expect("failed to load config in test");
        // create a keychain with a private key
        let alice = alice_keychain();
        let bob = bob_keychain();

        // create a test mint transaction for alice
        let (minted_resource, transaction) = create_test_mint_transaction(&config, &alice).await;

        pa_submit_transaction(transaction)
            .await
            .expect("failed to submit mint transaction");

        // Give the indexer time to pick up the transaction. TODO! Remove in the future.
        sleep(Duration::from_secs(10));

        // create a test transfer function from bob to alice
        let transaction =
            create_test_transfer_transaction(&config, alice, bob, minted_resource).await;

        pa_submit_transaction(transaction)
            .await
            .expect("failed to submit transfer transaction");
    }

    #[tokio::test]
    #[serial]
    /// Create a mint transaction, and then split the resource between the minter and another
    /// person.
    async fn test_mint_and_split() {
        let config = load_config().expect("failed to load config in test");
        // create a keychain with a private key
        let alice = alice_keychain();
        let bob = bob_keychain();

        // create a test mint transaction for alice
        let (minted_resource, transaction) = create_test_mint_transaction(&config, &alice).await;

        pa_submit_transaction(transaction)
            .await
            .expect("failed to submit mint transaction");

        // Give the indexer time to pick up the transaction. TODO! Remove in the future.
        sleep(Duration::from_secs(10));

        // create a test split transaction function from bob to alice.
        // alice gets 1, and bob gets 1 too.
        let (_resource, _remainder_resource, transaction) =
            create_test_split_transaction(&config, &alice, &bob, minted_resource, 1).await;

        pa_submit_transaction(transaction)
            .await
            .expect("failed to submit split transaction");
    }

    #[tokio::test]
    #[serial]
    /// Create a mint transaction, and then split the resource between the minter and another
    /// person. Burn the remainder resource afterward.
    async fn test_mint_and_split_and_burn() {
        let config = load_config().expect("failed to load config in test");
        // create a keychain with a private key
        let alice = alice_keychain();
        let bob = bob_keychain();

        // create a test mint transaction for alice
        let (minted_resource, transaction) = create_test_mint_transaction(&config, &alice).await;

        pa_submit_transaction(transaction)
            .await
            .expect("failed to submit mint transaction");

        // Give the indexer time to pick up the transaction. TODO! Remove in the future.
        sleep(Duration::from_secs(10));

        // create a test split transaction from bob to alice
        let (_resource, remainder_resource, transaction) =
            create_test_split_transaction(&config, &alice, &bob, minted_resource, 1).await;

        pa_submit_transaction(transaction)
            .await
            .expect("failed to submit split transaction");

        // Give the indexer time to pick up the transaction. TODO! Remove in the future.
        sleep(Duration::from_secs(10));

        // create a burn transfer for alice's remainder resource.
        let transaction = create_test_burn_transaction(&config, &alice, remainder_resource).await;

        pa_submit_transaction(transaction)
            .await
            .expect("failed to submit burn transaction");
    }

    #[tokio::test]
    #[serial]
    /// Create a mint transaction, and then burn the resource.
    async fn test_mint_and_burn() {
        let config = load_config().expect("failed to load config in test");
        // create a keychain with a private key
        let alice = alice_keychain();

        // create a test mint transaction for alice
        let (minted_resource, transaction) = create_test_mint_transaction(&config, &alice).await;

        pa_submit_transaction(transaction)
            .await
            .expect("failed to submit mint transaction");

        // Give the indexer time to pick up the transaction. TODO! Remove in the future.
        sleep(Duration::from_secs(10));

        // create a test burn transaction
        let transaction = create_test_burn_transaction(&config, &alice, minted_resource).await;

        pa_submit_transaction(transaction)
            .await
            .expect("failed to submit burn transaction");
    }

    ////////////////////////////////////////////////////////////////////////////
    // Helpers

    /// Create a new transfer transaction, transferring the resource from sender to receiver.
    async fn create_test_transfer_transaction(
        config: &AnomaPayConfig,
        sender: Keychain,
        receiver: Keychain,
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

    /// Create a burn tranasction for the given resource.
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
}
