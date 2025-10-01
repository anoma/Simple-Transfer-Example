#[cfg(test)]
mod tests {
    use crate::requests::transfer::parse_json_transfer_request;

    const JSON_STR: &str = r#"
        {
          "transferred_resource": {
            "logic_ref": "+E8yGC3d26/WxfQ1V4w7sHtQqAFLJVHs6+uZFuJjnMU=",
            "label_ref": "+tUVxU3nScXpI1KLPhROAowKMgBfH4GdGsqEyaVpvzY=",
            "quantity": 10,
            "value_ref": "X6PmKmeD8+Dq+8GjtddPVCQMC8BSOFM9U70EL0eNJp4=",
            "is_ephemeral": false,
            "nonce": "HFsvztDwz2aQ9+4j52K6c7kb4g3M0PfIpKyNvNjE39g=",
            "nk_commitment": "6HhL3SfOK3dPlUrnfbnVd/jgm3nOAzFXRIkQiYnLgYY=",
            "rand_seed": "BgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgY="
          },
          "created_resource": {
            "logic_ref": "+E8yGC3d26/WxfQ1V4w7sHtQqAFLJVHs6+uZFuJjnMU=",
            "label_ref": "+tUVxU3nScXpI1KLPhROAowKMgBfH4GdGsqEyaVpvzY=",
            "quantity": 10,
            "value_ref": "oUURXaFm3Ae7+FJ7QEw2bxLz42lmlG256F8OKMEgj48=",
            "is_ephemeral": false,
            "nonce": "pVFIUA3rFZoH7LqzT0dnJIpy4XxkxNK6xRNQWYlLnFo=",
            "nk_commitment": "+nDL533/Q8QpIqn2KfutNgezcKU+jEF6lQElr7Ku9OA=",
            "rand_seed": "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc="
          },
          "sender_nf_key": "/IikJdlwW4NFCoyE/WG23TD4GVaP9vgFvOxYDoO9hXI=",
          "sender_verifying_key": "02BEF41483A7D9975C7A6690B9B628896DBF1DB2E903B6BB982ADA1B7B4678017B",
          "auth_signature": "xyysieY3XxTG5KxgNUdwTHL6LI35MkMxFFFFyouNtal/gVtYCULnrzy7SguBEDOM8tAK1M4a9OPCXotngO5pDA==",
          "receiver_discovery_pk": "03C7FDA83664E5DFB2B77AD72C640C793ED487CDA9965CC48EEF3A3C6D3B47EB60",
          "receiver_encryption_pk": "039FAFA29FDD286BBE3EBBDBFBF292CE32F3E03AACD7A22E254920F7F89DB518BE"
        }
        "#;

    #[test]
    fn parse_json() {
        let transfer_request = parse_json_transfer_request(JSON_STR);
        assert_ne!(transfer_request, None);
    }
    #[test]
    fn generate_json() {
        let transfer_request = parse_json_transfer_request(JSON_STR).unwrap();

        let json_string = serde_json::to_string(&transfer_request).unwrap();
        let transfer_request_readback = parse_json_transfer_request(json_string.as_str()).unwrap();
        assert_eq!(transfer_request, transfer_request_readback);
    }
}
