#[cfg(test)]
mod tests {
    const JSON_STR: &str = r#"
        {
          "consumed_resource": {
            "logic_ref": "+E8yGC3d26/WxfQ1V4w7sHtQqAFLJVHs6+uZFuJjnMU=",
            "label_ref": "+tUVxU3nScXpI1KLPhROAowKMgBfH4GdGsqEyaVpvzY=",
            "quantity": 10,
            "value_ref": "llwjaee3GjUyLVi4K/KLucFJg2NFs0aXpz/IHwhDii4=",
            "is_ephemeral": true,
            "nonce": "zoZtj8t71SB4JRP2E5lBaf5IKgsmkfYi1EH//T6cEXI=",
            "nk_commitment": "6HhL3SfOK3dPlUrnfbnVd/jgm3nOAzFXRIkQiYnLgYY=",
            "rand_seed": "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc="
          },
          "created_resource": {
            "logic_ref": "+E8yGC3d26/WxfQ1V4w7sHtQqAFLJVHs6+uZFuJjnMU=",
            "label_ref": "+tUVxU3nScXpI1KLPhROAowKMgBfH4GdGsqEyaVpvzY=",
            "quantity": 10,
            "value_ref": "X6PmKmeD8+Dq+8GjtddPVCQMC8BSOFM9U70EL0eNJp4=",
            "is_ephemeral": false,
            "nonce": "mglCyZMw9fFJOW6HebPA2Ez1wKR0KUzWB+wHSoRjFMo=",
            "nk_commitment": "6HhL3SfOK3dPlUrnfbnVd/jgm3nOAzFXRIkQiYnLgYY=",
            "rand_seed": "BgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgY="
          },
          "latest_cm_tree_root": "zB0vg4RF23rsQx357oqHH0Dnql4GT8BWYz74xg+rewY=",
          "consumed_nf_key": "/IikJdlwW4NFCoyE/WG23TD4GVaP9vgFvOxYDoO9hXI=",
          "forwarder_addr": "CXEeJKN0hZFiTS5XW7G9h9uH78g=",
          "token_addr": "HH1LGWywx7AddD+8YRapAjeccjg=",
          "user_addr": "JqvYw2P2qn/E25ibpPNOe9VXOhY=",
          "permit_nonce": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHs=",
          "permit_deadline": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHDb2IA=",
          "permit_sig": "UaPxmNdsBIugpN9WM/nwvXLDb02CdiHWlQxLS5uykGcdsuw9EsQ0/mK6iQ5/QOGaA6c1vwnHnx8Y+unX+60X5Bs=",
          "created_discovery_pk": "02C3B443241A97C4CB6356598CE3B234A65901DD538BFF523AECD421445D23D014",
          "created_encryption_pk": "03183B685824E862B0BCB17FB10EEA0911CD2BA239B14277D746D636D809D7E04F"
        }
        "#;

    use crate::requests::mint::parse_json_request;

    #[test]
    fn parse_json() {
        let create_request = parse_json_request(JSON_STR);
        assert_ne!(create_request, None);
    }
    #[test]
    fn generate_json() {
        let create_request = parse_json_request(JSON_STR).unwrap();

        let json_string = serde_json::to_string(&create_request).unwrap();
        let create_request_readback = parse_json_request(json_string.as_str()).unwrap();
        assert_eq!(create_request, create_request_readback);
    }
}
