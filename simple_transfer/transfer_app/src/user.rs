use alloy::primitives::Address;
use alloy::signers::local::PrivateKeySigner;
use arm::authorization::{AuthorizationSigningKey, AuthorizationVerifyingKey};
use arm::encryption::{random_keypair, SecretKey};
use arm::nullifier_key::NullifierKey;
use k256::AffinePoint;

pub struct Keychain {
    pub auth_signing_key: AuthorizationSigningKey,
    pub nf_key: NullifierKey,
    pub discovery_sk: SecretKey,
    pub discovery_pk: AffinePoint,
    pub encryption_sk: SecretKey,
    pub encryption_pk: AffinePoint,
    pub evm_address: Address,
    pub private_key: Option<PrivateKeySigner>,
}

impl Keychain {
    // pub fn bob(private_key: Option<PrivateKeySigner>) -> Keychain {
    //     let evm_address = "0x44B73CbC3C2E902cD0768854c2ff914DD44a325F"
    //         .parse::<Address>()
    //         .unwrap();
    //
    //     let discovery_sk_bytes: [u8; 32] = [
    //         80, 35, 79, 155, 117, 210, 75, 68, 253, 197, 65, 105, 156, 112, 246, 55, 104, 248, 233,
    //         99, 118, 94, 175, 57, 215, 34, 142, 101, 221, 197, 125, 134,
    //     ];
    //     let discovery_sk: SecretKey = bincode::deserialize(discovery_sk_bytes.as_ref())
    //         .expect("failed to decode discovery_sk");
    //     let discovery_pk_bytes: [u8; 41] = [
    //         33, 0, 0, 0, 0, 0, 0, 0, 3, 199, 253, 168, 54, 100, 229, 223, 178, 183, 122, 215, 44,
    //         100, 12, 121, 62, 212, 135, 205, 169, 150, 92, 196, 142, 239, 58, 60, 109, 59, 71, 235,
    //         96,
    //     ];
    //     let discovery_pk: AffinePoint = bincode::deserialize(discovery_pk_bytes.as_ref())
    //         .expect("failed to decode discovery_pk");
    //     let encryption_sk_bytes: [u8; 32] = [
    //         3, 223, 24, 234, 86, 30, 71, 29, 67, 114, 113, 163, 192, 128, 27, 234, 123, 208, 82,
    //         217, 194, 163, 241, 86, 160, 112, 213, 207, 232, 51, 171, 229,
    //     ];
    //     let encryption_sk: SecretKey = bincode::deserialize(encryption_sk_bytes.as_ref())
    //         .expect("failed to decode encryption_sk");
    //     let encryption_pk_bytes: [u8; 41] = [
    //         33, 0, 0, 0, 0, 0, 0, 0, 3, 159, 175, 162, 159, 221, 40, 107, 190, 62, 187, 219, 251,
    //         242, 146, 206, 50, 243, 224, 58, 172, 215, 162, 46, 37, 73, 32, 247, 248, 157, 181, 24,
    //         190,
    //     ];
    //     let encryption_pk: AffinePoint = bincode::deserialize(encryption_pk_bytes.as_ref())
    //         .expect("failed to decode encryption_pk");
    //
    //     let nf_key_bytes: [u8; 40] = [
    //         32, 0, 0, 0, 0, 0, 0, 0, 4, 186, 116, 75, 43, 251, 203, 31, 218, 1, 102, 202, 204, 43,
    //         45, 168, 74, 243, 55, 12, 108, 47, 50, 4, 222, 221, 250, 200, 98, 157, 11, 235,
    //     ];
    //     let nf_key = bincode::deserialize(nf_key_bytes.as_ref()).expect("failed to decode nf_key");
    //
    //     let auth_signing_key_bytes: [u8; 40] = [
    //         32, 0, 0, 0, 0, 0, 0, 0, 193, 176, 17, 73, 49, 57, 37, 78, 14, 120, 53, 246, 36, 6, 77,
    //         41, 156, 32, 253, 212, 35, 9, 1, 75, 129, 160, 122, 155, 169, 255, 236, 229,
    //     ];
    //     let auth_signing_key: AuthorizationSigningKey =
    //         bincode::deserialize(auth_signing_key_bytes.as_ref())
    //             .expect("failed to decode auth_signing_key");
    //
    //     Keychain {
    //         auth_signing_key,
    //         nf_key,
    //         discovery_sk,
    //         discovery_pk,
    //         encryption_sk,
    //         encryption_pk,
    //         evm_address,
    //         private_key,
    //     }
    // }

    // pub fn alice(private_key: Option<PrivateKeySigner>) -> Keychain {
    //     let evm_address = "0x26aBD8C363f6Aa7FC4db989Ba4F34E7Bd5573A16"
    //         .parse::<Address>()
    //         .unwrap();
    //
    //     let discovery_sk_bytes: [u8; 32] = [
    //         186, 37, 174, 180, 152, 218, 143, 227, 232, 139, 212, 23, 5, 37, 204, 192, 80, 5, 200,
    //         38, 227, 161, 151, 76, 100, 54, 209, 12, 68, 80, 116, 86,
    //     ];
    //     let discovery_sk: SecretKey = bincode::deserialize(discovery_sk_bytes.as_ref())
    //         .expect("failed to decode discovery_sk");
    //     let discovery_pk_bytes: [u8; 41] = [
    //         33, 0, 0, 0, 0, 0, 0, 0, 2, 195, 180, 67, 36, 26, 151, 196, 203, 99, 86, 89, 140, 227,
    //         178, 52, 166, 89, 1, 221, 83, 139, 255, 82, 58, 236, 212, 33, 68, 93, 35, 208, 20,
    //     ];
    //     let discovery_pk: AffinePoint = bincode::deserialize(discovery_pk_bytes.as_ref())
    //         .expect("failed to decode discovery_pk");
    //     let encryption_sk_bytes: [u8; 32] = [
    //         15, 197, 146, 196, 80, 170, 20, 137, 32, 123, 75, 251, 16, 24, 222, 182, 90, 45, 253,
    //         193, 79, 102, 154, 57, 128, 19, 171, 59, 132, 182, 228, 53,
    //     ];
    //     let encryption_sk: SecretKey = bincode::deserialize(encryption_sk_bytes.as_ref())
    //         .expect("failed to decode encryption_sk");
    //     let encryption_pk_bytes: [u8; 41] = [
    //         33, 0, 0, 0, 0, 0, 0, 0, 3, 24, 59, 104, 88, 36, 232, 98, 176, 188, 177, 127, 177, 14,
    //         234, 9, 17, 205, 43, 162, 57, 177, 66, 119, 215, 70, 214, 54, 216, 9, 215, 224, 79,
    //     ];
    //     let encryption_pk: AffinePoint = bincode::deserialize(encryption_pk_bytes.as_ref())
    //         .expect("failed to decode encryption_pk");
    //
    //     let nf_key_bytes: [u8; 40] = [
    //         32, 0, 0, 0, 0, 0, 0, 0, 252, 136, 164, 37, 217, 112, 91, 131, 69, 10, 140, 132, 253,
    //         97, 182, 221, 48, 248, 25, 86, 143, 246, 248, 5, 188, 236, 88, 14, 131, 189, 133, 114,
    //     ];
    //     let nf_key = bincode::deserialize(nf_key_bytes.as_ref()).expect("failed to decode nf_key");
    //
    //     let auth_signing_key_bytes: [u8; 40] = [
    //         32, 0, 0, 0, 0, 0, 0, 0, 121, 163, 69, 102, 244, 108, 118, 2, 37, 56, 88, 232, 87, 251,
    //         123, 48, 61, 106, 78, 26, 151, 28, 25, 24, 72, 87, 165, 138, 196, 125, 201, 59,
    //     ];
    //     let auth_signing_key: AuthorizationSigningKey =
    //         bincode::deserialize(auth_signing_key_bytes.as_ref())
    //             .expect("failed to decode auth_signing_key");
    //
    //     Keychain {
    //         auth_signing_key,
    //         nf_key,
    //         discovery_sk,
    //         discovery_pk,
    //         encryption_sk,
    //         encryption_pk,
    //         evm_address,
    //         private_key,
    //     }
    // }

    pub fn new(evm_address: &str, private_key: Option<PrivateKeySigner>) -> Keychain {
        let evm_address = evm_address.parse::<Address>().unwrap();

        let (discovery_sk, discovery_pk) = random_keypair();
        let (encryption_sk, encryption_pk) = random_keypair();

        let auth_signing_key: AuthorizationSigningKey = AuthorizationSigningKey::new();
        let nf_key: NullifierKey = NullifierKey::random_pair().0;

        Keychain {
            auth_signing_key,
            nf_key,
            discovery_sk,
            discovery_pk,
            encryption_sk,
            encryption_pk,
            evm_address,
            private_key,
        }
    }

    pub fn auth_verifying_key(&self) -> AuthorizationVerifyingKey {
        AuthorizationVerifyingKey::from_signing_key(&self.auth_signing_key)
    }
}
