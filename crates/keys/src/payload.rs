use prism_serde::raw_or_b64;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{CryptoAlgorithm, Signature, VerifyingKey};

#[derive(Serialize, Deserialize, ToSchema)]
/// Data structure containing a cryptographic payload with algorithm and bytes
pub struct CryptoPayload {
    /// The cryptographic algorithm to be used
    pub algorithm: CryptoAlgorithm,
    /// The raw bytes of the cryptographic data
    #[schema(
        value_type = String,
        format = Byte,
        example = "jMaZEeHpjIrpO33dkS223jPhurSFixoDJUzNWBAiZKA")]
    #[serde(with = "raw_or_b64")]
    pub bytes: Vec<u8>,
}

impl TryFrom<String> for CryptoPayload {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.starts_with("did:key:") {
            let vk = VerifyingKey::from_did(&value)
                .expect("Failed to parse VerifyingKey from CryptoPayload");

            Ok(vk.into())
        } else {
            // TAG(DID)
            let sig = Signature::from_plc_signature(&value)
                .expect("Failed to parse Signature from CryptoPayload");
            Ok(sig.into())
        }
    }
}
