use base32::{Alphabet, decode, encode};

pub trait ToBase32 {
    fn to_base32(&self) -> String;
}

impl<T> ToBase32 for T
where
    T: AsRef<[u8]>,
{
    fn to_base32(&self) -> String {
        encode(Alphabet::Rfc4648Lower { padding: false }, self.as_ref())
    }
}

pub trait FromBase32: Sized {
    fn from_base32<T: AsRef<[u8]>>(base64: T) -> Option<Self>;
}

impl FromBase32 for Vec<u8> {
    // TODO(DID): This base32 library SUCKS compared to b64
    fn from_base32<T: AsRef<[u8]>>(base32: T) -> Option<Self> {
        let bytes = str::from_utf8(base32.as_ref());
        if bytes.is_err() {
            return None;
        }
        decode(Alphabet::Rfc4648Lower { padding: false }, bytes.unwrap())
    }
}
