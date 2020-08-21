use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar as ScalarRepr,
};
use rand::{CryptoRng, RngCore};
use serde::{
    de::{SeqAccess, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};

struct ThirtyTwoBytesVisitor;

impl<'de> Visitor<'de> for ThirtyTwoBytesVisitor {
    type Value = [u8; 32];

    fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(formatter, "a bytestring of length 32")
    }

    fn visit_bytes<E>(self, b: &[u8]) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if b.len() == 32 {
            let mut buf = [0u8; 32];
            buf.copy_from_slice(b);
            Ok(buf)
        } else {
            Err(serde::de::Error::invalid_length(b.len(), &"32 bytes"))
        }
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut buf = [0u8; 32];
        for i in 0..32 {
            buf[i] = seq
                .next_element()
                .expect("error getting next element in sequence")
                .expect("expected another element in seq");
        }
        Ok(buf)
    }
}

fn serialize_ristretto_point<S: Serializer>(
    point: &RistrettoPoint,
    ser: S,
) -> Result<S::Ok, S::Error> {
    let bytes = point.compress().to_bytes();
    ser.serialize_bytes(&bytes)
}

fn deserialize_ristretto_point<'de, D: Deserializer<'de>>(
    de: D,
) -> Result<RistrettoPoint, D::Error> {
    let bytes = de.deserialize_bytes(ThirtyTwoBytesVisitor)?;
    let compressed = CompressedRistretto::from_slice(&bytes);

    let point = compressed
        .decompress()
        .expect("encountered an invalid Ristretto point");
    Ok(point)
}

#[derive(Copy, Clone, Deserialize, Serialize)]
pub struct GroupElem(
    #[serde(
        serialize_with = "serialize_ristretto_point",
        deserialize_with = "deserialize_ristretto_point"
    )]
    pub RistrettoPoint,
);

impl From<RistrettoPoint> for GroupElem {
    fn from(p: RistrettoPoint) -> GroupElem {
        GroupElem(p)
    }
}

impl GroupElem {
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.compress().to_bytes()
    }
}

fn serialize_scalar<S: Serializer>(scalar: &ScalarRepr, ser: S) -> Result<S::Ok, S::Error> {
    ser.serialize_bytes(scalar.as_bytes())
}

fn deserialize_scalar<'de, D: Deserializer<'de>>(de: D) -> Result<ScalarRepr, D::Error> {
    let bytes = de.deserialize_bytes(ThirtyTwoBytesVisitor)?;
    let scalar = ScalarRepr::from_canonical_bytes(bytes).expect("encountered an invalid scalar");
    Ok(scalar)
}

#[derive(Copy, Clone, Default, Deserialize, Serialize)]
pub struct Scalar(
    #[serde(
        serialize_with = "serialize_scalar",
        deserialize_with = "deserialize_scalar"
    )]
    pub ScalarRepr,
);

impl From<ScalarRepr> for Scalar {
    fn from(s: ScalarRepr) -> Scalar {
        Scalar(s)
    }
}

impl Scalar {
    pub fn random<R: CryptoRng + RngCore>(rng: &mut R) -> Scalar {
        Scalar(ScalarRepr::random(rng))
    }
}
