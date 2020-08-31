use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar as ScalarRepr,
};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

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
    let bytes = <[u8; 32]>::deserialize(de)?;
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
    let bytes = <[u8; 32]>::deserialize(de)?;
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

pub trait FourMoveBlindSig {
    const MAX_PARALLEL_SESSIONS: usize;

    type Privkey: Clone + Copy + Send + Sync + 'static;
    type Pubkey: Clone + Copy + Send + Sync + 'static;

    type ServerState: Clone + Send + Sync + 'static;
    type ClientState: Clone;
    type ClientResp: Clone + for<'de> Deserialize<'de> + Serialize;
    type ServerResp1: Clone + for<'de> Deserialize<'de> + Serialize;
    type ServerResp2: Clone + for<'de> Deserialize<'de> + Serialize;
    type Signature: Clone;

    fn keygen<R: RngCore + CryptoRng>(rng: &mut R) -> (Self::Privkey, Self::Pubkey);
    fn verify(pubkey: &Self::Pubkey, m: &[u8], sig: &Self::Signature) -> bool;

    fn sign1<R: RngCore + CryptoRng>(
        rng: &mut R,
        pubkey: &Self::Pubkey,
    ) -> (Self::ServerState, Self::ServerResp1);
    fn user1<R: RngCore + CryptoRng>(
        rng: &mut R,
        pubkey: &Self::Pubkey,
        m: &[u8],
        server_resp1: &Self::ServerResp1,
    ) -> (Self::ClientState, Self::ClientResp);
    fn sign2(
        privkey: &Self::Privkey,
        state: &Self::ServerState,
        client_resp: &Self::ClientResp,
    ) -> Self::ServerResp2;
    fn user2(
        pubkey: &Self::Pubkey,
        state: &Self::ClientState,
        m: &[u8],
        server_resp2: &Self::ServerResp2,
    ) -> Option<Self::Signature>;
}
