/* The Schnorr blind signature scheme, using notation from
*  https://eprint.iacr.org/2019/877.pdf
*
* x is the secret key
* X is the public key
* G is a group generator
* S is the set of scalars
* m is the message
*
*         Signer(x)                            Client(X, m)
*         ----------                           ------------
* Pick a nonce and commit to it
*
* r ← S
* R := rG
*
*                                 R
*                               ----->
*                                              Blind the commitment and
*                                              make a blinded challenge
*
*                                              α, β ← S
*                                              R' := R + αG + βX
*                                              c' := H(R', m)
*                                              c := c' + β
*                                 c
*                               <-----
* Compute the response
* to the challenge
*
* s := r + cx
*                                 s
*                               ----->
*                                              Check validity, then undo
*                                              blinding
*
*                                              if sG ≠ R + cX: abort
*                                              s' := s + α
*                                              σ := (R', s')
*
* KeyGen():
*   x ← S
*   X := xG
*   return (x, X)
*
* Verif(P, m, σ = (R', s')):
*   c' := H(R', m)
*   return s'G == R' + c'X
*/

use blake2::{digest::Digest, Blake2b};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_TABLE,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use rand::{CryptoRng, RngCore};

type Privkey = Scalar;
type Pubkey = RistrettoPoint;

// Used in protocol step 1
type Nonce = Scalar;
type Com = RistrettoPoint;
type SerializedCom = [u8; 32];

// Used in protocol step 2
type BlindingFactor = Scalar;
type Challenge = Scalar;
type SerializedChallenge = [u8; 32];

// Used in protocol step 3
type Resp = Scalar;
type SerializedResp = [u8; 32];

// Used in protocol step 4
type Signature = (Com, Resp);

/// Generates a Schnorr keypair
pub fn keygen<R: RngCore + CryptoRng>(rng: &mut R) -> (Privkey, Pubkey) {
    // x ← ℤ/ℓℤ where ℓ is the group order. We don't care about cofactors here because Ristretto
    // is a prime-order curve
    let x = Scalar::random(rng);
    let X = &x * &RISTRETTO_BASEPOINT_TABLE;

    (x, X)
}

/// Verifies the signature
pub fn verify(X: &Pubkey, m: &[u8], σ: &Signature) -> bool {
    // σ = (R', s')
    let (R_prime, s_prime) = σ;

    // c' = H(R', m)
    let c_prime = {
        let mut hasher = Blake2b::default();
        hasher.input(&R_prime.compress().to_bytes());
        hasher.input(m);
        let digest = hasher.result();
        let mut truncated_digest = [0u8; 32];
        truncated_digest.copy_from_slice(&digest[..32]);
        Scalar::from_bits(truncated_digest)
    };

    // Check s'G == R' + c'X
    let s_primeG = s_prime * &RISTRETTO_BASEPOINT_TABLE;
    s_primeG == R_prime + c_prime * X
}

/// Step 1 in the protocol
/// Returns (r, R)
pub fn server_com<R: RngCore + CryptoRng>(rng: &mut R) -> (Nonce, Com, SerializedCom) {
    // Generating a commitment is actually identical in functionality to keygen()
    // r ← S, R := rG
    let (r, R) = keygen(rng);

    // Serialize the commitment R
    let serialized_R = R.compress().to_bytes();
    (r, R, serialized_R)
}

/// Step 2 in the protocol
/// Recieves m, X, R
/// Returns (α, R', c)
pub fn client_chal<R: RngCore + CryptoRng>(
    rng: &mut R,
    m: &[u8],
    X: &Pubkey,
    serialized_R: &SerializedCom,
) -> (BlindingFactor, Com, Challenge, SerializedChallenge) {
    // Generate the blinding factors
    let α = Scalar::random(rng);
    let β = Scalar::random(rng);

    // Deserialize the received commitment
    let R = CompressedRistretto::from_slice(serialized_R)
        .decompress()
        .expect("corrupted R");
    // Blind the commitment
    let R_prime = {
        let αG = &α * &RISTRETTO_BASEPOINT_TABLE;
        let βX = β * X;
        R + αG + βX
    };

    // Compute the hash c' = H(R', m)
    let c_prime = {
        let mut hasher = Blake2b::default();
        hasher.input(&R_prime.compress().to_bytes());
        hasher.input(m);
        let digest = hasher.result();
        let mut truncated_digest = [0u8; 32];
        truncated_digest.copy_from_slice(&digest[..32]);
        Scalar::from_bits(truncated_digest)
    };

    // Compute c and serialize it
    let c = c_prime + β;
    let serialized_c = c.to_bytes();

    (α, R_prime, c, serialized_c)
}

/// Step 3 in the protocol
/// Receives x, r, c
/// Returns s
pub fn server_resp(x: &Privkey, r: &Nonce, serialized_c: &SerializedChallenge) -> SerializedResp {
    let c = Scalar::from_canonical_bytes(*serialized_c).expect("corrupted c");
    let s = r + c * x;
    s.to_bytes()
}

/// Step 4 in the protocol
/// Receives c, α, R, R', X, s
/// Returns σ
pub fn client_unblind(
    c: &Challenge,
    α: &BlindingFactor,
    R: &Com,
    R_prime: &Com,
    X: &Pubkey,
    serialized_s: &SerializedCom,
) -> Signature {
    // Check sG == R + cX
    let s = Scalar::from_canonical_bytes(*serialized_s).expect("corrupted s");
    let sG = &s * &RISTRETTO_BASEPOINT_TABLE;
    if sG != R + c * X {
        panic!("invalid signature");
    }

    let s_prime = s + α;
    (*R_prime, s_prime)
}

#[test]
fn test_correctness() {
    let mut csprng = rand::thread_rng();
    let m = b"Hello world";

    let (x, X) = keygen(&mut csprng);
    let (r, R, serialized_R) = server_com(&mut csprng);
    let (α, R_prime, c, serialized_c) = client_chal(&mut csprng, m, &X, &serialized_R);
    let serialized_s = server_resp(&x, &r, &serialized_c);
    let σ = client_unblind(&c, &α, &R, &R_prime, &X, &serialized_s);

    assert!(verify(&X, m, &σ));
}
