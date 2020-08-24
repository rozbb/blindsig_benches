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

use crate::common::{FourMoveBlindSig, GroupElem, Scalar};

use blake2::{digest::Digest, Blake2b};
use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_TABLE, scalar::Scalar as ScalarRepr};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy)]
pub struct Privkey(Scalar);
#[derive(Clone, Copy)]
pub struct Pubkey(GroupElem);

#[derive(Clone, Copy)]
pub struct ServerState {
    r: Scalar,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
pub struct ServerResp1 {
    R: GroupElem,
}

#[derive(Clone)]
pub struct ClientState {
    α: Scalar,
    c: Scalar,
    R: GroupElem,
    R_prime: GroupElem,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
pub struct ClientResp {
    c: Scalar,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
pub struct ServerResp2 {
    s: Scalar,
}

// Used in protocol step 4
#[derive(Clone, Copy, Deserialize, Serialize)]
pub struct Signature {
    R_prime: GroupElem,
    s_prime: Scalar,
}

pub struct BlindSchnorr;

impl FourMoveBlindSig for BlindSchnorr {
    type Privkey = Privkey;
    type Pubkey = Pubkey;

    type ServerState = ServerState;
    type ClientState = ClientState;
    type ClientResp = ClientResp;
    type ServerResp1 = ServerResp1;
    type ServerResp2 = ServerResp2;
    type Signature = Signature;

    /// Generates a Schnorr keypair
    fn keygen<R: RngCore + CryptoRng>(rng: &mut R) -> (Privkey, Pubkey) {
        // sk ← ℤ/ℓℤ where ℓ is the group order. We don't care about cofactors here because Ristretto
        // is a prime-order curve
        let x = Scalar::random(rng);
        let X = &x.0 * &RISTRETTO_BASEPOINT_TABLE;

        let sk = Privkey(x);
        let pk = Pubkey(X.into());

        (sk, pk)
    }

    /// Verifies the signature
    fn verify(pubkey: &Pubkey, m: &[u8], sig: &Signature) -> bool {
        let Pubkey(X) = pubkey;
        let Signature { R_prime, s_prime } = sig;

        // c' = H(R', m)
        let c_prime = ScalarRepr::from_hash(Blake2b::default().chain(R_prime.to_bytes()).chain(m));

        // Check s'G == R' + c'X
        let s_primeG = &s_prime.0 * &RISTRETTO_BASEPOINT_TABLE;
        s_primeG == R_prime.0 + c_prime * X.0
    }

    fn server1<R: RngCore + CryptoRng>(
        rng: &mut R,
        _pubkey: &Pubkey,
    ) -> (ServerState, ServerResp1) {
        // Generating a commitment is actually identical in functionality to keygen()
        // r ← S, R := rG
        let (r, R) = Self::keygen(rng);

        let state = ServerState { r: r.0 };
        let resp = ServerResp1 { R: R.0 };

        (state, resp)
    }

    fn client1<R: RngCore + CryptoRng>(
        rng: &mut R,
        pubkey: &Pubkey,
        m: &[u8],
        server_resp1: &ServerResp1,
    ) -> (ClientState, ClientResp) {
        let Pubkey(X) = pubkey;

        // Generate the blinding factors
        let α = Scalar::random(rng);
        let β = Scalar::random(rng);

        // Deserialize the received commitment
        let &ServerResp1 { R } = server_resp1;

        // Blind the commitment
        let R_prime = {
            let αG = &α.0 * &RISTRETTO_BASEPOINT_TABLE;
            let βX = β.0 * X.0;
            GroupElem(R.0 + αG + βX)
        };

        // Compute the hash c' = H(R', m)
        let c_prime = ScalarRepr::from_hash(Blake2b::default().chain(R_prime.to_bytes()).chain(m));

        // Compute c
        let c = Scalar(c_prime + β.0);

        let state = ClientState { α, c, R, R_prime };
        let resp = ClientResp { c };

        (state, resp)
    }

    fn server2(privkey: &Privkey, state: &ServerState, client_resp: &ClientResp) -> ServerResp2 {
        let Privkey(x) = privkey;
        let ServerState { r } = state;
        let ClientResp { c } = client_resp;
        let s = Scalar(r.0 + c.0 * x.0);

        ServerResp2 { s }
    }

    fn client2(
        pubkey: &Pubkey,
        state: &ClientState,
        m: &[u8],
        server_resp2: &ServerResp2,
    ) -> Option<Signature> {
        let Pubkey(X) = pubkey;
        let &ClientState { α, c, R, R_prime } = state;
        let ServerResp2 { s } = server_resp2;

        // Check sG == R + cX
        let sG = &s.0 * &RISTRETTO_BASEPOINT_TABLE;
        if sG != R.0 + c.0 * X.0 {
            return None;
        }

        let s_prime = Scalar(s.0 + α.0);

        Some(Signature { R_prime, s_prime })
    }
}

#[test]
fn test_correctness() {
    let mut csprng = rand::thread_rng();
    let m = b"Hello world";
    type Alg = BlindSchnorr;

    let (privkey, pubkey) = Alg::keygen(&mut csprng);
    let (server_state, server_resp1) = Alg::server1(&mut csprng, &pubkey);
    let (client_state, client_resp) = Alg::client1(&mut csprng, &pubkey, m, &server_resp1);
    let server_resp2 = Alg::server2(&privkey, &server_state, &client_resp);
    let sig = Alg::client2(&pubkey, &client_state, m, &server_resp2).unwrap();

    assert!(Alg::verify(&pubkey, m, &sig));
}
