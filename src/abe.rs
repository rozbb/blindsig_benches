/* The Abe blind signature scheme, using notation from
 * https://www.iacr.org/archive/eurocrypt2001/20450135.pdf
 *
 * x is the secret key
 * y is the public key
 * z is the fixed tag key
 * g is a group generator
 * h is another group generator
 * S is the set of scalars
 * S* is the set of unit scalar
 * Hᵢ are independent hash functions. H₁ and H₂ map to G, while H₃ maps to S.
 * m is the message
 *
 *         Signer(x,z,g,h)                           Client(y,z,g,h,m)
 *         ---------------                           -----------------
 * Pick a nonce and commit to it
 *
 * rnd ← {0,1}*
 * z₁ := H₂(rnd)
 * z₂ := z/z₁
 * u, s₁, s₂, d ← S
 * a := gᵘ
 * b₁ := gˢ¹ z₁ᵈ
 * b₂ := hˢ²z₂ᵈ
 *                              rnd, a, b₁, b₂
 *                             --------------->
 *
 *                                                   Blind the commitment and
 *                                                   make a blinded challenge
 *
 *                                                   z₁ := H₂(rnd)
 *                                                   γ ← S*
 *                                                   ζ := z^γ
 *                                                   ζ₁ := z₁^γ
 *                                                   ζ₂ := ζ/ζ₁
 *                                                   t₁, t₂, t₃, t₄, t₅ ← S
 *                                                   α := agᵗ¹yᵗ²
 *                                                   β₁ := b₁^γ gᵗ³ ζ₁ᵗ⁴
 *                                                   β₂ := b₂^γ hᵗ⁵ ζ₂ᵗ⁴
 *                                                   τ ← S
 *                                                   η := z^τ
 *                                                   ε := H₃(ζ, ζ₁, α, β₁ β₂, η, m)
 *                                                   e := ε - t₂ - t₄
 *
 *                                   e
 *                                <------
* Compute the response
* to the challenge
*
*  c := e - d
*  r := u - cx
*                              r, c, s₁, s₂, d
*                             ----------------->
*                                                    Check validity, then undo
*                                                    blinding
*
*                                                    ρ := r + t₁
*                                                    ω := c + t₂
*                                                    σ₁ := γs₁ + t₃
*                                                    σ₂ := γs₂ + t₅
*                                                    δ := d + t₄
*                                                    μ := τ - δγ
*                                                    if ω + δ ≠ H₃(
*                                                       ζ, ζ₁, g^ρ y^ω, g^σ₁ ζ₁^δ,
*                                                       h^σ₂ ζ₂^δ, z^μ ζ^δ, m,
*                                                    ):
*                                                        abort
*                                                    return (ζ, ζ₁, ρ, ω, σ₁, σ₂, δ, μ)
*
* KeyGen():
*   x ← S
*   y := g^x
*   z := H₁(h, y)
*   if z == 1: retry
*   sk := x
*   pk := (y, z)
*   return (sk, pk)
*
* Verify(ζ, ζ₁, ρ, ω, σ₁, σ₂, δ, μ, m):
*   return ω + δ == H₃(ζ, ζ₁, g^ρ y^ω, g^σ₁ ζ₁^δ, h^σ₂ (ζ/ζ₁)^δ, z^μ ζ^δ, m):
*/

use crate::common::{FourMoveBlindSig, GroupElem, Scalar};

use blake2::{crypto_mac::Mac, digest::Digest, Blake2b};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_TABLE,
    ristretto::{RistrettoBasepointTable, RistrettoPoint},
    scalar::Scalar as ScalarRepr,
};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

lazy_static! {
    // This is h in the above notation
    static ref RISTRETTO_ALT_GENERATOR: RistrettoBasepointTable = {
        let basepoint = RistrettoPoint::hash_from_bytes::<Blake2b>(b"Abe Blind Sig Alt Basepoint");
        RistrettoBasepointTable::create(&basepoint)
    };
    // Independent hash functions H₁, H₂, H₃
    static ref H1: Blake2b = Blake2b::new_varkey(b"Abe Blind Sig Oracle 1").unwrap();
    static ref H2: Blake2b = Blake2b::new_varkey(b"Abe Blind Sig Oracle 2").unwrap();
    static ref H3: Blake2b = Blake2b::new_varkey(b"Abe Blind Sig Oracle 3").unwrap();
}

#[derive(Clone, Copy, Deserialize, Serialize)]
pub struct Pubkey {
    y: GroupElem,
    z: GroupElem,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
pub struct Privkey(Scalar);

#[derive(Clone, Copy, Default, Deserialize, Serialize)]
pub struct ServerState {
    u: Scalar,
    s1: Scalar,
    s2: Scalar,
    d: Scalar,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
pub struct ServerResp1 {
    rnd: [u8; 32],
    a: GroupElem,
    b1: GroupElem,
    b2: GroupElem,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
pub struct ClientState {
    ζ: GroupElem,
    ζ1: GroupElem,
    γ: Scalar,
    τ: Scalar,
    t1: Scalar,
    t2: Scalar,
    t3: Scalar,
    t4: Scalar,
    t5: Scalar,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
pub struct ClientResp(Scalar);

#[derive(Clone, Copy, Deserialize, Serialize)]
pub struct ServerResp2 {
    r: Scalar,
    c: Scalar,
    s1: Scalar,
    s2: Scalar,
    d: Scalar,
}

#[derive(Clone)]
pub struct Signature {
    ζ: GroupElem,
    ζ1: GroupElem,
    ρ: Scalar,
    ω: Scalar,
    σ1: Scalar,
    σ2: Scalar,
    δ: Scalar,
    μ: Scalar,
}

/// The impl of the Abe blind signature scheme
pub struct Abe;

impl FourMoveBlindSig for Abe {
    type Privkey = Privkey;
    type Pubkey = Pubkey;

    type ServerState = ServerState;
    type ClientState = ClientState;
    type ClientResp = ClientResp;
    type ServerResp1 = ServerResp1;
    type ServerResp2 = ServerResp2;
    type Signature = Signature;

    fn keygen<R: CryptoRng + RngCore>(rng: &mut R) -> (Privkey, Pubkey) {
        // x ← S
        // y := g^x
        // z := H₁(h, y)
        // if z == 1: retry
        let x = Scalar::random(rng);
        let y = GroupElem(&x.0 * &RISTRETTO_BASEPOINT_TABLE);
        let z = GroupElem(RistrettoPoint::from_hash(
            H1.clone()
                .chain(&RISTRETTO_ALT_GENERATOR.basepoint().compress().to_bytes())
                .chain(y.0.compress().to_bytes()),
        ));

        // sk = x
        let privkey = Privkey(x);
        // pk = (y, z)
        let pubkey = Pubkey { y, z };

        (privkey, pubkey)
    }

    fn verify(pubkey: &Pubkey, m: &[u8], sig: &Signature) -> bool {
        let Pubkey { y, z } = pubkey;
        let Signature {
            ζ,
            ζ1,
            ρ,
            ω,
            σ1,
            σ2,
            δ,
            μ,
        } = sig;

        // Intermediate calculations
        let ζ2 = GroupElem(ζ.0 - ζ1.0);
        let α = (&ρ.0 * &RISTRETTO_BASEPOINT_TABLE) + ω.0 * y.0;
        let β1 = &σ1.0 * &RISTRETTO_BASEPOINT_TABLE + δ.0 * ζ1.0;
        let β2 = &σ2.0 * &*RISTRETTO_ALT_GENERATOR + δ.0 * ζ2.0;
        let η = μ.0 * z.0 + δ.0 * ζ.0;

        // if ω + δ ≠ H₃(
        //    ζ, ζ₁, g^ρ y^ω, g^σ₁ ζ₁^δ,
        //    h^σ₂ ζ₂^δ, z^μ ζ^δ, m,
        // ):
        //     abort
        // return (ζ, ζ₁, ρ, ω, σ₁, σ₂, δ, μ)
        let h = ScalarRepr::from_hash(
            H3.clone()
                .chain(ζ.to_bytes())
                .chain(ζ1.to_bytes())
                .chain(α.compress().to_bytes())
                .chain(β1.compress().to_bytes())
                .chain(β2.compress().to_bytes())
                .chain(η.compress().to_bytes())
                .chain(m),
        );

        h == ω.0 + δ.0
    }

    fn server1<R: RngCore + CryptoRng>(rng: &mut R, pubkey: &Pubkey) -> (ServerState, ServerResp1) {
        let Pubkey { z, .. } = pubkey;

        // rnd ← {0,1}*
        // z₁ := H₂(rnd)
        // z₂ := z/z₁
        let mut rnd = [0u8; 32];
        rng.fill_bytes(&mut rnd);
        let z1 = RistrettoPoint::from_hash(H1.clone().chain(&rnd));
        let z2 = z.0 - z1;

        // u, s₁, s₂, d ← S
        let (u, s1, s2, d) = (
            Scalar::random(rng),
            Scalar::random(rng),
            Scalar::random(rng),
            Scalar::random(rng),
        );

        // a := gᵘ
        // b₁ := gˢ¹ z₁ᵈ
        // b₂ := hˢ²z₂ᵈ
        let a = GroupElem(&u.0 * &RISTRETTO_BASEPOINT_TABLE);
        let b1 = GroupElem(&s1.0 * &RISTRETTO_BASEPOINT_TABLE + d.0 * z1);
        let b2 = GroupElem(&s2.0 * &*RISTRETTO_ALT_GENERATOR + d.0 * z2);

        let state = ServerState { u, s1, s2, d };
        let resp = ServerResp1 { rnd, a, b1, b2 };

        (state, resp)
    }

    fn client1<R: RngCore + CryptoRng>(
        rng: &mut R,
        pubkey: &Pubkey,
        m: &[u8],
        server_resp1: &ServerResp1,
    ) -> (ClientState, ClientResp) {
        let Pubkey { y, z } = pubkey;
        let ServerResp1 { rnd, a, b1, b2 } = server_resp1;

        // z₁ := H₂(rnd)
        // γ ← S*
        let z1 = RistrettoPoint::from_hash(H1.clone().chain(&rnd));
        let mut γ = Scalar(ScalarRepr::zero());
        while γ.0 == ScalarRepr::zero() {
            γ = Scalar::random(rng);
        }

        // ζ := z^γ
        // ζ₁ := z₁^γ
        // ζ₂ := ζ/ζ
        let ζ = GroupElem(γ.0 * z.0);
        let ζ1 = GroupElem(γ.0 * z1);
        let ζ2 = GroupElem(ζ.0 - ζ1.0);

        // t₁, t₂, t₃, t₄, t₅ ← S
        let (t1, t2, t3, t4, t5) = (
            Scalar::random(rng),
            Scalar::random(rng),
            Scalar::random(rng),
            Scalar::random(rng),
            Scalar::random(rng),
        );

        // α := agᵗ¹yᵗ²
        // β₁ := b₁^γ gᵗ³ ζ₁ᵗ⁴
        // β₂ := b₂^γ hᵗ⁵ ζ₂ᵗ⁴
        let α = a.0 + &t1.0 * &RISTRETTO_BASEPOINT_TABLE + t2.0 * y.0;
        let β1 = γ.0 * b1.0 + &t3.0 * &RISTRETTO_BASEPOINT_TABLE + t4.0 * ζ1.0;
        let β2 = γ.0 * b2.0 + &t5.0 * &*RISTRETTO_ALT_GENERATOR + t4.0 * ζ2.0;

        // τ ← S
        // η := z^τ
        // ε := H₃(ζ, ζ₁, α, β₁ β₂, η, m)
        let τ = Scalar::random(rng);
        let η = τ.0 * z.0;
        let ε = ScalarRepr::from_hash(
            H3.clone()
                .chain(ζ.to_bytes())
                .chain(ζ1.to_bytes())
                .chain(α.compress().to_bytes())
                .chain(β1.compress().to_bytes())
                .chain(β2.compress().to_bytes())
                .chain(η.compress().to_bytes())
                .chain(m),
        );

        // e := ε - t₂ - t₄
        let e = Scalar(ε - t2.0 - t4.0);

        let state = ClientState {
            ζ,
            ζ1,
            γ,
            τ,
            t1,
            t2,
            t3,
            t4,
            t5,
        };
        let resp = ClientResp(e);

        (state, resp)
    }

    fn server2(privkey: &Privkey, state: &ServerState, client_resp: &ClientResp) -> ServerResp2 {
        let Privkey(x) = privkey;
        let ServerState { u, s1, s2, d } = state;
        let ClientResp(e) = client_resp;

        // c := e - d
        // r := u - cx
        let c = Scalar(e.0 - d.0);
        let r = Scalar(u.0 - c.0 * x.0);

        ServerResp2 {
            r,
            c,
            s1: *s1,
            s2: *s2,
            d: *d,
        }
    }

    fn client2(
        pubkey: &Pubkey,
        state: &ClientState,
        m: &[u8],
        server_resp2: &ServerResp2,
    ) -> Option<Signature> {
        let ClientState {
            ζ,
            ζ1,
            γ,
            τ,
            t1,
            t2,
            t3,
            t4,
            t5,
        } = state;
        let ServerResp2 { r, c, s1, s2, d } = server_resp2;

        // ρ := r + t₁
        // ω := c + t₂
        let ρ = Scalar(r.0 + t1.0);
        let ω = Scalar(c.0 + t2.0);

        // σ₁ := γs₁ + t₃
        // σ₂ := γs₂ + t₅
        let σ1 = Scalar(γ.0 * s1.0 + t3.0);
        let σ2 = Scalar(γ.0 * s2.0 + t5.0);

        // δ := d + t₄
        // μ := τ - δγ
        let δ = Scalar(d.0 + t4.0);
        let μ = Scalar(τ.0 - δ.0 * γ.0);

        let tentative_sig = Signature {
            ζ: *ζ,
            ζ1: *ζ1,
            ρ,
            ω,
            σ1,
            σ2,
            δ,
            μ,
        };

        if Self::verify(pubkey, m, &tentative_sig) {
            Some(tentative_sig)
        } else {
            None
        }
    }
}

#[test]
fn test_correctness() {
    let mut csprng = rand::thread_rng();
    let m = b"Hello world";
    type Alg = Abe;

    let (privkey, pubkey) = Alg::keygen(&mut csprng);
    let (server_state, server_resp1) = Alg::server1(&mut csprng, &pubkey);
    let (client_state, client_resp) = Alg::client1(&mut csprng, &pubkey, m, &server_resp1);
    let server_resp2 = Alg::server2(&privkey, &server_state, &client_resp);
    let sig = Alg::client2(&pubkey, &client_state, m, &server_resp2).unwrap();

    assert!(Alg::verify(&pubkey, m, &sig));
}
