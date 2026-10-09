//! Groth16 verification over the BN254 host-function primitives.
//!
//! The verification equation follows ark-groth16 0.5.0,
//! `src/groth16/verifier.rs:49-64`:
//!
//! ```text
//! e(A, B) · e(π_l, −γ) · e(C, −δ) == e(α, β)
//! where π_l = IC[0] + Σ_i x_i · IC[i+1]
//! ```
//!
//! Both sides are checked with a **single** `pairing_check` by moving
//! `e(α, β)` to the left (negating its G2 point):
//!
//! ```text
//! e(A, B) · e(π_l, −γ) · e(C, −δ) · e(α, −β) == 1
//! ```
//!
//! and `π_l` is evaluated with a **single** `g1_multiexp` over
//! `[IC[0], IC[1], …, IC[n]]` with scalars `[1, x_0, …, x_{n−1}]`.
//! Negation happens in arkworks *before* encoding — the encoded buffers the
//! host sees already contain the negated coordinates (G1: negated `y`;
//! G2: negated `y.c0`/`y.c1`, via `Neg for Affine`).

use crate::bn128::{self, Fr, G1, G2};

/// Verification key of the Groth16 proving system.
#[derive(Debug, Clone)]
pub struct VerifyingKey {
    /// `[α]₁`
    pub alpha_g1: G1,
    /// `[β]₂`
    pub beta_g2: G2,
    /// `[γ]₂`
    pub gamma_g2: G2,
    /// `[δ]₂`
    pub delta_g2: G2,
    /// `IC[0] … IC[n]`: `[α]₁ + x_i·[β]₁` bindings for the public inputs.
    pub ic: Vec<G1>,
}

/// A Groth16 proof: three curve points.
#[derive(Debug, Clone)]
pub struct Proof {
    /// `A ∈ G1`
    pub a: G1,
    /// `B ∈ G2`
    pub b: G2,
    /// `C ∈ G1`
    pub c: G1,
}

/// Verifies `proof` against `vk` and `public_inputs`.
///
/// Returns `false` (never panics) for:
/// * an empty verifying key (`vk.ic` empty),
/// * a public-input count that doesn't satisfy `public_inputs.len() + 1 == vk.ic.len()`,
/// * identity points for `A`, `B`, or `C` (a degenerate proof).
///
/// The only way this function can trap is if the host itself aborts on a
/// malformed curve encoding — impossible for points produced by our
/// encoders.
pub fn verify(vk: &VerifyingKey, proof: &Proof, public_inputs: &[Fr]) -> bool {
    // Shape / degeneracy guards first — every branch below reaches the host.
    if vk.ic.is_empty() || public_inputs.len() + 1 != vk.ic.len() {
        return false;
    }
    // Reject identity points AND zero-coordinate points: a point with
    // `infinity = false` but zero coordinates still encodes to 64/128 zero bytes,
    // which the host reads as the identity and pairs trivially — an attacker-supplied
    // degenerate proof must not pass that way. (Correction to the first draft, which
    // only checked the infinity flag.)
    let zero_g1 = |p: &G1| ark_ff::Zero::is_zero(&p.x) && ark_ff::Zero::is_zero(&p.y);
    let zero_g2 = |p: &G2| ark_ff::Zero::is_zero(&p.x) && ark_ff::Zero::is_zero(&p.y);
    if proof.a.infinity || proof.b.infinity || proof.c.infinity
        || zero_g1(&proof.a) || zero_g2(&proof.b) || zero_g1(&proof.c)
    {
        return false;
    }

    // Points must be on-curve: the NEAR host ABORTS on off-curve input
    // (`AltBn128InvalidInput`), which would turn a bad proof into a panicking
    // transaction, while arkworks' verifier simply returns false. Check up front so
    // `verify` is total for any well-typed input. (Correction to the first draft,
    // which assumed only encoding errors could reach the host.)
    let on_curve_g1 = |p: &G1| p.is_on_curve();
    let on_curve_g2 = |p: &G2| p.is_on_curve();
    if !on_curve_g1(&proof.a)
        || !on_curve_g2(&proof.b)
        || !on_curve_g1(&proof.c)
        || !on_curve_g1(&vk.alpha_g1)
        || !on_curve_g2(&vk.beta_g2)
        || !on_curve_g2(&vk.gamma_g2)
        || !on_curve_g2(&vk.delta_g2)
        || vk.ic.iter().any(|p| !on_curve_g1(p))
    {
        return false;
    }

    // π_l = IC[0] + Σ x_i · IC[i+1] — one host multiexp call.
    let scalars: Vec<Fr> = std::iter::once(Fr::from(1u64))
        .chain(public_inputs.iter().copied())
        .collect();
    let pi_l = bn128::g1_multiexp(&vk.ic, &scalars);

    // e(A,B) · e(π_l,−γ) · e(C,−δ) · e(α,−β) == 1 — one host pairing check.
    bn128::pairing_check(&[
        (proof.a, proof.b),
        (pi_l, -vk.gamma_g2),
        (proof.c, -vk.delta_g2),
        (vk.alpha_g1, -vk.beta_g2),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vk_with(n_ic: usize) -> VerifyingKey {
        VerifyingKey {
            alpha_g1: G1::identity(),
            beta_g2: G2::identity(),
            gamma_g2: G2::identity(),
            delta_g2: G2::identity(),
            ic: vec![G1::identity(); n_ic],
        }
    }

    fn valid_proof() -> Proof {
        Proof {
            // Non-identity markers: nonzero coordinates, not validated
            // on-curve, but the guard only checks `infinity`.
            a: G1::new_unchecked(ark_bn254::Fq::from(1u64), ark_bn254::Fq::from(2u64)),
            b: G2::new_unchecked(
                ark_bn254::Fq2 {
                    c0: ark_bn254::Fq::from(1u64),
                    c1: ark_bn254::Fq::from(0u64),
                },
                ark_bn254::Fq2 {
                    c0: ark_bn254::Fq::from(2u64),
                    c1: ark_bn254::Fq::from(0u64),
                },
            ),
            c: G1::new_unchecked(ark_bn254::Fq::from(2u64), ark_bn254::Fq::from(1u64)),
        }
    }

    #[test]
    fn empty_ic_is_rejected() {
        let vk = vk_with(0);
        assert!(!verify(&vk, &valid_proof(), &[]));
    }

    #[test]
    fn wrong_public_input_count_is_rejected() {
        // ic.len() == 3 requires exactly 2 public inputs.
        let vk = vk_with(3);
        assert!(!verify(&vk, &valid_proof(), &[Fr::from(0u64)]));
        assert!(!verify(
            &vk,
            &valid_proof(),
            &[Fr::from(0u64), Fr::from(1u64), Fr::from(2u64)]
        ));
    }

    #[test]
    fn identity_proof_points_are_rejected() {
        let vk = vk_with(2); // 1 public input
        let inputs = [Fr::from(0u64)];

        let mut p = valid_proof();
        p.a = G1::identity();
        assert!(!verify(&vk, &p, &inputs));

        let mut p = valid_proof();
        p.b = G2::identity();
        assert!(!verify(&vk, &p, &inputs));

        let mut p = valid_proof();
        p.c = G1::identity();
        assert!(!verify(&vk, &p, &inputs));
    }
}
