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
/// * identity points for `A`, `B`, or `C` (a degenerate proof),
/// * off-curve or wrong-subgroup points among the proof or verifying key (the
///   NEAR host *aborts* on those; `verify` stays total and returns `false`).
///
/// `verify` itself never traps on malformed input: every curve point is checked
/// on-curve and in the prime-order subgroup before the host is touched.
/// Callers whose VK is already known valid (e.g. the pinned RISC Zero key)
/// skip the VK-side re-validation with [`verify_trusted_vk`].
pub fn verify(vk: &VerifyingKey, proof: &Proof, public_inputs: &[Fr]) -> bool {
    // VK half of the validity checks (the proof-side twin guards live in
    // `verify_trusted_vk`): the NEAR host ABORTS on off-curve input
    // (`AltBn128InvalidInput`), and on G1/G2 encodings that are on-curve but
    // outside the prime-order subgroup, so no malformed point may reach
    // `g1_multiexp`/`pairing_check`.
    let on_curve_g1 = |p: &G1| p.is_on_curve();
    let on_curve_g2 = |p: &G2| p.is_on_curve();
    if !on_curve_g1(&vk.alpha_g1)
        || !on_curve_g2(&vk.beta_g2)
        || !on_curve_g2(&vk.gamma_g2)
        || !on_curve_g2(&vk.delta_g2)
        || vk.ic.iter().any(|p| !on_curve_g1(p))
    {
        return false;
    }
    let subgroup_g1 = |p: &G1| p.is_in_correct_subgroup_assuming_on_curve();
    let subgroup_g2 = |p: &G2| p.is_in_correct_subgroup_assuming_on_curve();
    if !subgroup_g1(&vk.alpha_g1)
        || !subgroup_g2(&vk.beta_g2)
        || !subgroup_g2(&vk.gamma_g2)
        || !subgroup_g2(&vk.delta_g2)
        || vk.ic.iter().any(|p| !subgroup_g1(p))
    {
        return false;
    }
    verify_trusted_vk(vk, proof, public_inputs)
}

/// [`verify`] minus the verifying-key on-curve/subgroup checks, for callers
/// whose VK is valid by construction (the pinned RISC Zero key: fixed
/// compile-time constants whose unchecked construction is asserted equal to
/// the fully checked [`crate::risc0::verifying_key()`] in
/// tests/risc0_verify.rs). Every proof-side guard of [`verify`] is kept —
/// shape, degeneracy, on-curve, subgroup — so this path is total for any
/// well-typed input.
pub(crate) fn verify_trusted_vk(vk: &VerifyingKey, proof: &Proof, public_inputs: &[Fr]) -> bool {
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
    if !on_curve_g1(&proof.a) || !on_curve_g2(&proof.b) || !on_curve_g1(&proof.c) {
        return false;
    }

    // Points must also lie in the prime-order subgroup: the NEAR host aborts
    // on G1/G2 encodings that are on-curve but outside it, so a raw-parsed
    // unchecked point must never reach `pairing_check`.
    let subgroup_g1 = |p: &G1| p.is_in_correct_subgroup_assuming_on_curve();
    let subgroup_g2 = |p: &G2| p.is_in_correct_subgroup_assuming_on_curve();
    if !subgroup_g1(&proof.a) || !subgroup_g2(&proof.b) || !subgroup_g1(&proof.c) {
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
    use ark_ec::AffineRepr;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::testing_env;

    // The host functions need a mocked chain even in unit tests — the mock
    // delegates `alt_bn128_*` to nearcore VMLogic and aborts on a malformed
    // point (panic), exactly like the on-chain host.
    fn mock_chain() {
        testing_env!(VMContextBuilder::new().build());
    }

    /// `[k]G1` — real on-curve, in-subgroup, non-identity point for `k ≠ 0`.
    fn g1_mul(k: Fr) -> G1 {
        (G1::generator() * k).into()
    }

    /// `[k]G2` — same, on the twist.
    fn g2_mul(k: Fr) -> G2 {
        (G2::generator() * k).into()
    }

    /// A VK whose points are all `[1]` multiples of the generators.
    fn gen_vk(n_ic: usize) -> VerifyingKey {
        VerifyingKey {
            alpha_g1: g1_mul(Fr::from(1u64)),
            beta_g2: g2_mul(Fr::from(1u64)),
            gamma_g2: g2_mul(Fr::from(1u64)),
            delta_g2: g2_mul(Fr::from(1u64)),
            ic: vec![g1_mul(Fr::from(1u64)); n_ic],
        }
    }

    /// Positive control: generator multiples that SATISFY the verification
    /// equation. With a=b=α=β=γ=δ=IC₀=IC₁=1 and x=[0], π_l=[1]G1, so C must
    /// be [−1]: ab − π_l·γ − c·δ − α·β = 1 − 1 + 1 − 1 = 0.
    fn satisfying() -> (VerifyingKey, Proof, Vec<Fr>) {
        (
            gen_vk(2),
            Proof {
                a: g1_mul(Fr::from(1u64)),
                b: g2_mul(Fr::from(1u64)),
                c: g1_mul(-Fr::from(1u64)),
            },
            vec![Fr::from(0u64)],
        )
    }

    // Deterministic on-curve G2 point outside the prime-order subgroup
    // (same search as tests/risc0_verify.rs).
    fn wrong_subgroup_g2() -> G2 {
        for i in 1u64..64 {
            let p = G2::get_point_from_x_unchecked(
                ark_bn254::Fq2::new(ark_bn254::Fq::from(i), ark_bn254::Fq::from(0u64)),
                false,
            );
            if let Some(p) = p {
                if !p.infinity && p.is_on_curve() && !p.is_in_correct_subgroup_assuming_on_curve()
                {
                    return p;
                }
            }
        }
        panic!("deterministic wrong-subgroup G2 search failed");
    }

    /// Off-curve G1: (1, 3) fails y² = x³ + 3 (9 ≠ 4).
    fn off_curve_g1() -> G1 {
        G1::new_unchecked(ark_bn254::Fq::from(1u64), ark_bn254::Fq::from(3u64))
    }

    /// Off-curve G2: x=(1,0) would need 3/(9+u) ∈ Fq for y=(2,0) to sit on
    /// the twist; it does not, so (x=(1,0), y=(2,0)) is off-curve.
    fn off_curve_g2() -> G2 {
        G2::new_unchecked(
            ark_bn254::Fq2 {
                c0: ark_bn254::Fq::from(1u64),
                c1: ark_bn254::Fq::from(0u64),
            },
            ark_bn254::Fq2 {
                c0: ark_bn254::Fq::from(2u64),
                c1: ark_bn254::Fq::from(0u64),
            },
        )
    }

    /// Positive control: proves the fixtures reach the host pairing (and
    /// pass it), so every `!verify` below is a guard firing, not an earlier
    /// check masking it.
    #[test]
    fn generator_fixture_satisfies_the_equation() {
        mock_chain();
        let (vk, proof, inputs) = satisfying();
        assert!(verify(&vk, &proof, &inputs));
        assert!(verify_trusted_vk(&vk, &proof, &inputs));
    }

    /// Pins the `vk.ic.is_empty()` arm of the shape guard: deleting it lets
    /// `g1_multiexp` see 0 points with 1 scalar, which `bn128::g1_multiexp`
    /// treats as a programming error and panics on — red test.
    #[test]
    fn empty_ic_is_rejected() {
        mock_chain();
        let (mut vk, proof, _) = satisfying();
        vk.ic.clear();
        assert!(!verify(&vk, &proof, &[]));
    }

    /// Pins the input-count arm of the shape guard (`ic.len() == 2` needs
    /// exactly 1 input): deleting it panics in `g1_multiexp` on the 1-vs-2
    /// and 3-vs-2 scalar/point length mismatches.
    #[test]
    fn wrong_public_input_count_is_rejected() {
        mock_chain();
        let (vk, proof, _) = satisfying();
        assert!(!verify(&vk, &proof, &[]));
        assert!(!verify(&vk, &proof, &[Fr::from(0u64), Fr::from(1u64)]));
    }

    /// Pins the identity/zero guard. Each mutant re-balances the scalar
    /// equation so DELETING the guard would satisfy it and return true
    /// (ab − π_l·γ − c·δ − α·β = 0): A or B at infinity zeroes ab,
    /// compensated by C=[−2]; C at infinity needs π_l = 0, i.e. x=[−1].
    #[test]
    fn identity_proof_points_are_rejected() {
        mock_chain();
        let (vk, mut proof, inputs) = satisfying();
        proof.a = G1::identity();
        proof.c = g1_mul(-Fr::from(2u64));
        assert!(!verify(&vk, &proof, &inputs));

        let (vk, mut proof, inputs) = satisfying();
        proof.b = G2::identity();
        proof.c = g1_mul(-Fr::from(2u64));
        assert!(!verify(&vk, &proof, &inputs));

        let (vk, mut proof, mut inputs) = satisfying();
        proof.c = G1::identity();
        inputs[0] = -Fr::from(1u64);
        assert!(!verify(&vk, &proof, &inputs));
    }

    /// Pins the proof-side on-curve guard: the off-curve points that reach
    /// the host abort it (`AltBn128InvalidInput` — a panic under the mock),
    /// so deleting the guard turns this test red through that panic.
    #[test]
    fn off_curve_proof_points_are_rejected() {
        mock_chain();
        let (vk, mut proof, inputs) = satisfying();
        proof.a = off_curve_g1();
        assert!(!verify(&vk, &proof, &inputs));

        let (vk, mut proof, inputs) = satisfying();
        proof.b = off_curve_g2();
        assert!(!verify(&vk, &proof, &inputs));

        let (vk, mut proof, inputs) = satisfying();
        proof.c = G1::new_unchecked(ark_bn254::Fq::from(2u64), ark_bn254::Fq::from(1u64));
        assert!(!verify(&vk, &proof, &inputs));
    }

    /// Pins the proof-side subgroup guard: the point is on-curve (the
    /// on-curve guard passes) but outside the prime-order subgroup, and the
    /// host pairing aborts on exactly that — deleting the guard panics.
    #[test]
    fn wrong_subgroup_proof_point_is_rejected() {
        mock_chain();
        let (vk, mut proof, inputs) = satisfying();
        proof.b = wrong_subgroup_g2();
        assert!(!verify(&vk, &proof, &inputs));
    }

    /// Pins the VK-side on-curve checks that live only in `verify`
    /// (`verify_trusted_vk` skips them by contract): deleting them lets the
    /// malformed point reach the host, which aborts it.
    #[test]
    fn off_curve_vk_points_are_rejected() {
        mock_chain();
        let (mut vk, proof, inputs) = satisfying();
        vk.alpha_g1 = off_curve_g1();
        assert!(!verify(&vk, &proof, &inputs));

        let (mut vk, proof, inputs) = satisfying();
        vk.gamma_g2 = off_curve_g2();
        assert!(!verify(&vk, &proof, &inputs));

        let (mut vk, proof, inputs) = satisfying();
        vk.ic[0] = G1::new_unchecked(ark_bn254::Fq::from(2u64), ark_bn254::Fq::from(1u64));
        assert!(!verify(&vk, &proof, &inputs));
    }

    /// Pins the VK-side subgroup guard (δ reaches the pairing): deleting it
    /// aborts the host on the cofactor-coset point.
    #[test]
    fn wrong_subgroup_vk_point_is_rejected() {
        mock_chain();
        let (mut vk, proof, inputs) = satisfying();
        vk.delta_g2 = wrong_subgroup_g2();
        assert!(!verify(&vk, &proof, &inputs));
    }
}
