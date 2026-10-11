//! The guest's `ed25519_verify` must accept exactly what NEAR's host
//! `ed25519_verify` accepts.
//!
//! That equivalence is the soundness property behind routing the guest's crypto
//! through RISC Zero's precompile forks. A fork that changed acceptance
//! semantics — stricter or looser than `near-crypto`, which is what the mock
//! delegates to and what the chain actually runs — would make the light client
//! reject signatures the chain accepts, or accept ones it rejects.
//!
//! Neither failure shows up in tests that only feed valid or garbage
//! signatures: every implementation agrees on those. The corpus here includes
//! edge cases where permissive and strict ed25519 rules are known to diverge.
use ed25519_dalek::{Signer, SigningKey};
use guest::Sha256Dalek;
use near_sdk::test_utils::VMContextBuilder;
use near_sdk::testing_env;
use verify_core::Crypto;

/// Ed25519 group order, little-endian. `S' = S + L` is the canonical example of
/// a signature that satisfies the verification equation modulo L but is not in
/// canonical form.
const L: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2,
    0xde, 0xf9, 0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

#[test]
fn guest_ed25519_acceptance_matches_the_near_host() {
    let sk = SigningKey::from_bytes(&[7u8; 32]);
    let key = sk.verifying_key().to_bytes();
    let msg: &[u8] = b"acceptance parity corpus";
    let good = sk.sign(msg).to_bytes();

    // Non-canonical S: add the group order to the second half of the signature.
    // `S < L < 2^252`, so `S + L` always fits in 32 bytes and never carries out.
    let mut non_canonical = good;
    let mut carry = 0u16;
    for i in 32..64 {
        let sum = non_canonical[i] as u16 + L[i - 32] as u16 + carry;
        non_canonical[i] = sum as u8;
        carry = sum >> 8;
    }
    assert_eq!(carry, 0, "S + L must fit in 32 bytes");

    let mut tampered = good;
    tampered[0] ^= 0x01;

    // A *weak* public key: the ed25519 identity, whose compressed encoding is
    // y = 1. This is the case where `verify` and `verify_strict` actually part —
    // `verify_strict` rejects small-order `A`, `verify` does not — and with `A`
    // the identity the equation collapses to `[S]B == R`, so `S = 1` with
    // `R = B` is a valid signature under `verify`. Buildable from the public
    // API alone: `SigningKey::from_bytes(&[1; 32]).verifying_key()` is `B`.
    let mut weak_key = [0u8; 32];
    weak_key[0] = 0x01;
    // B, the ed25519 basepoint in compressed form (y = 4/5). Not derivable via
    // `SigningKey::from_bytes`, which takes a *seed* and hashes it — that would
    // give `[H(seed)]B`, not `B`.
    let basepoint: [u8; 32] = [
        0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    ];
    let mut weak_sig = [0u8; 64];
    weak_sig[..32].copy_from_slice(&basepoint);
    weak_sig[32] = 1; // S = 1

    // Prove this case is actually the discriminator — otherwise it would not
    // be testing the axis the corpus exists for.
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let weak_vk = VerifyingKey::from_bytes(&weak_key).expect("identity is representable");
    assert!(
        weak_vk.verify(msg, &Signature::from_bytes(&weak_sig)).is_ok(),
        "verify accepts a signature under a weak key"
    );
    assert!(
        weak_vk.verify_strict(msg, &Signature::from_bytes(&weak_sig)).is_err(),
        "verify_strict rejects it"
    );

    let corpus: Vec<(&str, [u8; 64], &[u8], [u8; 32])> = vec![
        ("valid", good, msg, key),
        ("non-canonical S", non_canonical, msg, key),
        ("tampered signature", tampered, msg, key),
        ("wrong message", good, b"a different message", key),
        ("small-order key", weak_sig, msg, weak_key),
    ];

    testing_env!(VMContextBuilder::new().build());
    for (name, sig, message, pubkey) in corpus {
        let via_guest = Sha256Dalek.ed25519_verify(&sig, message, &pubkey);
        let via_host = near_sdk::env::ed25519_verify(&sig, message, &pubkey);
        assert_eq!(
            via_guest, via_host,
            "guest and NEAR host disagree on case: {name}"
        );
    }

    // Positive control: the corpus must contain an accepted case, or this is
    // comparing two implementations that reject everything.
    assert!(Sha256Dalek.ed25519_verify(&good, msg, &key));
}
