//! The guest crate is resolved from two lockfiles: the root `Cargo.lock`
//! (via xtask's path dependency, used by native `cargo test --workspace`)
//! and `guest/methods/guest/Cargo.lock` (used by the zkVM build). What must
//! agree is the guest's PROVEN closure — the code that ends up in the zkVM
//! ELF — so a native test run exercises the same code the zkVM build proves.
//!
//! Comparing every name in both locks is wrong: the root lock holds the whole
//! NEAR/near-workspaces graph with many extra versions, and lockfiles do not
//! distinguish dev-dependencies, so the guest's dev-only `risc0-zkvm` subtree
//! (reqwest, rustls, toml_edit, winnow…) is noise. Instead we seed from the
//! guest's non-optional `[dependencies]`, walk the GUEST lock's closure, and
//! require every package compiled on both sides to carry the same pin.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;

/// One lockfile entry: every (version, source) pinned for that name, plus the
/// union of dependency names across versions. `source` is empty for
/// path/workspace packages.
#[derive(Default)]
struct Pkg {
    pins: Vec<(String, String)>,
    deps: Vec<String>,
}

type Lock = BTreeMap<String, Pkg>;

fn parse_lockfile(text: &str) -> Lock {
    let mut lock: Lock = BTreeMap::new();
    let mut name = String::new();
    let mut version = String::new();
    let mut source = String::new();
    let mut deps: Vec<String> = Vec::new();
    let mut in_deps = false;
    let flush = |name: &str, version: &str, source: &str, deps: Vec<String>, lock: &mut Lock| {
        if !name.is_empty() {
            let pkg = lock.entry(name.to_string()).or_default();
            pkg.pins.push((version.to_string(), source.to_string()));
            pkg.deps.extend(deps);
        }
    };
    for line in text.lines() {
        let t = line.trim();
        if in_deps {
            if t.starts_with(']') || t.starts_with('[') {
                in_deps = false;
            } else if let Some(entry) = t.strip_prefix('"') {
                // Entries are `name`, `name 1.2.3`, or `name 1.2.3 (source)`.
                let entry = entry.trim_end_matches(|c| c == '"' || c == ',');
                if let Some(first) = entry.split_whitespace().next() {
                    deps.push(first.to_string());
                }
            }
            continue;
        }
        if t == "[[package]]" {
            flush(&name, &version, &source, std::mem::take(&mut deps), &mut lock);
            name.clear();
            version.clear();
            source.clear();
        } else if let Some(v) = t.strip_prefix("name = ") {
            name = v.trim_matches('"').to_string();
        } else if let Some(v) = t.strip_prefix("version = ") {
            version = v.trim_matches('"').to_string();
        } else if let Some(v) = t.strip_prefix("source = ") {
            source = v.trim_matches('"').to_string();
        } else if t.starts_with("dependencies = [") {
            in_deps = !t.ends_with(']');
            if !in_deps {
                // Single-line `dependencies = ["x"]`: handle inline entries.
                for entry in t.trim_start_matches("dependencies = [")
                    .trim_end_matches(']')
                    .split(',')
                {
                    if let Some(first) = entry.trim().trim_matches('"').split_whitespace().next() {
                        deps.push(first.to_string());
                    }
                }
            }
        }
    }
    flush(&name, &version, &source, deps, &mut lock);
    for pkg in lock.values_mut() {
        pkg.pins.sort();
    }
    lock
}

/// Non-optional `[dependencies]` keys of the guest manifest (the zkVM-only
/// `risc0-zkvm` is `optional = true` and excluded: the root never compiles it).
fn seed_names(manifest: &str) -> Vec<String> {
    let mut seeds = Vec::new();
    let mut in_deps = false;
    for line in manifest.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            in_deps = t == "[dependencies]";
            continue;
        }
        if in_deps && !t.starts_with('#') && t.contains('=') && !t.contains("optional = true") {
            seeds.push(t.split('=').next().unwrap().trim().to_string());
        }
    }
    seeds
}

#[test]
fn root_lock_pins_the_guests_proven_closure() {
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let root_lock = parse_lockfile(&fs::read_to_string(repo.join("Cargo.lock")).unwrap());
    let guest_lock = parse_lockfile(
        &fs::read_to_string(repo.join("guest/methods/guest/Cargo.lock")).unwrap(),
    );
    let seeds = seed_names(&fs::read_to_string(repo.join("guest/methods/guest/Cargo.toml")).unwrap());
    assert!(
        !seeds.is_empty(),
        "no dependencies parsed from guest manifest — did [dependencies] drift?"
    );
    for seed in &seeds {
        assert!(
            guest_lock.contains_key(seed),
            "seed {seed} missing from guest lock — manifest/lock drift?"
        );
    }

    // Walk the proven closure through the guest lock's dependency lists.
    let mut closure = BTreeSet::new();
    let mut queue: Vec<String> = seeds.clone();
    while let Some(n) = queue.pop() {
        if closure.insert(n.clone()) {
            if let Some(pkg) = guest_lock.get(&n) {
                queue.extend(pkg.deps.iter().cloned());
            }
        }
    }

    let mut drift = Vec::new();
    for name in &closure {
        let Some(guest_pkg) = guest_lock.get(name) else { continue };
        for (version, source) in &guest_pkg.pins {
            if source.is_empty() {
                continue; // path/workspace package: no registry pin to compare
            }
            // A lockfile records optional dependencies enabled by *any* feature
            // set in its workspace — here the guest's dev-dep `stellar-xdr`
            // default features — so a name absent from the root lock is not
            // compiled natively at all and has nothing to agree with.
            let Some(root_pkg) = root_lock.get(name) else { continue };
            // `crypto-bigint` is overridden by the guest's own [patch.crates-io]
            // (guest/methods/guest/Cargo.toml), which the root lock does not
            // apply; for that name only the version must agree.
            let ok = if name == "crypto-bigint" {
                root_pkg.pins.iter().any(|(v, _)| v == version)
            } else {
                root_pkg.pins.iter().any(|(v, s)| v == version && s == source)
            };
            if !ok {
                drift.push(format!(
                    "{name}: guest ({version}, {source}) not in root {:?}",
                    root_pkg.pins
                ));
            }
        }
    }
    assert!(
        drift.is_empty(),
        "guest proven closure drifts from root lock:\n{}\nhint: move the ROOT lock to match the guest lock; never the reverse — changing the guest lock changes the proven program / image ID.",
        drift.join("\n")
    );
}
