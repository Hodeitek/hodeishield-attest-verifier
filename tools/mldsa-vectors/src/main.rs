// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Hodeitek S.L.

//! Runs the ML-DSA-65 verify primitive of `aws-lc-rs` over the published test
//! vectors (`tests/vectors/v1`) and checks that it reaches the same signature
//! verdict as the reference script, for every case where the manifest states
//! that verdict. See README.md in this directory for what that does and does
//! not show.
//!
//! Usage: mldsa-vectors <vectors-dir> <verify-attestation.sh>
//!
//! The canonical bytes a signature covers come from the reference script's own
//! embedded encoders (CANON_PY, CANON_STATUS_PY), which are read out of the
//! script text and run with python3, exactly as the script runs them. This
//! program does not re-implement the encoders: it tests the primitive, not a
//! second encoder.

use aws_lc_rs::digest;
use aws_lc_rs::signature::{UnparsedPublicKey, ML_DSA_65};
use data_encoding::{BASE64URL_NOPAD, HEXLOWER};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

/// Fewer checked cases than this fails the run, so that cases silently falling
/// into "skipped" cannot hide a regression. Equal to the count measured on
/// 2026-10-11 (see README.md). Raise it when vectors are added; never lower it.
const MIN_CHECKED: usize = 47;

#[derive(Clone, Copy, PartialEq)]
enum Want {
    Verify,
    Reject,
}

#[derive(Clone, Copy)]
enum Target {
    Attestation,
    StatusList,
}

impl Target {
    fn name(self) -> &'static str {
        match self {
            Target::Attestation => "attestation",
            Target::StatusList => "status list",
        }
    }
}

/// Everything the primitive needs for one signature.
struct Input {
    signing_input: Vec<u8>,
    signature: Vec<u8>,
    public_key: Vec<u8>,
    canonical_sha256: String,
}

fn read_text(p: &Path) -> Result<String, String> {
    fs::read_to_string(p).map_err(|e| format!("cannot read {}: {e}", p.display()))
}

fn read_json(p: &Path) -> Result<Value, String> {
    serde_json::from_str(&read_text(p)?).map_err(|e| format!("{}: {e}", p.display()))
}

fn b64(s: &str, what: &str) -> Result<Vec<u8>, String> {
    BASE64URL_NOPAD
        .decode(s.as_bytes())
        .map_err(|e| format!("{what} is not base64url: {e}"))
}

/// The text of a single-quoted bash assignment `NAME='...'` at the start of a
/// line, with the quotes removed.
fn extract_assignment(script: &str, name: &str) -> Result<String, String> {
    let head = format!("\n{name}='");
    let start = script
        .find(&head)
        .ok_or_else(|| format!("{name} not found in the script"))?
        + head.len();
    let end = script[start..]
        .find("\n'\n")
        .ok_or_else(|| format!("end of {name} not found in the script"))?;
    Ok(script[start..start + end + 1].to_string())
}

fn canonical(code: &str, file: &Path, mode: Option<&str>) -> Result<Vec<u8>, String> {
    let mut cmd = Command::new("python3");
    cmd.args(["-I", "-X", "utf8", "-c", code]).arg(file);
    if let Some(m) = mode {
        cmd.arg(m);
    }
    let out = cmd.output().map_err(|e| format!("cannot run python3: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "canonical encoder refused the document: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(out.stdout)
}

fn arg_value<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

/// The key of `keys_file` whose `kid` label is `kid`; exactly one must match.
fn find_key(keys_file: &Path, kid: &str) -> Result<Vec<u8>, String> {
    let doc = read_json(keys_file)?;
    let keys = doc
        .get("keys")
        .and_then(Value::as_array)
        .ok_or("key set has no keys array")?;
    let hits: Vec<&Value> = keys
        .iter()
        .filter(|k| k.get("kid").and_then(Value::as_str) == Some(kid))
        .collect();
    if hits.len() != 1 {
        return Err(format!("{} keys carry kid {kid}", hits.len()));
    }
    let pubkey = hits[0]
        .get("pub")
        .and_then(Value::as_str)
        .ok_or("key has no pub member")?;
    b64(pubkey, "pub")
}

fn header_kid(h: &str) -> Result<String, String> {
    let hdr: Value = serde_json::from_slice(&b64(h, "protected header")?)
        .map_err(|e| format!("protected header is not JSON: {e}"))?;
    hdr.get("kid")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| "protected header has no kid".to_string())
}

fn sha256_hex(data: &[u8]) -> String {
    HEXLOWER.encode(digest::digest(&digest::SHA256, data).as_ref())
}

struct Ctx<'a> {
    dir: &'a Path,
    tmp: &'a Path,
    canon_py: &'a str,
    canon_status_py: &'a str,
}

fn attestation_input(cx: &Ctx, args: &[String]) -> Result<Input, String> {
    let jwks = cx.dir.join(arg_value(args, "--jwks").ok_or("no --jwks")?);
    // Where the compact JWS and the claims come from, as the script reads them
    // (the "split" mode of its DOCX_PY for --attestation).
    let (jws, claims_file): (String, Option<PathBuf>) =
        if let Some(a) = arg_value(args, "--attestation") {
            let doc = read_json(&cx.dir.join(a))?;
            let d = match doc.get("attestation") {
                Some(inner) if inner.is_object() => inner,
                _ => &doc,
            };
            let claims = d.get("claims").unwrap_or(d);
            let sig = d
                .get("signature")
                .and_then(Value::as_str)
                .ok_or("attestation has no signature string")?;
            let f = cx.tmp.join("claims.json");
            fs::write(&f, serde_json::to_vec(claims).map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?;
            (sig.to_string(), Some(f))
        } else if let Some(j) = arg_value(args, "--jws") {
            let t: String = read_text(&cx.dir.join(j))?
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect();
            (t, arg_value(args, "--claims").map(|c| cx.dir.join(c)))
        } else {
            return Err("neither --attestation nor --jws".into());
        };
    let parts: Vec<&str> = jws.split('.').collect();
    if parts.len() != 3 {
        return Err("not a three-segment compact JWS".into());
    }
    let (h, p, s) = (parts[0], parts[1], parts[2]);
    // Signing input: ASCII(BASE64URL(protected) || '.' || BASE64URL(payload)),
    // the protected segment exactly as received. The payload is the segment
    // itself (attached) or the canonical envelope bytes the script re-derives
    // from the claims (detached).
    let payload_b64 = match claims_file {
        Some(cf) => {
            let canon = canonical(cx.canon_py, &cf, Some("envelope"))?;
            let derived = BASE64URL_NOPAD.encode(&canon);
            if !p.is_empty() && p != derived {
                return Err("attached payload differs from the claims".into());
            }
            derived
        }
        None if p.is_empty() => return Err("detached JWS without claims".into()),
        None => p.to_string(),
    };
    let canon_bytes = b64(&payload_b64, "payload")?;
    let key = find_key(&jwks, &header_kid(h)?)?;
    Ok(Input {
        signing_input: format!("{h}.{payload_b64}").into_bytes(),
        signature: b64(s, "signature")?,
        public_key: key,
        canonical_sha256: sha256_hex(&canon_bytes),
    })
}

fn status_input(cx: &Ctx, args: &[String]) -> Result<Input, String> {
    let list = read_json(&cx.dir.join(arg_value(args, "--status").ok_or("no --status")?))?;
    let keys = cx
        .dir
        .join(arg_value(args, "--status-keys").ok_or("no --status-keys")?);
    let status_list = list.get("statusList").ok_or("no statusList member")?;
    let sig = list
        .get("signature")
        .and_then(Value::as_str)
        .ok_or("no signature string")?;
    let parts: Vec<&str> = sig.split('.').collect();
    if parts.len() != 3 || !parts[1].is_empty() {
        return Err("not a detached compact JWS".into());
    }
    let f = cx.tmp.join("list.json");
    fs::write(&f, serde_json::to_vec(status_list).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let canon = canonical(cx.canon_status_py, &f, None)?;
    Ok(Input {
        signing_input: format!("{}.{}", parts[0], BASE64URL_NOPAD.encode(&canon)).into_bytes(),
        signature: b64(parts[2], "signature")?,
        public_key: find_key(&keys, &header_kid(parts[0])?)?,
        canonical_sha256: sha256_hex(&canon),
    })
}

/// What the manifest proves about each signature of a case, or why it proves
/// nothing (the case is then skipped).
fn plan(args: &[String], exit: i64, code: &str, matched: &str) -> Result<Vec<(Target, Want)>, String> {
    if args.iter().any(|a| a == "--anchor-file") {
        return Err("anchor case: decided by cosign and the key statement, not by an ML-DSA verdict".into());
    }
    let status_mode = args.iter().any(|a| a == "--status-list");
    if exit == 0 {
        // Exit 0 (verified, good) needs every signature the run touched to verify.
        let mut t = vec![(Target::Attestation, Want::Verify)];
        if status_mode {
            t.push((Target::StatusList, Want::Verify));
        }
        return Ok(t);
    }
    match code {
        "signature_invalid" | "signature_size_invalid" => Ok(vec![(Target::Attestation, Want::Reject)]),
        "status_unknown_bad_signature" | "status_unknown_signature_size" => {
            Ok(vec![(Target::StatusList, Want::Reject)])
        }
        // Rejected for another reason, but the reference prints that the signature is valid.
        _ if matched.contains("the signature is valid") => Ok(vec![(Target::Attestation, Want::Verify)]),
        _ => Err(format!("{code}: the manifest states no signature verdict for this case")),
    }
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().collect();
    if argv.len() != 3 {
        eprintln!("usage: mldsa-vectors <vectors-dir> <verify-attestation.sh>");
        return ExitCode::from(2);
    }
    match run(Path::new(&argv[1]), Path::new(&argv[2])) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(2)
        }
    }
}

fn run(dir: &Path, script: &Path) -> Result<ExitCode, String> {
    let manifest = read_json(&dir.join("vectors.json"))?;
    let cases = manifest
        .get("cases")
        .and_then(Value::as_array)
        .ok_or("vectors.json has no cases")?;
    let script_text = read_text(script)?;
    let canon_py = extract_assignment(&script_text, "CANON_PY")?;
    let canon_status_py = extract_assignment(&script_text, "CANON_STATUS_PY")?;
    let tmp = std::env::temp_dir().join(format!("mldsa-vectors-{}", std::process::id()));
    fs::create_dir_all(&tmp).map_err(|e| e.to_string())?;
    let cx = Ctx { dir, tmp: &tmp, canon_py: &canon_py, canon_status_py: &canon_status_py };

    let (mut checked, mut skipped, mut disagreed, mut signatures) = (0usize, 0usize, 0usize, 0usize);
    for case in cases {
        let id = case["id"].as_str().unwrap_or("?");
        let args: Vec<String> = case["args"]
            .as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
            .unwrap_or_default();
        let exit = case["expect"]["exit"].as_i64().unwrap_or(-1);
        let code = case["expect"]["code"].as_str().unwrap_or("");
        let matched = case["expect"]["match"].as_str().unwrap_or("");
        let targets = match plan(&args, exit, code, matched) {
            Ok(t) => t,
            Err(why) => {
                println!("SKIP  {id}: {why}");
                skipped += 1;
                continue;
            }
        };
        let mut lines = Vec::new();
        let mut bad = Vec::new();
        let mut setup_skip = None;
        for (target, want) in targets {
            let input = match target {
                Target::Attestation => attestation_input(&cx, &args),
                Target::StatusList => status_input(&cx, &args),
            };
            let input = match input {
                Ok(i) => i,
                // Inputs the primitive cannot even be handed. For a case that
                // must verify that is a failure of the run; for a case that must
                // be rejected it is a reason to skip, listed in the output.
                Err(e) if want == Want::Verify => {
                    bad.push(format!("{}: cannot build the inputs: {e}", target.name()));
                    continue;
                }
                Err(e) => {
                    setup_skip = Some(format!("{}: {e}", target.name()));
                    continue;
                }
            };
            let manifest_key = match target {
                Target::Attestation => "canonical_sha256",
                Target::StatusList => "status_canonical_sha256",
            };
            if let Some(expected) = case.get(manifest_key).and_then(Value::as_str) {
                if expected != input.canonical_sha256 {
                    bad.push(format!("{}: canonical bytes differ from the manifest ({} != {expected})", target.name(), input.canonical_sha256));
                    continue;
                }
            }
            let accepted = UnparsedPublicKey::new(&ML_DSA_65, &input.public_key)
                .verify(&input.signing_input, &input.signature)
                .is_ok();
            signatures += 1;
            let want_accept = want == Want::Verify;
            let verdict = if accepted { "accepted" } else { "rejected" };
            let wanted = if want_accept { "accepted" } else { "rejected" };
            if accepted == want_accept {
                lines.push(format!("{}: {verdict}", target.name()));
            } else {
                bad.push(format!("{}: primitive {verdict}, reference says {wanted}", target.name()));
            }
        }
        if !bad.is_empty() {
            println!("FAIL  {id}: {}", bad.join("; "));
            disagreed += 1;
        } else if let (Some(why), true) = (&setup_skip, lines.is_empty()) {
            println!("SKIP  {id}: {why}");
            skipped += 1;
        } else {
            println!("ok    {id}: {}", lines.join(", "));
            checked += 1;
        }
    }
    let _ = fs::remove_dir_all(&tmp);

    println!();
    println!(
        "cases: {} total, {checked} checked and agreed, {disagreed} disagreed, {skipped} skipped; {signatures} signature verdicts compared",
        cases.len()
    );
    if disagreed > 0 {
        println!("FAILED: the primitive and the reference disagree on {disagreed} case(s)");
        return Ok(ExitCode::from(1));
    }
    if checked < MIN_CHECKED {
        println!("FAILED: {checked} cases checked, fewer than the floor of {MIN_CHECKED}; cases were skipped that used to be checked");
        return Ok(ExitCode::from(1));
    }
    Ok(ExitCode::SUCCESS)
}
