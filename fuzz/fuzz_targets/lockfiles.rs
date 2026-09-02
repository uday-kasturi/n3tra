//! Fuzz every lockfile parser.
//!
//! Threat model §2: a hostile repository controls its own lockfiles, so these are
//! **attacker-influenced input**. A malicious PR can supply one, which makes the
//! parsers a real attack surface rather than a convenience.
//!
//! The property asserted is narrow and absolute: *no input may panic*. A panic in
//! the parser is a denial-of-service against the scan, and per INV-5 a scan that
//! dies must degrade to `unknown` rather than take the process down.
//!
//! One byte of the input selects which parser to drive, so a single corpus
//! exercises all of them and the fuzzer can learn to reach each one.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((selector, rest)) = data.split_first() else {
        return;
    };
    let Ok(text) = std::str::from_utf8(rest) else {
        return;
    };
    let label = "fuzz-input";

    match selector % 8 {
        0 => drop(n3t_parse::npm::parse_package_lock_str(text, label)),
        1 => drop(n3t_parse::npm::parse_pnpm_lock_str(text, label)),
        2 => drop(n3t_parse::npm::parse_yarn_lock_str(text, label)),
        3 => drop(n3t_parse::python::parse_uv_lock_str(text, label)),
        4 => drop(n3t_parse::python::parse_poetry_lock_str(text, label)),
        5 => drop(n3t_parse::python::parse_requirements_str(text, label)),
        6 => drop(n3t_parse::python::parse_pyproject_str(text, label)),
        _ => drop(n3t_parse::apt::parse_dpkg_status_str(
            text,
            label,
            Some("debian".to_string()),
        )),
    }
});
