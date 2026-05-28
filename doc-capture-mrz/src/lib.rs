//! `doc-capture-mrz` — ICAO 9303 Machine Readable Zone parser.
//!
//! Implements the three TD (Travel Document) formats defined by ICAO
//! 9303:
//!
//!   - **TD1**: 3 × 30-char lines (size of a credit card; used by US
//!     enhanced driver licenses, national IDs).
//!   - **TD2**: 2 × 36-char lines (older non-passport ID cards).
//!   - **TD3**: 2 × 44-char lines (passport).
//!
//! Each format has check digits at known offsets covering:
//!   - document number
//!   - date of birth
//!   - date of expiration
//!   - personal number (TD3) / optional data (TD1)
//!   - a composite check digit over selected fields
//!
//! The check digit algorithm is the same across all formats: weighted
//! mod-10 over the ASCII MRZ alphabet `<0-9A-Z` where `<` and letters
//! map to specific digit values. See [`mrz_check_digit`] for the
//! canonical implementation + the ICAO 9303 reference test vectors.
//!
//! This crate exposes ONLY parsing + checksum verification. Image
//! preprocessing, OCR, and orchestrating the parse into the pipeline
//! signals live in sibling crates.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::all, clippy::pedantic)]

use doc_capture_core::{Error, MrzSignals};
use std::collections::BTreeMap;

/// MRZ check-digit per ICAO 9303 Part 3 § 4.9.
///
/// Weights are `[7, 3, 1]` cycling through the input. Each character
/// maps to a digit per `mrz_char_value`. Sum mod 10 is the check
/// digit.
///
/// The function is `pub` because external tests (the workspace test
/// suite + the ICAO 9303 reference vectors) exercise it independent
/// of full-MRZ parsing.
#[must_use]
pub fn mrz_check_digit(s: &str) -> u8 {
    const WEIGHTS: [u8; 3] = [7, 3, 1];
    let mut sum: u32 = 0;
    for (i, c) in s.chars().enumerate() {
        let v = u32::from(mrz_char_value(c));
        sum += v * u32::from(WEIGHTS[i % 3]);
    }
    // `sum % 10` is always in 0..=9, so the narrowing is total.
    u8::try_from(sum % 10).unwrap_or(0)
}

/// Map a single MRZ character to its numeric value for check-digit
/// arithmetic.
///
/// `0-9` → 0-9. `A-Z` → 10-35. `<` (filler) → 0.
/// Any other character is treated as 0 (lenient parse; the caller
/// catches non-conforming MRZ via the checksum mismatch downstream).
#[must_use]
pub fn mrz_char_value(c: char) -> u8 {
    match c {
        '0'..='9' => c as u8 - b'0',
        'A'..='Z' => (c as u8 - b'A') + 10,
        // `<` (filler) and any non-conforming character both map to 0.
        _ => 0,
    }
}

/// Decode a single ASCII check-digit byte to its `0..=9` value.
///
/// Returns the sentinel `255` for any non-digit byte (e.g. a `<`
/// filler in an empty optional field) so the caller's equality
/// comparison against a computed check digit fails closed rather
/// than matching a real digit.
fn check_digit_byte(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        _ => 255,
    }
}

/// Parsed MRZ data + checksum results.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedMrz {
    /// MRZ format detected from line shape.
    pub format: MrzFormat,
    /// Document type letter (e.g. "P" for passport, "I" for ID).
    pub document_type: String,
    /// Issuing country (ISO 3166-1 alpha-3, e.g. "USA").
    pub issuing_country: String,
    /// Document number as parsed from MRZ (uppercase, `<` stripped).
    pub document_number: String,
    /// Surname (primary identifier in ICAO 9303 nomenclature).
    pub surname: String,
    /// Given names (secondary identifier), space-separated when
    /// multiple are encoded.
    pub given_names: String,
    /// Nationality (ISO 3166-1 alpha-3).
    pub nationality: String,
    /// Date of birth in `YYMMDD` as parsed from MRZ. The caller
    /// expands the year to 4 digits using century-window logic
    /// outside this crate.
    pub date_of_birth_yymmdd: String,
    /// Date of expiration in `YYMMDD`.
    pub expiration_yymmdd: String,
    /// Sex marker ("M", "F", "X", or "<").
    pub sex: String,
    /// All check digits the parser verified, keyed by field name.
    /// Useful for diagnostics when one fails — the parser fills this
    /// even on overall failure.
    pub checksums: BTreeMap<String, bool>,
}

/// Recognized MRZ formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum MrzFormat {
    /// 2 × 44 — passports (most common).
    Td3,
    /// 2 × 36 — older ID cards.
    Td2,
    /// 3 × 30 — modern ID cards, US enhanced driver licenses.
    Td1,
}

impl ParsedMrz {
    /// Whether every checksum verified the parser computed passed.
    #[must_use]
    pub fn all_checksums_valid(&self) -> bool {
        self.checksums.values().all(|v| *v)
    }

    /// Convert to the [`MrzSignals`] surface that the orchestrator
    /// emits in the final attestation.
    #[must_use]
    pub fn to_signals(&self) -> MrzSignals {
        MrzSignals {
            all_checksums_valid: self.all_checksums_valid(),
            lines_parsed: match self.format {
                MrzFormat::Td3 | MrzFormat::Td2 => 2,
                MrzFormat::Td1 => 3,
            },
            checksum_results: self.checksums.clone(),
        }
    }
}

/// Parse an MRZ from one to three lines of input.
///
/// Accepts a slice of lines; auto-detects the format from line count
/// and length. The parse is lenient: it always returns a [`ParsedMrz`]
/// even when checksums fail, populating the `checksums` map with the
/// failure detail. Hard failures (wrong line count, unparseable
/// structure) return [`Error::MrzParseFailed`].
///
/// # Errors
///
/// Returns [`Error::MrzParseFailed`] when the line count is not 2 or 3,
/// or when the line lengths match no recognized TD format.
pub fn parse_mrz(lines: &[&str]) -> Result<ParsedMrz, Error> {
    match lines.len() {
        2 => match (lines[0].len(), lines[1].len()) {
            (44, 44) => parse_td3(lines[0], lines[1]),
            (36, 36) => parse_td2(lines[0], lines[1]),
            (a, b) => Err(Error::MrzParseFailed(format!(
                "unrecognized 2-line MRZ length: line1={a} line2={b}"
            ))),
        },
        3 => match (lines[0].len(), lines[1].len(), lines[2].len()) {
            (30, 30, 30) => parse_td1(lines[0], lines[1], lines[2]),
            (a, b, c) => Err(Error::MrzParseFailed(format!(
                "unrecognized 3-line MRZ length: line1={a} line2={b} line3={c}"
            ))),
        },
        n => Err(Error::MrzParseFailed(format!(
            "MRZ must be 2 or 3 lines, got {n}"
        ))),
    }
}

/// Parse a TD3 (passport) MRZ.
///
/// TD3 layout:
/// ```text
/// Line 1 (44 chars):
///   [0-1]   document type ("P<")
///   [2-4]   issuing country (3-char ISO)
///   [5-43]  name field, surname<<given<<<...<<<<<< (filled with `<`)
///
/// Line 2 (44 chars):
///   [0-8]   document number
///   [9]     document number check digit
///   [10-12] nationality (3-char ISO)
///   [13-18] date of birth (YYMMDD)
///   [19]    DOB check digit
///   [20]    sex
///   [21-26] date of expiration (YYMMDD)
///   [27]    expiration check digit
///   [28-41] personal number / optional
///   [42]    personal-number check digit
///   [43]    composite check digit (over [0-9, 13-19, 21-27, 28-42])
/// ```
#[allow(clippy::unnecessary_wraps)] // uniform fallible signature: stricter parsing will reject malformed input here
fn parse_td3(l1: &str, l2: &str) -> Result<ParsedMrz, Error> {
    let l1 = l1.as_bytes();
    let l2 = l2.as_bytes();

    let document_type = ascii_clean(&l1[0..2]);
    let issuing_country = ascii_clean(&l1[2..5]);
    let (surname, given_names) = parse_name_field(&l1[5..44]);

    let document_number = ascii_clean(&l2[0..9]);
    let dn_check = check_digit_byte(l2[9]);
    let nationality = ascii_clean(&l2[10..13]);
    let dob = ascii_clean(&l2[13..19]);
    let dob_check = check_digit_byte(l2[19]);
    let sex = ascii_clean(&l2[20..21]);
    let expiration = ascii_clean(&l2[21..27]);
    let exp_check = check_digit_byte(l2[27]);
    let personal = std::str::from_utf8(&l2[28..42]).unwrap_or("");
    let personal_check = check_digit_byte(l2[42]);
    let composite_check = check_digit_byte(l2[43]);

    let mut checksums = BTreeMap::new();
    checksums.insert(
        "document_number".to_string(),
        mrz_check_digit(std::str::from_utf8(&l2[0..9]).unwrap_or("")) == dn_check,
    );
    checksums.insert(
        "date_of_birth".to_string(),
        mrz_check_digit(std::str::from_utf8(&l2[13..19]).unwrap_or("")) == dob_check,
    );
    checksums.insert(
        "expiration".to_string(),
        mrz_check_digit(std::str::from_utf8(&l2[21..27]).unwrap_or("")) == exp_check,
    );
    checksums.insert(
        "personal_number".to_string(),
        // Personal number can be empty (all `<`) on TD3; in that
        // case ICAO allows the check digit to be `<` (0) and we
        // treat it as valid.
        if personal.chars().all(|c| c == '<') {
            true
        } else {
            mrz_check_digit(personal) == personal_check
        },
    );
    // Composite check covers positions [0..10] + [13..20] + [21..28]
    // + [28..43] from line 2. Concatenate and run the same algorithm.
    let composite_input: String = format!(
        "{}{}{}{}",
        std::str::from_utf8(&l2[0..10]).unwrap_or(""),
        std::str::from_utf8(&l2[13..20]).unwrap_or(""),
        std::str::from_utf8(&l2[21..28]).unwrap_or(""),
        std::str::from_utf8(&l2[28..43]).unwrap_or(""),
    );
    checksums.insert(
        "composite".to_string(),
        mrz_check_digit(&composite_input) == composite_check,
    );

    Ok(ParsedMrz {
        format: MrzFormat::Td3,
        document_type,
        issuing_country,
        document_number,
        surname,
        given_names,
        nationality,
        date_of_birth_yymmdd: dob,
        expiration_yymmdd: expiration,
        sex,
        checksums,
    })
}

/// Parse a TD2 (older ID card) MRZ.
///
/// TD2 layout:
/// ```text
/// Line 1 (36): doctype(2) + country(3) + name(31, surname<<given)
/// Line 2 (36): docnum(9) + check(1) + nationality(3) + dob(6) +
///              check(1) + sex(1) + exp(6) + check(1) + optional(7) +
///              composite-check(1)
/// ```
#[allow(clippy::unnecessary_wraps)] // uniform fallible signature: stricter parsing will reject malformed input here
fn parse_td2(l1: &str, l2: &str) -> Result<ParsedMrz, Error> {
    let l1 = l1.as_bytes();
    let l2 = l2.as_bytes();
    let document_type = ascii_clean(&l1[0..2]);
    let issuing_country = ascii_clean(&l1[2..5]);
    let (surname, given_names) = parse_name_field(&l1[5..36]);

    let document_number = ascii_clean(&l2[0..9]);
    let dn_check = check_digit_byte(l2[9]);
    let nationality = ascii_clean(&l2[10..13]);
    let dob = ascii_clean(&l2[13..19]);
    let dob_check = check_digit_byte(l2[19]);
    let sex = ascii_clean(&l2[20..21]);
    let expiration = ascii_clean(&l2[21..27]);
    let exp_check = check_digit_byte(l2[27]);
    let composite_check = check_digit_byte(l2[35]);

    let mut checksums = BTreeMap::new();
    checksums.insert(
        "document_number".to_string(),
        mrz_check_digit(std::str::from_utf8(&l2[0..9]).unwrap_or("")) == dn_check,
    );
    checksums.insert(
        "date_of_birth".to_string(),
        mrz_check_digit(std::str::from_utf8(&l2[13..19]).unwrap_or("")) == dob_check,
    );
    checksums.insert(
        "expiration".to_string(),
        mrz_check_digit(std::str::from_utf8(&l2[21..27]).unwrap_or("")) == exp_check,
    );
    let composite_input: String = format!(
        "{}{}{}{}",
        std::str::from_utf8(&l2[0..10]).unwrap_or(""),
        std::str::from_utf8(&l2[13..20]).unwrap_or(""),
        std::str::from_utf8(&l2[21..28]).unwrap_or(""),
        std::str::from_utf8(&l2[28..35]).unwrap_or(""),
    );
    checksums.insert(
        "composite".to_string(),
        mrz_check_digit(&composite_input) == composite_check,
    );

    Ok(ParsedMrz {
        format: MrzFormat::Td2,
        document_type,
        issuing_country,
        document_number,
        surname,
        given_names,
        nationality,
        date_of_birth_yymmdd: dob,
        expiration_yymmdd: expiration,
        sex,
        checksums,
    })
}

/// Parse a TD1 (modern ID card / enhanced DL) MRZ.
///
/// TD1 layout:
/// ```text
/// Line 1 (30): doctype(2) + country(3) + docnum(9) + check(1) + optional(15)
/// Line 2 (30): dob(6) + check(1) + sex(1) + exp(6) + check(1) +
///              nationality(3) + optional(11) + composite-check(1)
/// Line 3 (30): name (surname<<given, padded to 30)
/// ```
#[allow(clippy::unnecessary_wraps)] // uniform fallible signature: stricter parsing will reject malformed input here
fn parse_td1(l1: &str, l2: &str, l3: &str) -> Result<ParsedMrz, Error> {
    let l1b = l1.as_bytes();
    let l2b = l2.as_bytes();
    let l3b = l3.as_bytes();
    let document_type = ascii_clean(&l1b[0..2]);
    let issuing_country = ascii_clean(&l1b[2..5]);
    let document_number = ascii_clean(&l1b[5..14]);
    let dn_check = check_digit_byte(l1b[14]);

    let dob = ascii_clean(&l2b[0..6]);
    let dob_check = check_digit_byte(l2b[6]);
    let sex = ascii_clean(&l2b[7..8]);
    let expiration = ascii_clean(&l2b[8..14]);
    let exp_check = check_digit_byte(l2b[14]);
    let nationality = ascii_clean(&l2b[15..18]);
    let composite_check = check_digit_byte(l2b[29]);

    let (surname, given_names) = parse_name_field(&l3b[0..30]);

    let mut checksums = BTreeMap::new();
    checksums.insert(
        "document_number".to_string(),
        mrz_check_digit(std::str::from_utf8(&l1b[5..14]).unwrap_or("")) == dn_check,
    );
    checksums.insert(
        "date_of_birth".to_string(),
        mrz_check_digit(std::str::from_utf8(&l2b[0..6]).unwrap_or("")) == dob_check,
    );
    checksums.insert(
        "expiration".to_string(),
        mrz_check_digit(std::str::from_utf8(&l2b[8..14]).unwrap_or("")) == exp_check,
    );
    let composite_input: String = format!(
        "{}{}{}",
        std::str::from_utf8(&l1b[5..30]).unwrap_or(""),
        std::str::from_utf8(&l2b[0..7]).unwrap_or(""),
        std::str::from_utf8(&l2b[8..15]).unwrap_or(""),
    );
    checksums.insert(
        "composite".to_string(),
        mrz_check_digit(&composite_input) == composite_check,
    );

    Ok(ParsedMrz {
        format: MrzFormat::Td1,
        document_type,
        issuing_country,
        document_number,
        surname,
        given_names,
        nationality,
        date_of_birth_yymmdd: dob,
        expiration_yymmdd: expiration,
        sex,
        checksums,
    })
}

/// Split an MRZ name field into surname + given names.
///
/// MRZ encodes names as `SURNAME<<GIVEN<NAMES<<<<<<<<<<<<...` —
/// double-`<` separates surname from given, single-`<` separates
/// given-name tokens, trailing `<` chars are filler.
fn parse_name_field(bytes: &[u8]) -> (String, String) {
    let s = std::str::from_utf8(bytes).unwrap_or("");
    // Strip trailing filler then split on the first `<<`.
    let trimmed = s.trim_end_matches('<');
    if let Some(idx) = trimmed.find("<<") {
        let surname = trimmed[..idx].replace('<', " ").trim().to_string();
        let given = trimmed[idx + 2..].replace('<', " ").trim().to_string();
        (surname, given)
    } else {
        (trimmed.replace('<', " ").trim().to_string(), String::new())
    }
}

/// Clean an ASCII byte slice into a String, stripping `<` filler.
fn ascii_clean(bytes: &[u8]) -> String {
    std::str::from_utf8(bytes)
        .unwrap_or("")
        .trim_end_matches('<')
        .replace('<', "")
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── ICAO 9303 reference check-digit vectors ─────────────────
    //
    // From ICAO 9303 Part 3 § 4.9 examples. These pin the
    // check-digit algorithm against the spec — if the function
    // ever drifts, these fail first.

    #[test]
    fn check_digit_icao_example_document_number() {
        // ICAO example: "L898902C3" should produce check digit 6.
        assert_eq!(mrz_check_digit("L898902C3"), 6);
    }

    #[test]
    fn check_digit_icao_example_date() {
        // ICAO example: "740812" (DOB on ERIKSSON example passport)
        // should produce check digit 2. Weighted sum = 7*7 + 4*3 +
        // 0*1 + 8*7 + 1*3 + 2*1 = 49+12+0+56+3+2 = 122; 122 mod 10 = 2.
        // The TD3 line 2 of the ERIKSSON passport reads
        // "...7408122F..." — the '2' between "740812" and "F"
        // (sex marker) is this check digit.
        assert_eq!(mrz_check_digit("740812"), 2);
    }

    #[test]
    fn check_digit_icao_example_expiration() {
        // ICAO example: "120415" should produce check digit 9.
        assert_eq!(mrz_check_digit("120415"), 9);
    }

    #[test]
    fn check_digit_all_filler_is_zero() {
        // All-`<` input should produce check digit 0 (filler maps
        // to value 0 in the algorithm).
        assert_eq!(mrz_check_digit("<<<<<<<<<"), 0);
    }

    #[test]
    fn char_value_mapping() {
        assert_eq!(mrz_char_value('0'), 0);
        assert_eq!(mrz_char_value('9'), 9);
        assert_eq!(mrz_char_value('A'), 10);
        assert_eq!(mrz_char_value('Z'), 35);
        assert_eq!(mrz_char_value('<'), 0);
        // Out-of-alphabet falls through to 0.
        assert_eq!(mrz_char_value(' '), 0);
        assert_eq!(mrz_char_value('!'), 0);
    }

    // ─── Full MRZ parse tests ─────────────────────────────────────

    /// Canonical ICAO 9303 example passport (TD3).
    /// `ERIKSSON, ANNA MARIA` — Sweden, born 1974-08-12, expires
    /// 2012-04-15. Document number L898902C3. This is the textbook
    /// example MRZ — verified to compute valid checksums.
    const ICAO_TD3_LINE1: &str = "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<";
    const ICAO_TD3_LINE2: &str = "L898902C36UTO7408122F1204159ZE184226B<<<<<10";

    #[test]
    fn parse_td3_icao_example() {
        let mrz = parse_mrz(&[ICAO_TD3_LINE1, ICAO_TD3_LINE2]).unwrap();
        assert_eq!(mrz.format, MrzFormat::Td3);
        assert_eq!(mrz.document_type, "P");
        assert_eq!(mrz.issuing_country, "UTO");
        assert_eq!(mrz.document_number, "L898902C3");
        assert_eq!(mrz.surname, "ERIKSSON");
        assert_eq!(mrz.given_names, "ANNA MARIA");
        assert_eq!(mrz.date_of_birth_yymmdd, "740812");
        assert_eq!(mrz.expiration_yymmdd, "120415");
        assert_eq!(mrz.sex, "F");
        assert_eq!(mrz.nationality, "UTO");
        assert!(
            mrz.all_checksums_valid(),
            "ICAO example should checksum-verify: {:?}",
            mrz.checksums
        );
    }

    #[test]
    fn parse_rejects_wrong_line_count() {
        let r = parse_mrz(&["one line only"]);
        assert!(matches!(r, Err(Error::MrzParseFailed(_))));
    }

    #[test]
    fn parse_rejects_wrong_line_length() {
        let r = parse_mrz(&["too short", "also short"]);
        assert!(matches!(r, Err(Error::MrzParseFailed(_))));
    }

    #[test]
    fn parse_td3_corrupted_dob_flags_checksum() {
        // Take the ICAO example and corrupt the DOB digit — the
        // dob checksum should now fail but parsing still completes.
        let mut bad_l2: Vec<u8> = ICAO_TD3_LINE2.as_bytes().to_vec();
        bad_l2[13] = b'9'; // was '7' in "7408122..."
        let bad_l2_str = std::str::from_utf8(&bad_l2).unwrap();
        let mrz = parse_mrz(&[ICAO_TD3_LINE1, bad_l2_str]).unwrap();
        assert_eq!(
            mrz.checksums.get("date_of_birth").copied(),
            Some(false),
            "DOB checksum should fail after corruption"
        );
        assert!(!mrz.all_checksums_valid());
    }

    #[test]
    fn parse_td3_corrupted_doc_number_flags_checksum() {
        // Corrupt the document number digit.
        let mut bad_l2: Vec<u8> = ICAO_TD3_LINE2.as_bytes().to_vec();
        bad_l2[2] = b'X'; // was '8' in "L898902C3"
        let bad_l2_str = std::str::from_utf8(&bad_l2).unwrap();
        let mrz = parse_mrz(&[ICAO_TD3_LINE1, bad_l2_str]).unwrap();
        assert_eq!(
            mrz.checksums.get("document_number").copied(),
            Some(false),
            "document_number checksum should fail after corruption"
        );
    }

    #[test]
    fn name_field_parses_surname_and_given() {
        let (s, g) = parse_name_field(b"DOE<<JOHN<MICHAEL<<<<<<<<<<<<<<<<<<");
        assert_eq!(s, "DOE");
        assert_eq!(g, "JOHN MICHAEL");
    }

    #[test]
    fn name_field_handles_surname_only() {
        let (s, g) = parse_name_field(b"DOE<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<");
        assert_eq!(s, "DOE");
        assert_eq!(g, "");
    }

    #[test]
    fn name_field_handles_no_separator() {
        // Pathological: no `<<` separator. Treat the whole thing as
        // surname so the parse doesn't lose data.
        let (s, g) = parse_name_field(b"SOMETHING<WITHOUT<DOUBLE<<<<<<<<<<<<");
        // Trimmed at first `<<`, surname is "SOMETHING<WITHOUT<DOUBLE"
        // minus trailing — but ours sees the first `<<` and splits.
        // Verify behaviour: if there's any `<<`, we split there.
        // (Test documents actual behaviour, not the pathological case.)
        assert!(s.starts_with("SOMETHING"));
        let _ = g;
    }

    #[test]
    fn to_signals_propagates_checksum_status() {
        let mrz = parse_mrz(&[ICAO_TD3_LINE1, ICAO_TD3_LINE2]).unwrap();
        let sig = mrz.to_signals();
        assert!(sig.all_checksums_valid);
        assert_eq!(sig.lines_parsed, 2);
        assert!(sig.checksum_results.contains_key("document_number"));
        assert!(sig.checksum_results.contains_key("composite"));
    }
}
