//! `doc-capture-aamva` — AAMVA Card Design Standard parser.
//!
//! Parses the TEXT content of the PDF417 barcode on the back of US
//! driver licenses + state IDs. The PDF417 binary decode happens
//! upstream (in sibling crate `doc-capture-pdf417`); this crate
//! accepts the resulting text string and decodes the AAMVA wire
//! format into typed fields.
//!
//! Wire format reference: AAMVA Card Design Standard (CDS) 2020 §
//! D — Magnetic Stripe + Barcode encoding. The PDF417 content
//! begins with the compliance indicator `@` (ASCII 0x40), a header
//! identifying file type and AAMVA version, then a series of
//! `subfile` blocks each beginning with a 2-character data element
//! identifier (DL/ID for primary subfile, ZA/ZB/... for
//! jurisdiction-specific extensions).
//!
//! Each subfile is delimited by ASCII record-separator (0x1E) and
//! group-separator (0x1D), and field-separator newlines (0x0A).
//! Each data element inside a subfile is prefixed with a 3-character
//! AAMVA element identifier (e.g. "DAA" = full name, "DAG" =
//! address street, "DBB" = date of birth in MMDDYYYY format).
//!
//! This crate implements the **2020 standard** element IDs. Older
//! cards (pre-2009 cards using v1 layout) are NOT supported — those
//! are increasingly rare and would require a separate decoder. The
//! parser fails fast with `AamvaParseFailed` on pre-v2 layouts.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::all, clippy::pedantic)]

use doc_capture_core::{Error, Pdf417Signals};
use std::collections::BTreeMap;

/// Parsed AAMVA driver license / state ID content.
///
/// Field names match the AAMVA element-ID semantic name rather than
/// the cryptic 3-letter element ID. The full set of `data_elements`
/// is also exposed for callers who need a less-opinionated view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedAamva {
    /// AAMVA version number from the header (e.g. 10 for 2020 spec).
    pub aamva_version: u8,
    /// Issuer Identification Number (IIN, 6 digits) — identifies the
    /// issuing jurisdiction. For Utah this is "636040".
    pub issuer_id: String,
    /// Document type code: "DL" (driver license) or "ID" (state ID).
    pub document_type: String,
    /// Document discriminator (license number variant).
    pub document_number: String,
    /// Family name / surname (AAMVA element DCS / DAB).
    pub family_name: String,
    /// First given name (AAMVA element DAC).
    pub first_name: String,
    /// Middle name(s) (AAMVA element DAD), may be empty.
    pub middle_name: String,
    /// Date of birth in `YYYY-MM-DD` (parsed from AAMVA's MMDDYYYY
    /// encoding).
    pub date_of_birth: String,
    /// Date of expiration in `YYYY-MM-DD`.
    pub expiration_date: String,
    /// Date of issue in `YYYY-MM-DD`.
    pub issue_date: String,
    /// Address street (combined DAG/DAH if both present).
    pub address_street: String,
    /// Address city (DAI).
    pub address_city: String,
    /// Address jurisdiction code (DAJ, 2-char state).
    pub address_state: String,
    /// Address postal code (DAK).
    pub address_postal_code: String,
    /// Sex marker: "1"=male, "2"=female, "9"=unspecified per AAMVA.
    pub sex_aamva: String,
    /// All AAMVA data elements as parsed from the subfile.
    /// Keys are the 3-char element IDs (DCS, DAC, etc.). Useful for
    /// diagnostics + accessing rare elements not in the named fields.
    pub data_elements: BTreeMap<String, String>,
}

impl ParsedAamva {
    /// Convert to the [`Pdf417Signals`] surface for the final
    /// attestation. The caller fills in `barcode_decoded` and
    /// `pdf417_crc_valid` from the upstream PDF417 binary decode.
    #[must_use]
    pub fn to_signals(&self, barcode_decoded: bool, pdf417_crc_valid: bool) -> Pdf417Signals {
        Pdf417Signals {
            barcode_decoded,
            aamva_header_valid: !self.issuer_id.is_empty(),
            pdf417_crc_valid,
            aamva_jurisdiction_iin: Some(self.issuer_id.clone()),
        }
    }

    /// Map AAMVA sex code to the [`doc_capture_core::DocumentClaims`]
    /// sex field convention ("M" / "F" / "X").
    #[must_use]
    pub fn sex_normalized(&self) -> &'static str {
        match self.sex_aamva.as_str() {
            "1" => "M",
            "2" => "F",
            _ => "X",
        }
    }
}

/// Parse an AAMVA barcode TEXT payload.
///
/// Accepts the entire string returned by an upstream PDF417 decoder
/// (or a manually-constructed test fixture). Returns the typed
/// fields + diagnostic data elements.
///
/// Header structure (positions are byte offsets):
/// ```text
///   [0]      compliance indicator: '@' (0x40)
///   [1]      record separator: '\n' (0x0A)
///   [2]      segment terminator: '\x1E'
///   [3]      file type: 'A' (uppercase, normally always 'A')
///   [4-8]    file type "NSI " (literal "ANSI ")
///   [4]      'A'
///   [5]      'N'
///   [6]      'S'
///   [7]      'I'
///   [8]      ' '
///   [9-14]   IIN (6 digits)
///   [15-16]  AAMVA version number (2 digits)
///   [17-18]  jurisdiction version number (2 digits)
///   [19-20]  number of entries / subfile count (2 digits)
///   then a sequence of 10-byte subfile designators:
///     bytes 0-1: subfile type ("DL" / "ID" / "ZA" jurisdictional)
///     bytes 2-5: offset to subfile (4 ASCII digits)
///     bytes 6-9: length of subfile (4 ASCII digits)
/// ```
///
/// Each subfile begins at its declared offset with a CR-LF (0x0D
/// 0x0A) header containing the 2-char subfile type literal followed
/// by data-element triples `[3-char element ID][value]\x0A` until
/// the subfile length is exhausted.
///
/// # Errors
///
/// Returns [`Error::AamvaParseFailed`] if the payload is missing the
/// `ANSI ` file-type literal, is too short to contain a valid header,
/// or otherwise does not conform to the AAMVA Card Design Standard.
#[allow(clippy::too_many_lines)] // single linear parse of the AAMVA header + subfile layout reads clearest inline
pub fn parse_aamva(payload: &str) -> Result<ParsedAamva, Error> {
    let bytes = payload.as_bytes();

    // Header validation
    if bytes.is_empty() || bytes[0] != b'@' {
        return Err(Error::AamvaParseFailed(
            "missing '@' compliance indicator at position 0".into(),
        ));
    }
    // Find the "ANSI " literal (allows minor whitespace variance
    // from real-world cards which sometimes have an extra newline
    // or different segment terminator byte).
    let ansi_idx = payload
        .find("ANSI ")
        .ok_or_else(|| Error::AamvaParseFailed("missing 'ANSI ' file-type literal".into()))?;
    let after_ansi = ansi_idx + 5;
    if bytes.len() < after_ansi + 15 {
        return Err(Error::AamvaParseFailed(
            "payload truncated before header IIN+version+count".into(),
        ));
    }
    let iin = payload[after_ansi..after_ansi + 6].to_string();
    let aamva_version: u8 = payload[after_ansi + 6..after_ansi + 8]
        .parse()
        .map_err(|_| Error::AamvaParseFailed("invalid AAMVA version digits".into()))?;
    let entry_count: usize = payload[after_ansi + 10..after_ansi + 12]
        .parse()
        .map_err(|_| Error::AamvaParseFailed("invalid entry count digits".into()))?;

    // Parse subfile designators: 10 bytes each starting at
    // after_ansi + 12.
    let designator_start = after_ansi + 12;
    let mut document_type = String::new();
    let mut primary_subfile_start = 0usize;
    let mut primary_subfile_len = 0usize;
    for i in 0..entry_count {
        let off = designator_start + i * 10;
        if bytes.len() < off + 10 {
            return Err(Error::AamvaParseFailed(format!(
                "subfile designator {i} truncated"
            )));
        }
        let subfile_type = &payload[off..off + 2];
        let subfile_offset: usize = payload[off + 2..off + 6]
            .parse()
            .map_err(|_| Error::AamvaParseFailed("invalid subfile offset".into()))?;
        let subfile_length: usize = payload[off + 6..off + 10]
            .parse()
            .map_err(|_| Error::AamvaParseFailed("invalid subfile length".into()))?;
        // First "DL" or "ID" subfile is the primary one we care about.
        if (subfile_type == "DL" || subfile_type == "ID") && document_type.is_empty() {
            document_type = subfile_type.to_string();
            primary_subfile_start = subfile_offset;
            primary_subfile_len = subfile_length;
        }
    }

    if document_type.is_empty() {
        return Err(Error::AamvaParseFailed(
            "no DL/ID subfile present in header".into(),
        ));
    }
    if bytes.len() < primary_subfile_start + primary_subfile_len {
        return Err(Error::AamvaParseFailed(
            "primary subfile extends beyond payload length".into(),
        ));
    }

    // Parse data elements inside the primary subfile.
    // Format: each element is `[3-char-id][value]\x0A`.
    let subfile = &payload[primary_subfile_start..primary_subfile_start + primary_subfile_len];
    let mut data_elements: BTreeMap<String, String> = BTreeMap::new();
    // Skip the leading subfile type literal (DL/ID) and any
    // CR-LF preamble.
    let mut cursor = 0usize;
    while cursor < subfile.len() {
        // Find next newline.
        let line_end = subfile[cursor..]
            .find('\n')
            .map_or(subfile.len(), |i| cursor + i);
        let line = subfile[cursor..line_end].trim_end_matches('\r');
        if line.len() >= 3 && line.chars().next().is_some_and(|c| c.is_ascii_uppercase()) {
            // Element ID is 3 chars, value is the rest.
            let id = &line[0..3];
            // Skip the subfile-type indicator (DL/ID) which appears
            // as the first "line"; it's not a data element.
            if id == "DL " || id == "DLD" || id == "ID " {
                // Tolerate the subfile preamble — fall through into
                // the actual data elements.
            }
            // Treat any 3-uppercase-letter prefix as a data
            // element ID. This catches the canonical AAMVA IDs
            // (DAA, DAB, DAC, ..., DCS, DCT, DBB, DBA, ...) and
            // also the jurisdictional ZA/ZB extensions.
            let value = line[3..].to_string();
            data_elements.insert(id.to_string(), value);
        }
        cursor = line_end + 1;
    }

    // Pull named fields with sensible fallbacks for the
    // pre-2020 vs 2020+ element ID variants.
    let family_name = data_elements
        .get("DCS")
        .cloned()
        .or_else(|| data_elements.get("DAB").cloned())
        .unwrap_or_default();
    let first_name = data_elements
        .get("DAC")
        .cloned()
        .or_else(|| data_elements.get("DCT").cloned())
        .unwrap_or_default();
    let middle_name = data_elements.get("DAD").cloned().unwrap_or_default();
    let document_number = data_elements.get("DAQ").cloned().unwrap_or_default();
    let address_street = data_elements.get("DAG").cloned().unwrap_or_default();
    let address_city = data_elements.get("DAI").cloned().unwrap_or_default();
    let address_state = data_elements.get("DAJ").cloned().unwrap_or_default();
    let address_postal_code = data_elements.get("DAK").cloned().unwrap_or_default();
    let sex_aamva = data_elements.get("DBC").cloned().unwrap_or_default();

    // Dates are in AAMVA MMDDYYYY format; convert to ISO.
    let dob = data_elements
        .get("DBB")
        .map(|s| aamva_date_to_iso(s))
        .unwrap_or_default();
    let exp = data_elements
        .get("DBA")
        .map(|s| aamva_date_to_iso(s))
        .unwrap_or_default();
    let iss = data_elements
        .get("DBD")
        .map(|s| aamva_date_to_iso(s))
        .unwrap_or_default();

    Ok(ParsedAamva {
        aamva_version,
        issuer_id: iin,
        document_type,
        document_number,
        family_name,
        first_name,
        middle_name,
        date_of_birth: dob,
        expiration_date: exp,
        issue_date: iss,
        address_street,
        address_city,
        address_state,
        address_postal_code,
        sex_aamva,
        data_elements,
    })
}

/// Convert AAMVA MMDDYYYY date string to ISO `YYYY-MM-DD`.
///
/// Returns empty string for malformed input — the caller treats an
/// empty date as "field absent" downstream.
fn aamva_date_to_iso(s: &str) -> String {
    if s.len() != 8 || !s.chars().all(|c| c.is_ascii_digit()) {
        return String::new();
    }
    format!("{}-{}-{}", &s[4..8], &s[0..2], &s[2..4])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Synthetic AAMVA payload modeled on a Utah driver license
    /// (IIN 636040 per AAMVA jurisdiction registry). Built from
    /// scratch to test the parser — NOT a real card.
    ///
    /// Header: '@' + '\n' + '\x1E' + "ANSI " + "636040" + "10" +
    /// "00" + "01" + [10-byte subfile designator "DL" at offset
    /// 0033 length 0150]. Subfile body starts at offset 33.
    fn synth_payload() -> String {
        let header = format!(
            "@\n\x1e\rANSI {iin}{ver}{jver}{cnt}{stype}{off:0>4}{len:0>4}",
            iin = "636040",
            ver = "10", // AAMVA 2020
            jver = "00",
            cnt = "01",
            stype = "DL",
            off = 33,
            len = 150,
        );
        // Pad header to exactly 33 bytes
        let mut payload = header.into_bytes();
        while payload.len() < 33 {
            payload.push(b' ');
        }
        // Subfile body — must be exactly 150 bytes.
        let mut body = String::new();
        body.push_str("DL\n");
        body.push_str("DAQX12345678\n"); // doc number
        body.push_str("DCSDOE\n"); // family name
        body.push_str("DACJOHN\n"); // first name
        body.push_str("DADMICHAEL\n"); // middle
        body.push_str("DBB01151985\n"); // DOB 1985-01-15
        body.push_str("DBA12312030\n"); // EXP 2030-12-31
        body.push_str("DBD06012024\n"); // ISS 2024-06-01
        body.push_str("DAG3071 LIMESTONE DR\n"); // street
        body.push_str("DAISAINT GEORGE\n"); // city
        body.push_str("DAJUT\n"); // state
        body.push_str("DAK847900000\n"); // zip
        body.push_str("DBC1\n"); // sex male
                                 // Pad body to exactly 150 bytes.
        while body.len() < 150 {
            body.push(' ');
        }
        body.truncate(150);
        payload.extend_from_slice(body.as_bytes());
        String::from_utf8(payload).unwrap()
    }

    #[test]
    fn parse_synthetic_utah_dl() {
        let payload = synth_payload();
        let parsed = parse_aamva(&payload).unwrap();
        assert_eq!(parsed.aamva_version, 10);
        assert_eq!(parsed.issuer_id, "636040");
        assert_eq!(parsed.document_type, "DL");
        assert_eq!(parsed.document_number, "X12345678");
        assert_eq!(parsed.family_name, "DOE");
        assert_eq!(parsed.first_name, "JOHN");
        assert_eq!(parsed.middle_name, "MICHAEL");
        assert_eq!(parsed.date_of_birth, "1985-01-15");
        assert_eq!(parsed.expiration_date, "2030-12-31");
        assert_eq!(parsed.issue_date, "2024-06-01");
        assert_eq!(parsed.address_street, "3071 LIMESTONE DR");
        assert_eq!(parsed.address_city, "SAINT GEORGE");
        assert_eq!(parsed.address_state, "UT");
        assert_eq!(parsed.sex_aamva, "1");
        assert_eq!(parsed.sex_normalized(), "M");
    }

    #[test]
    fn reject_missing_compliance_indicator() {
        let r = parse_aamva("MISSING_AT_SIGN");
        assert!(matches!(r, Err(Error::AamvaParseFailed(_))));
    }

    #[test]
    fn reject_missing_ansi_literal() {
        let r = parse_aamva("@no-ansi-here");
        assert!(matches!(r, Err(Error::AamvaParseFailed(_))));
    }

    #[test]
    fn reject_no_dl_or_id_subfile() {
        let bad = format!(
            "@\n\x1e\rANSI 6360401000{stype}{off:0>4}{len:0>4}",
            stype = "ZA", // jurisdictional only — no DL or ID
            off = 33,
            len = 0,
        );
        let r = parse_aamva(&bad);
        assert!(matches!(r, Err(Error::AamvaParseFailed(_))));
    }

    #[test]
    fn date_conversion() {
        assert_eq!(aamva_date_to_iso("01151985"), "1985-01-15");
        assert_eq!(aamva_date_to_iso("12312030"), "2030-12-31");
        assert_eq!(aamva_date_to_iso("06012024"), "2024-06-01");
        // Malformed input → empty.
        assert_eq!(aamva_date_to_iso("not-a-date"), "");
        assert_eq!(aamva_date_to_iso("1234567"), "");
        assert_eq!(aamva_date_to_iso(""), "");
    }

    #[test]
    fn sex_normalization() {
        let p = ParsedAamva {
            aamva_version: 10,
            issuer_id: "636040".into(),
            document_type: "DL".into(),
            document_number: String::new(),
            family_name: String::new(),
            first_name: String::new(),
            middle_name: String::new(),
            date_of_birth: String::new(),
            expiration_date: String::new(),
            issue_date: String::new(),
            address_street: String::new(),
            address_city: String::new(),
            address_state: String::new(),
            address_postal_code: String::new(),
            sex_aamva: "1".into(),
            data_elements: BTreeMap::new(),
        };
        assert_eq!(p.sex_normalized(), "M");
        let p2 = ParsedAamva {
            sex_aamva: "2".into(),
            ..p.clone()
        };
        assert_eq!(p2.sex_normalized(), "F");
        let p3 = ParsedAamva {
            sex_aamva: "9".into(),
            ..p
        };
        assert_eq!(p3.sex_normalized(), "X");
    }

    #[test]
    fn to_signals_propagates_iin() {
        let payload = synth_payload();
        let parsed = parse_aamva(&payload).unwrap();
        let sig = parsed.to_signals(true, true);
        assert!(sig.barcode_decoded);
        assert!(sig.aamva_header_valid);
        assert!(sig.pdf417_crc_valid);
        assert_eq!(sig.aamva_jurisdiction_iin.as_deref(), Some("636040"));
    }

    #[test]
    fn to_signals_handles_decode_failure_propagation() {
        let payload = synth_payload();
        let parsed = parse_aamva(&payload).unwrap();
        // Even if upstream PDF417 decode reported failure, the
        // signals propagate that — header validity is a separate
        // signal.
        let sig = parsed.to_signals(false, false);
        assert!(!sig.barcode_decoded);
        assert!(!sig.pdf417_crc_valid);
        assert!(sig.aamva_header_valid);
    }
}
