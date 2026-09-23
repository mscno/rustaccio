//! Bounded-memory extraction of a publish document (`PUT /:package`).
//!
//! An npm publish body is one JSON document whose tarball payload is embedded
//! as base64 under `_attachments.<filename>.data`. This module splits the
//! document while streaming it: everything outside the first attachment's
//! `data` string is buffered as metadata (bounded by `max_metadata_bytes`),
//! while the base64 payload is decoded incrementally, hashed (SHA-512 SRI and
//! SHA-1, matching npm's `dist.integrity` / `dist.shasum`) and handed to the
//! caller in `out` for spooling.
//!
//! Exactly one attachment is supported; the assembled metadata keeps
//! `_attachments` with an empty `data` string so the caller can validate the
//! final document shape with `parse_publish_metadata`.

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use serde_json::Value;
use sha2::Digest;

/// Reason the publish document could not be split into metadata and tarball.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtractError {
    /// The document framing is not a supported npm publish shape.
    Malformed(&'static str),
    /// The metadata portion exceeded the configured bound.
    MetadataTooLarge,
}

impl std::fmt::Display for ExtractError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(reason) => write!(f, "malformed publish document: {reason}"),
            Self::MetadataTooLarge => write!(f, "publish metadata exceeds the configured limit"),
        }
    }
}

impl std::error::Error for ExtractError {}

/// Outcome of feeding a complete publish body through [`PublishExtractor`].
#[derive(Debug)]
pub enum Extracted {
    /// The whole document (no `_attachments` data was found). The caller
    /// should treat this as a metadata-only write.
    MetadataOnly(Vec<u8>),
    /// A tarball payload was found and decoded.
    Publish {
        /// The publish document with the attachment `data` string emptied.
        metadata: Vec<u8>,
        /// `sha512-<base64>` over the decoded tarball bytes.
        integrity: String,
        /// Hex SHA-1 over the decoded tarball bytes.
        shasum: String,
        /// Exact number of decoded tarball bytes.
        tarball_bytes: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Scanning the top-level object for the `_attachments` key.
    FindAttachments,
    /// Saw `"_attachments":`, expecting its object to open.
    AttachmentsOpen,
    /// Inside `_attachments`, expecting the first (and only) entry key.
    FirstEntryKey,
    /// Saw the entry key, expecting its object to open.
    AttachmentOpen,
    /// Inside the attachment object, looking for the `data` key.
    FindDataKey,
    /// Saw `"data":`, expecting the opening quote of the payload string.
    DataOpen,
    /// Inside the base64 payload string.
    Data,
    /// Past the payload; buffering the remaining document.
    Tail,
}

const MAX_KEY_BYTES: usize = 1024;

/// Streaming splitter for npm publish documents. Feed body chunks with
/// [`PublishExtractor::feed`]; decoded tarball bytes are appended to the
/// `out` vector (flush it to the spool as it grows) and digests are updated
/// in lockstep. Call [`PublishExtractor::finish`] at end of stream.
pub struct PublishExtractor {
    max_metadata_bytes: usize,
    phase: Phase,
    meta: Vec<u8>,
    depth: u32,
    in_string: bool,
    escape: bool,
    key_buf: Vec<u8>,
    key_valid: bool,
    last_string: Option<Vec<u8>>,
    attachments_empty: bool,
    quad: [u8; 4],
    quad_len: usize,
    saw_padding: bool,
    data_escape: bool,
    sha512: sha2::Sha512,
    sha1: sha1::Sha1,
    data_len: u64,
}

impl PublishExtractor {
    pub fn new(max_metadata_bytes: usize) -> Self {
        Self {
            max_metadata_bytes,
            phase: Phase::FindAttachments,
            meta: Vec::new(),
            depth: 0,
            in_string: false,
            escape: false,
            key_buf: Vec::new(),
            key_valid: true,
            last_string: None,
            attachments_empty: false,
            quad: [0; 4],
            quad_len: 0,
            saw_padding: false,
            data_escape: false,
            sha512: sha2::Sha512::new(),
            sha1: sha1::Sha1::new(),
            data_len: 0,
        }
    }

    /// Process one body chunk, appending decoded tarball bytes to `out`.
    /// Callers should flush `out` to bounded storage as it grows.
    pub fn feed(&mut self, chunk: &[u8], out: &mut Vec<u8>) -> Result<(), ExtractError> {
        for &byte in chunk {
            self.step(byte, out)?;
        }
        Ok(())
    }

    /// Complete the extraction at end of stream.
    pub fn finish(self) -> Result<Extracted, ExtractError> {
        match self.phase {
            Phase::FindAttachments => Ok(Extracted::MetadataOnly(self.meta)),
            Phase::Tail if self.attachments_empty => Ok(Extracted::MetadataOnly(self.meta)),
            Phase::Tail => {
                let integrity = format!("sha512-{}", B64.encode(self.sha512.finalize()));
                let shasum = hex::encode(self.sha1.finalize());
                Ok(Extracted::Publish {
                    metadata: self.meta,
                    integrity,
                    shasum,
                    tarball_bytes: self.data_len,
                })
            }
            Phase::Data => Err(ExtractError::Malformed("unterminated attachment data")),
            Phase::AttachmentsOpen | Phase::FirstEntryKey | Phase::AttachmentOpen => {
                Err(ExtractError::Malformed("truncated _attachments object"))
            }
            Phase::FindDataKey | Phase::DataOpen => Err(ExtractError::Malformed(
                "attachment entry has no data string",
            )),
        }
    }

    fn step(&mut self, byte: u8, out: &mut Vec<u8>) -> Result<(), ExtractError> {
        if self.phase == Phase::Data {
            return self.step_data(byte, out);
        }

        self.meta.push(byte);
        if self.meta.len() > self.max_metadata_bytes {
            return Err(ExtractError::MetadataTooLarge);
        }

        if self.in_string {
            if self.escape {
                self.escape = false;
                self.capture(byte);
            } else if byte == b'\\' {
                self.escape = true;
                self.capture(byte);
            } else if byte == b'"' {
                self.in_string = false;
                self.last_string = if self.key_valid {
                    Some(std::mem::take(&mut self.key_buf))
                } else {
                    None
                };
            } else {
                self.capture(byte);
            }
            return Ok(());
        }

        match byte {
            b'"' => {
                self.in_string = true;
                self.escape = false;
                self.key_buf.clear();
                self.key_valid = true;
                if self.phase == Phase::DataOpen {
                    self.phase = Phase::Data;
                }
            }
            b':' => {
                let Some(key) = self.last_string.take() else {
                    return Ok(());
                };
                match self.phase {
                    Phase::FindAttachments if self.depth == 1 && key == b"_attachments" => {
                        self.phase = Phase::AttachmentsOpen;
                    }
                    Phase::FirstEntryKey if self.depth == 2 => {
                        self.phase = Phase::AttachmentOpen;
                    }
                    Phase::FindDataKey if self.depth == 3 && key == b"data" => {
                        self.phase = Phase::DataOpen;
                    }
                    _ => {}
                }
            }
            b'{' | b'[' => {
                self.depth += 1;
                self.last_string = None;
                match self.phase {
                    Phase::AttachmentsOpen if byte == b'{' => {
                        self.phase = Phase::FirstEntryKey;
                    }
                    Phase::AttachmentsOpen => {
                        return Err(ExtractError::Malformed("_attachments must be an object"));
                    }
                    Phase::AttachmentOpen if byte == b'{' => {
                        self.phase = Phase::FindDataKey;
                    }
                    Phase::AttachmentOpen => {
                        return Err(ExtractError::Malformed(
                            "attachment entry must be an object",
                        ));
                    }
                    _ => {}
                }
            }
            b'}' | b']' => {
                if byte == b'}' {
                    match self.phase {
                        Phase::FirstEntryKey | Phase::AttachmentOpen if self.depth == 2 => {
                            // `_attachments` closed before any entry data was seen.
                            self.attachments_empty = true;
                            self.phase = Phase::Tail;
                        }
                        Phase::FindDataKey | Phase::DataOpen if self.depth == 3 => {
                            return Err(ExtractError::Malformed(
                                "attachment entry has no data string",
                            ));
                        }
                        _ => {}
                    }
                }
                self.depth = self.depth.saturating_sub(1);
                self.last_string = None;
            }
            b',' => {
                self.last_string = None;
            }
            other => {
                if matches!(
                    self.phase,
                    Phase::AttachmentsOpen | Phase::AttachmentOpen | Phase::DataOpen
                ) && !other.is_ascii_whitespace()
                {
                    return Err(ExtractError::Malformed(
                        "unexpected content in attachment framing",
                    ));
                }
            }
        }
        Ok(())
    }

    fn capture(&mut self, byte: u8) {
        if !self.key_valid {
            return;
        }
        if self.key_buf.len() >= MAX_KEY_BYTES {
            self.key_valid = false;
            return;
        }
        self.key_buf.push(byte);
    }

    fn step_data(&mut self, byte: u8, out: &mut Vec<u8>) -> Result<(), ExtractError> {
        if self.data_escape {
            self.data_escape = false;
            return match byte {
                // JSON whitespace escapes inside the payload: skip.
                b'n' | b'r' | b't' => Ok(()),
                // Escaped solidus (`\/`): a real base64 alphabet character.
                b'/' => self.push_data_char(b'/', out),
                _ => Err(ExtractError::Malformed(
                    "unsupported escape sequence in attachment data",
                )),
            };
        }
        match byte {
            b'"' => {
                if self.quad_len != 0 {
                    return Err(ExtractError::Malformed("truncated base64 quad"));
                }
                // Close the (empty) data string in the metadata document.
                self.meta.push(byte);
                if self.meta.len() > self.max_metadata_bytes {
                    return Err(ExtractError::MetadataTooLarge);
                }
                self.phase = Phase::Tail;
                self.in_string = false;
                self.escape = false;
                self.last_string = None;
                Ok(())
            }
            b'\\' => {
                self.data_escape = true;
                Ok(())
            }
            b' ' | b'\t' | b'\n' | b'\r' => Ok(()),
            other => self.push_data_char(other, out),
        }
    }

    fn push_data_char(&mut self, byte: u8, out: &mut Vec<u8>) -> Result<(), ExtractError> {
        if self.saw_padding {
            return Err(ExtractError::Malformed(
                "base64 data continues after padding",
            ));
        }
        self.quad[self.quad_len] = byte;
        self.quad_len += 1;
        if self.quad_len < 4 {
            return Ok(());
        }
        let quad = self.quad;
        self.quad_len = 0;
        if quad[..2].contains(&b'=') {
            return Err(ExtractError::Malformed("misplaced base64 padding"));
        }
        if quad[2] == b'=' || quad[3] == b'=' {
            self.saw_padding = true;
        }
        let mut decoded = [0u8; 3];
        let len = B64
            .decode_slice(quad, &mut decoded)
            .map_err(|_| ExtractError::Malformed("invalid base64 in attachment data"))?;
        let decoded = &decoded[..len];
        self.sha512.update(decoded);
        self.sha1.update(decoded);
        self.data_len = self.data_len.saturating_add(len as u64);
        out.extend_from_slice(decoded);
        Ok(())
    }
}

/// Parsed and validated metadata portion of a publish document.
#[derive(Debug, Clone)]
pub struct PublishMetadata {
    pub name: String,
    pub version: String,
    /// The single version document from `versions`.
    pub manifest: Value,
    /// Keys of the `dist-tags` object, in document order.
    pub dist_tags: Vec<String>,
    /// Declared attachment length, when present in `_attachments`.
    pub declared_bytes: Option<u64>,
}

impl PublishMetadata {
    /// Validate the assembled metadata document (with an emptied attachment
    /// `data` string) for a publish against `expected_name`.
    pub fn parse(metadata: &[u8], expected_name: &str) -> Result<Self, ExtractError> {
        let document: Value = serde_json::from_slice(metadata)
            .map_err(|_| ExtractError::Malformed("publish document is not valid JSON"))?;
        let obj = document.as_object().ok_or(ExtractError::Malformed(
            "publish document must be a JSON object",
        ))?;

        let name = obj
            .get("name")
            .and_then(Value::as_str)
            .ok_or(ExtractError::Malformed(
                "publish document is missing `name`",
            ))?;
        if name != expected_name {
            return Err(ExtractError::Malformed(
                "publish document name does not match the request path",
            ));
        }

        let versions =
            obj.get("versions")
                .and_then(Value::as_object)
                .ok_or(ExtractError::Malformed(
                    "publish document is missing `versions`",
                ))?;
        if versions.len() != 1 {
            return Err(ExtractError::Malformed(
                "exactly one version per publish is supported",
            ));
        }
        let (version, manifest) = versions.iter().next().ok_or(ExtractError::Malformed(
            "publish document is missing `versions`",
        ))?;

        let attachments =
            obj.get("_attachments")
                .and_then(Value::as_object)
                .ok_or(ExtractError::Malformed(
                    "publish document is missing `_attachments`",
                ))?;
        if attachments.len() != 1 {
            return Err(ExtractError::Malformed(
                "exactly one attachment per publish is supported",
            ));
        }
        let attachment = attachments
            .values()
            .next()
            .and_then(Value::as_object)
            .ok_or(ExtractError::Malformed(
                "attachment entry must be an object",
            ))?;
        if !attachment
            .get("data")
            .and_then(Value::as_str)
            .is_some_and(str::is_empty)
        {
            return Err(ExtractError::Malformed("attachment data must be a string"));
        }
        let declared_bytes = attachment.get("length").and_then(Value::as_u64);

        let dist_tags = obj
            .get("dist-tags")
            .and_then(Value::as_object)
            .map(|tags| tags.keys().cloned().collect())
            .unwrap_or_default();

        Ok(Self {
            name: name.to_string(),
            version: version.clone(),
            manifest: manifest.clone(),
            dist_tags,
            declared_bytes,
        })
    }
}

/// Reject a metadata-only document that still carries attachment payloads.
/// This is a defence against framing evasion (for example an escaped
/// `_attachments` key): such documents are refused instead of being treated
/// as metadata writes.
pub fn ensure_no_attachment_data(document: &[u8]) -> Result<(), ExtractError> {
    let value: Value = serde_json::from_slice(document)
        .map_err(|_| ExtractError::Malformed("publish document is not valid JSON"))?;
    let has_data = value
        .get("_attachments")
        .and_then(Value::as_object)
        .map(|attachments| {
            attachments.values().any(|attachment| {
                attachment
                    .get("data")
                    .and_then(Value::as_str)
                    .is_some_and(|data| !data.is_empty())
            })
        })
        .unwrap_or(false);
    if has_data {
        return Err(ExtractError::Malformed(
            "attachment data is not supported on this path",
        ));
    }
    Ok(())
}

/// Stable fingerprint of one logical publish: base64 SHA-256 over
/// `name\nversion\n<canonical manifest json>\n<declared size>`.
pub fn publish_fingerprint(
    name: &str,
    version: &str,
    manifest: &Value,
    declared_bytes: u64,
) -> String {
    let manifest_json = serde_json::to_vec(manifest).unwrap_or_default();
    let mut hasher = sha2::Sha256::new();
    hasher.update(name.as_bytes());
    hasher.update(b"\n");
    hasher.update(version.as_bytes());
    hasher.update(b"\n");
    hasher.update(manifest_json);
    hasher.update(b"\n");
    hasher.update(declared_bytes.to_string().as_bytes());
    B64.encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TARBALL: &[u8] = b"hello from rustaccio\n";

    fn publish_doc(name: &str, data_b64: &str) -> String {
        serde_json::json!({
            "_id": name,
            "name": name,
            "description": "a \"quoted\" description with \\ escapes\nand newlines",
            "dist-tags": { "latest": "1.0.0" },
            "versions": {
                "1.0.0": {
                    "name": name,
                    "version": "1.0.0",
                    "dist": {
                        "tarball": format!("http://localhost:4873/{name}/-/{name}-1.0.0.tgz")
                    }
                }
            },
            "_attachments": {
                format!("{name}-1.0.0.tgz"): {
                    "content_type": "application/octet-stream",
                    "data": data_b64,
                    "length": TARBALL.len()
                }
            }
        })
        .to_string()
    }

    fn extract_chunked(doc: &str, chunk_size: usize) -> (Extracted, Vec<u8>) {
        let mut extractor = PublishExtractor::new(8 * 1024 * 1024);
        let mut decoded = Vec::new();
        for chunk in doc.as_bytes().chunks(chunk_size) {
            extractor
                .feed(chunk, &mut decoded)
                .expect("feed should succeed");
        }
        (extractor.finish().expect("finish should succeed"), decoded)
    }

    #[test]
    fn extracts_publish_in_one_shot() {
        let doc = publish_doc("demo", &B64.encode(TARBALL));
        let (extracted, decoded) = extract_chunked(&doc, usize::MAX);
        assert_eq!(decoded, TARBALL);
        let Extracted::Publish {
            metadata,
            integrity,
            shasum,
            tarball_bytes,
        } = extracted
        else {
            panic!("expected publish extraction");
        };
        assert_eq!(tarball_bytes, TARBALL.len() as u64);
        assert_eq!(
            integrity,
            "sha512-xqmY2G7Z5zqNkjn2EdWXgtVdvz/TTGViU7tLUZlmlOjhwn6PCWFVLgh0Tbe4a8anbKyj53uFLPTCw4PPpVq8YA=="
        );
        assert_eq!(shasum, "404c6570f781ea81e1b11b9434acd14d41781d9a");
        let parsed = PublishMetadata::parse(&metadata, "demo").expect("metadata parses");
        assert_eq!(parsed.version, "1.0.0");
        assert_eq!(parsed.dist_tags, vec!["latest".to_string()]);
        assert_eq!(parsed.declared_bytes, Some(TARBALL.len() as u64));
        assert_eq!(parsed.manifest["version"], "1.0.0");
    }

    #[test]
    fn extraction_is_identical_across_chunk_boundaries() {
        let doc = publish_doc("demo", &B64.encode(TARBALL));
        let (_, reference) = extract_chunked(&doc, usize::MAX);
        for size in [1usize, 2, 3, 4, 5, 7, 16, 64] {
            let (extracted, decoded) = extract_chunked(&doc, size);
            assert_eq!(decoded, reference, "chunk size {size} changed the payload");
            let Extracted::Publish { integrity, .. } = extracted else {
                panic!("expected publish extraction");
            };
            assert!(integrity.starts_with("sha512-"));
        }
    }

    #[test]
    fn handles_whitespace_inside_base64() {
        let encoded = B64.encode(TARBALL);
        let with_breaks = encoded
            .chars()
            .collect::<Vec<_>>()
            .chunks(4)
            .map(|chunk| chunk.iter().collect::<String>())
            .collect::<Vec<_>>()
            .join("\n");
        let doc = publish_doc("demo", &with_breaks);
        let (_, decoded) = extract_chunked(&doc, 9);
        assert_eq!(decoded, TARBALL);
    }

    #[test]
    fn rejects_invalid_base64() {
        let doc = publish_doc("demo", "!!!!");
        let mut extractor = PublishExtractor::new(1024);
        let mut out = Vec::new();
        let err = extractor
            .feed(doc.as_bytes(), &mut out)
            .expect_err("invalid base64 must fail");
        assert!(matches!(err, ExtractError::Malformed(_)));
    }

    #[test]
    fn rejects_escape_in_data() {
        // `\x` is not a supported JSON escape inside the payload.
        let doc = "{\"name\":\"demo\",\"_attachments\":{\"demo-1.0.0.tgz\":{\"data\":\"a\\xb\"}}}";
        let mut extractor = PublishExtractor::new(1024);
        let mut out = Vec::new();
        let err = extractor
            .feed(doc.as_bytes(), &mut out)
            .expect_err("unsupported escape in data must fail");
        assert!(matches!(err, ExtractError::Malformed(_)));
    }

    #[test]
    fn handles_escaped_solidus_in_data() {
        // `\/` is a valid JSON escape for the base64 alphabet character `/`.
        let doc = "{\"name\":\"demo\",\"_attachments\":{\"demo-1.0.0.tgz\":{\"data\":\"a\\/w=\"}}}";
        let (extracted, decoded) = extract_chunked(doc, 8);
        assert_eq!(decoded, vec![0x6b, 0xfc]);
        assert!(matches!(extracted, Extracted::Publish { .. }));
    }

    #[test]
    fn rejects_unterminated_data() {
        let mut doc = publish_doc("demo", &B64.encode(TARBALL));
        doc.truncate(doc.len() - 20);
        let mut extractor = PublishExtractor::new(8 * 1024 * 1024);
        let mut out = Vec::new();
        if extractor.feed(doc.as_bytes(), &mut out).is_ok() {
            let err = extractor.finish().expect_err("truncated data must fail");
            assert!(matches!(err, ExtractError::Malformed(_)));
        }
    }

    #[test]
    fn rejects_data_after_padding() {
        let doc = publish_doc("demo", "aGk=TWFu");
        let mut extractor = PublishExtractor::new(1024);
        let mut out = Vec::new();
        let err = extractor
            .feed(doc.as_bytes(), &mut out)
            .expect_err("data after padding must fail");
        assert!(matches!(err, ExtractError::Malformed(_)));
    }

    #[test]
    fn metadata_only_when_no_attachments() {
        let doc = serde_json::json!({
            "name": "demo",
            "versions": { "1.0.0": { "name": "demo", "version": "1.0.0" } }
        })
        .to_string();
        let (extracted, decoded) = extract_chunked(&doc, 8);
        assert!(decoded.is_empty());
        let Extracted::MetadataOnly(bytes) = extracted else {
            panic!("expected metadata-only extraction");
        };
        assert_eq!(bytes, doc.as_bytes());
    }

    #[test]
    fn metadata_only_when_attachments_empty() {
        let doc = serde_json::json!({
            "name": "demo",
            "versions": {},
            "_attachments": {}
        })
        .to_string();
        let (extracted, _) = extract_chunked(&doc, 4);
        assert!(matches!(extracted, Extracted::MetadataOnly(_)));
    }

    #[test]
    fn enforces_metadata_bound_before_marker() {
        let filler = "x".repeat(4096);
        let doc = format!("{{\"name\": \"{filler}\"");
        let mut extractor = PublishExtractor::new(256);
        let mut out = Vec::new();
        let err = extractor
            .feed(doc.as_bytes(), &mut out)
            .expect_err("oversized metadata must fail");
        assert_eq!(err, ExtractError::MetadataTooLarge);
    }

    #[test]
    fn parse_rejects_multiple_attachments() {
        let doc = serde_json::json!({
            "name": "demo",
            "versions": { "1.0.0": {} },
            "_attachments": {
                "a.tgz": { "data": "" },
                "b.tgz": { "data": "" }
            }
        })
        .to_string();
        let err = PublishMetadata::parse(doc.as_bytes(), "demo")
            .expect_err("multiple attachments must fail");
        assert!(matches!(err, ExtractError::Malformed(_)));
    }

    #[test]
    fn parse_rejects_name_mismatch() {
        let doc = serde_json::json!({
            "name": "other",
            "versions": { "1.0.0": {} },
            "_attachments": { "a.tgz": { "data": "" } }
        })
        .to_string();
        assert!(PublishMetadata::parse(doc.as_bytes(), "demo").is_err());
    }

    #[test]
    fn parse_rejects_multiple_versions() {
        let doc = serde_json::json!({
            "name": "demo",
            "versions": { "1.0.0": {}, "1.0.1": {} },
            "_attachments": { "a.tgz": { "data": "" } }
        })
        .to_string();
        assert!(PublishMetadata::parse(doc.as_bytes(), "demo").is_err());
    }

    #[test]
    fn no_attachment_data_guard_accepts_plain_metadata() {
        let doc = serde_json::json!({ "name": "demo", "versions": {} }).to_string();
        assert!(ensure_no_attachment_data(doc.as_bytes()).is_ok());
    }

    #[test]
    fn no_attachment_data_guard_rejects_hidden_payloads() {
        let doc = serde_json::json!({
            "name": "demo",
            "_attachments": { "a.tgz": { "data": B64.encode(TARBALL) } }
        })
        .to_string();
        assert!(ensure_no_attachment_data(doc.as_bytes()).is_err());
    }

    #[test]
    fn empty_payload_hashes_match_known_vectors() {
        let mut extractor = PublishExtractor::new(1024);
        let mut out = Vec::new();
        let doc = publish_doc("demo", "");
        extractor
            .feed(doc.as_bytes(), &mut out)
            .expect("feed should succeed");
        let Extracted::Publish {
            integrity, shasum, ..
        } = extractor.finish().expect("finish should succeed")
        else {
            panic!("expected publish extraction");
        };
        assert!(out.is_empty());
        assert_eq!(shasum, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(
            integrity,
            "sha512-z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUdBeoGlODJ6+SfaPg=="
        );
    }

    #[test]
    fn fingerprint_matches_known_vector() {
        let manifest = serde_json::json!({ "name": "demo", "version": "1.0.0" });
        assert_eq!(
            publish_fingerprint("demo", "1.0.0", &manifest, 3),
            "U/dgP/d7IJgB8o8YTJ3IVOPAuq5dOwKkDGzpcssDnw4="
        );
    }
}
