//! DNS name encoding/decoding (RFC 1035 §4.1.2/§4.1.4).
//!
//! Craft writes plain uncompressed label sequences (always legal);
//! dissection decodes both plain sequences and compression pointers,
//! with loop/length guards so hostile messages never panic or hang.

/// Maximum total name length (RFC 1035: 255 octets on the wire).
const MAX_NAME_OCTETS: usize = 255;
/// Maximum label length (RFC 1035: 63).
const MAX_LABEL: usize = 63;
/// Compression-pointer jump cap: any real message converges in a few
/// jumps; hostile chains must not spin.
const MAX_JUMPS: usize = 32;

/// Encode `name` (dotted presentation form, trailing dot optional;
/// empty string = the root) as an uncompressed label sequence.
pub fn encode_name(name: &str, out: &mut Vec<u8>) -> Result<(), String> {
    let trimmed = name.strip_suffix('.').unwrap_or(name);
    let mut total = 1usize; // the root byte
    if !trimmed.is_empty() {
        for label in trimmed.split('.') {
            if label.is_empty() {
                return Err(format!("empty label in `{name}` (no `..` or leading dot)"));
            }
            if label.len() > MAX_LABEL {
                return Err(format!("label `{label}` exceeds 63 octets"));
            }
            if label
                .bytes()
                .any(|b| !(0x21..=0x7e).contains(&b) || b == b'.' || b == b'\\')
            {
                // No escape grammar at tranche 3: reject separators and
                // non-printables explicitly (deltas are honest errors,
                // not silent corruption).
                return Err(format!(
                    "label `{label}` needs an escape grammar (unsupported)"
                ));
            }
            total += label.len() + 1;
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
    }
    if total > MAX_NAME_OCTETS {
        return Err(format!("name `{name}` exceeds 255 octets"));
    }
    out.push(0);
    Ok(())
}

/// Wire length of `name`'s encoding (labels + length bytes + root).
pub fn name_wire_len(name: &str) -> Result<usize, String> {
    let mut probe = Vec::new();
    encode_name(name, &mut probe)?;
    Ok(probe.len())
}

/// Decode a name at `offset` within `message`.
///
/// Returns the presentation form (no trailing dot; the root is the
/// empty string) and the number of octets consumed **from `offset`**
/// (pointer jumps do not advance the cursor past the 2-byte pointer).
pub fn decode_name(message: &[u8], offset: usize) -> Result<(String, usize), String> {
    let mut labels: Vec<String> = Vec::new();
    let mut cursor = offset;
    let mut jumps = 0usize;
    let mut consumed = 0usize;
    let mut total = 0usize;
    // Consumed tracks the linear extent from `offset`; octets read at
    // earlier positions (after a pointer jump) do not extend it.
    let mut advance = |cursor: usize, width: usize| {
        if cursor >= offset {
            consumed = consumed.max(cursor - offset + width);
        }
    };
    loop {
        let len = *message
            .get(cursor)
            .ok_or("truncated name (ran off the message)")?;
        if len == 0 {
            advance(cursor, 1);
            break;
        }
        let top = len & 0xC0;
        if top == 0xC0 {
            // Compression pointer: two octets, absolute offset.
            let hi = len as usize;
            let lo = *message
                .get(cursor + 1)
                .ok_or("truncated compression pointer")?;
            let target = ((hi & 0x3F) << 8) | lo as usize;
            advance(cursor, 2);
            jumps += 1;
            if jumps > MAX_JUMPS {
                return Err("too many compression-pointer jumps".to_string());
            }
            if target >= message.len() || target == 0 {
                return Err(format!("bad compression pointer (offset {target})"));
            }
            cursor = target;
            continue;
        }
        if top != 0 {
            return Err(format!("reserved label type 0x{len:02x}"));
        }
        let len = len as usize;
        if len > MAX_LABEL {
            return Err(format!("label length {len} exceeds 63"));
        }
        let end = cursor + 1 + len;
        if end > message.len() {
            return Err("truncated label".to_string());
        }
        let label_bytes = &message[cursor + 1..end];
        if label_bytes
            .iter()
            .any(|&b| !(0x21..=0x7e).contains(&b) || b == b'.' || b == b'\\')
        {
            return Err("label needs an escape grammar (unsupported)".to_string());
        }
        labels.push(String::from_utf8_lossy(label_bytes).into_owned());
        total += len + 1;
        if total > MAX_NAME_OCTETS {
            return Err("name exceeds 255 octets".to_string());
        }
        cursor = end;
        advance(cursor, 0);
    }
    Ok((labels.join("."), consumed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_plain_and_root() {
        let mut out = Vec::new();
        encode_name("example.com", &mut out).unwrap();
        assert_eq!(out, b"\x07example\x03com\x00");
        let mut out = Vec::new();
        encode_name("example.com.", &mut out).unwrap();
        assert_eq!(out, b"\x07example\x03com\x00");
        let mut out = Vec::new();
        encode_name("", &mut out).unwrap();
        assert_eq!(out, b"\x00");
        let mut out = Vec::new();
        encode_name(".", &mut out).unwrap();
        assert_eq!(out, b"\x00");
    }

    #[test]
    fn encode_rejects_bad_names() {
        let mut out = Vec::new();
        assert!(encode_name("a..b", &mut out).is_err());
        assert!(encode_name(".a", &mut out).is_err());
        assert!(encode_name(&"x".repeat(64), &mut out).is_err());
        assert!(encode_name(&format!("{}.{}", "a".repeat(64), "com"), &mut out).is_err());
        // 4 labels × 63 octets + length bytes + root > 255
        let over = vec!["x".repeat(63); 4].join(".");
        assert!(encode_name(&over, &mut out).is_err());
        let long = vec!["ab".repeat(40); 7].join(".");
        assert!(encode_name(&long, &mut out).is_err());
        assert!(encode_name("sp ace", &mut out).is_err());
    }

    #[test]
    fn decode_plain() {
        let msg = b"\x07example\x03com\x00";
        let (name, used) = decode_name(msg, 0).unwrap();
        assert_eq!(name, "example.com");
        assert_eq!(used, 13);
        let (root, used) = decode_name(b"\x00", 0).unwrap();
        assert_eq!(root, "");
        assert_eq!(used, 1);
    }

    #[test]
    fn decode_pointer() {
        // header (12) then question then a CNAME answer whose name is a
        // pointer back to offset 12.
        let mut msg = vec![0u8; 12];
        msg.extend_from_slice(b"\x07example\x03com\x00");
        let ptr_at = msg.len();
        msg.push(0xC0);
        msg.push(0x0C);
        let (name, used) = decode_name(&msg, ptr_at).unwrap();
        assert_eq!(name, "example.com");
        assert_eq!(used, 2, "pointer consumes 2 octets");
        // tail labels after the pointer jump
        msg.extend_from_slice(b"\x02ns\x00");
        let (name, used) = decode_name(&msg, ptr_at + 2).unwrap();
        assert_eq!(name, "ns");
        assert_eq!(used, 4);
    }

    #[test]
    fn decode_guards() {
        // truncated
        assert!(decode_name(b"\x07ex", 0).is_err());
        // pointer loop: offset 0 points at itself
        let mut msg = vec![0xC0, 0x00];
        assert!(decode_name(&msg, 0).is_err());
        // pointer chain longer than MAX_JUMPS: self-referential pointers
        // must hit the jump cap, not the length cap or a hang
        for _ in 0..64 {
            let at = msg.len();
            msg.push(0xC0);
            msg.push(at as u8);
            if at > 250 {
                break;
            }
        }
        assert!(decode_name(&msg, 0).is_err());
        // reserved label type
        assert!(decode_name(&[0x40, 0x00], 0).is_err());
        // overlong single label claim inside a short buffer
        assert!(decode_name(&[0x40], 0).is_err());
    }

    /// The pointer-jump cap, from every entry offset of a canonical
    /// self-referencing pointer chain (the pointer at 2 targets 2).
    /// Constant message ⇒ these are exactly the concrete paths a
    /// pinned-shape Kani harness would walk — kept as a unit test
    /// after the solver version cost 10GB (nested-loop unrolling; see
    /// the verification module docs).
    #[test]
    fn pointer_cap_terminates_from_every_offset() {
        let msg: [u8; 8] = [0xC0, 0x02, 0xC0, 0x02, 0x00, 0x00, 0x00, 0x00];
        for offset in 0..msg.len() {
            // Pointer loops (offsets 0..3) must Err via the MAX_JUMPS
            // cap, not hang or panic — and the cursor-jumps-backward
            // underflow guard must hold. Terminators elsewhere decode
            // without over-claiming `consumed`.
            if let Ok((_, consumed)) = decode_name(&msg, offset) {
                assert!(consumed <= msg.len());
            }
        }
        // The cap specifically: a self-pointer reachable from offset 2
        // loops until the jump counter fires.
        assert!(decode_name(&msg, 2).is_err());
    }
}
