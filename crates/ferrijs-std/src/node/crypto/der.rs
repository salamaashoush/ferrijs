//! The few DER structures a key moves through, read and written by hand.
//!
//! Node's exports are OpenSSL's encodings, byte for byte, and the parsing
//! crates each normalise a different subset of them. Writing the
//! wrappers here keeps the output under this module's control: an EC
//! PKCS#8 key carries its public point and no inner curve, a SEC1 key
//! carries both, exactly as OpenSSL emits them.

pub(super) const SEQUENCE: u8 = 0x30;
pub(super) const INTEGER: u8 = 0x02;
pub(super) const BIT_STRING: u8 = 0x03;
pub(super) const OCTET_STRING: u8 = 0x04;
pub(super) const NULL: u8 = 0x05;
pub(super) const OID: u8 = 0x06;
pub(super) const CONTEXT_0: u8 = 0xa0;
pub(super) const CONTEXT_1: u8 = 0xa1;

/// A tag and its content.
pub(super) type Element<'a> = (u8, &'a [u8]);

/// One element: its tag, its content, and the bytes after it.
pub(super) fn read(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
  let (&tag, rest) = input.split_first()?;
  let (&first, rest) = rest.split_first()?;
  let (length, rest) = if first < 0x80 {
    (usize::from(first), rest)
  } else {
    let count = usize::from(first & 0x7f);
    if count == 0 || count > 4 || rest.len() < count {
      return None;
    }
    let (bytes, rest) = rest.split_at(count);
    let length = bytes.iter().fold(0usize, |n, b| (n << 8) | usize::from(*b));
    (length, rest)
  };
  if rest.len() < length {
    return None;
  }
  let (content, rest) = rest.split_at(length);
  Some((tag, content, rest))
}

/// The content of an element that must carry `tag`, and what follows it.
pub(super) fn expect(input: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
  match read(input)? {
    (found, content, rest) if found == tag => Some((content, rest)),
    _ => None,
  }
}

/// The elements of a SEQUENCE's content, in order.
pub(super) fn elements(mut content: &[u8]) -> Option<Vec<Element<'_>>> {
  let mut out = Vec::new();
  while !content.is_empty() {
    let (tag, inner, rest) = read(content)?;
    out.push((tag, inner));
    content = rest;
  }
  Some(out)
}

pub(super) fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
  let mut out = Vec::with_capacity(content.len() + 6);
  out.push(tag);
  match u8::try_from(content.len()) {
    Ok(short) if short < 0x80 => out.push(short),
    _ => {
      let bytes = content.len().to_be_bytes();
      let skip = bytes.iter().take_while(|b| **b == 0).count();
      let count = u8::try_from(bytes.len() - skip).unwrap_or(u8::MAX);
      out.push(0x80 | count);
      out.extend_from_slice(&bytes[skip..]);
    },
  }
  out.extend_from_slice(content);
  out
}

pub(super) fn sequence(parts: &[&[u8]]) -> Vec<u8> {
  tlv(SEQUENCE, &parts.concat())
}

/// A BIT STRING with no unused bits.
pub(super) fn bits(content: &[u8]) -> Vec<u8> {
  tlv(BIT_STRING, &[&[0u8][..], content].concat())
}

/// The content of a BIT STRING with no unused bits.
pub(super) fn unbits(content: &[u8]) -> Option<&[u8]> {
  match content.split_first() {
    Some((0, rest)) => Some(rest),
    _ => None,
  }
}

/// An unsigned big-endian integer as a DER INTEGER: leading zeros
/// dropped, one put back when the top bit would read as a sign.
pub(super) fn unsigned(value: &[u8]) -> Vec<u8> {
  let skip = value.iter().take_while(|b| **b == 0).count();
  let trimmed = &value[skip..];
  if trimmed.is_empty() {
    return tlv(INTEGER, &[0]);
  }
  if trimmed[0] & 0x80 != 0 {
    return tlv(INTEGER, &[&[0u8][..], trimmed].concat());
  }
  tlv(INTEGER, trimmed)
}

/// A DER INTEGER's content as an unsigned value, without its sign byte.
pub(super) fn magnitude(content: &[u8]) -> &[u8] {
  let skip = content.iter().take_while(|b| **b == 0).count();
  &content[skip..]
}

/// `value` left-padded with zeros to `width` bytes, or `None` if it is
/// wider.
pub(super) fn padded(value: &[u8], width: usize) -> Option<Vec<u8>> {
  let value = magnitude(value);
  if value.len() > width {
    return None;
  }
  let mut out = vec![0; width - value.len()];
  out.extend_from_slice(value);
  Some(out)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn long_lengths_round_trip() {
    for length in [0usize, 1, 127, 128, 255, 256, 70_000] {
      let content = vec![7u8; length];
      let encoded = tlv(OCTET_STRING, &content);
      let (tag, read_back, rest) = read(&encoded).unwrap();
      assert_eq!((tag, read_back, rest), (OCTET_STRING, &content[..], &[][..]));
    }
  }

  #[test]
  fn integers_keep_their_sign_byte_only_when_needed() {
    assert_eq!(unsigned(&[0, 0, 0x7f]), [INTEGER, 1, 0x7f]);
    assert_eq!(unsigned(&[0x80]), [INTEGER, 2, 0, 0x80]);
    assert_eq!(unsigned(&[]), [INTEGER, 1, 0]);
  }

  #[test]
  fn truncated_input_reads_as_nothing() {
    assert!(read(&[SEQUENCE, 5, 1, 2]).is_none());
    assert!(read(&[SEQUENCE, 0x82, 1]).is_none());
  }
}
