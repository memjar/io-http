//! Byte searches shared by the line-oriented parsers: the chunk size line of
//! [`crate::rfc9112`] and the event stream lines of [`crate::sse`].

use crate::rfc9110::chars::{CR, LF};

/// The index of the first byte `hit` matches.
///
/// Sixteen bytes at a time, each block's hits gathered into one mask, which
/// compiles to vector compares on the x86_64 and aarch64 baselines. `hit`
/// must join its tests with `|`: a `matches!` compiles to a branch a byte.
#[inline]
pub(crate) fn position(bytes: &[u8], hit: impl Fn(u8) -> bool) -> Option<usize> {
    let (blocks, tail) = bytes.as_chunks::<16>();

    for (i, block) in blocks.iter().enumerate() {
        let mut mask = 0u16;

        for (j, &b) in block.iter().enumerate() {
            mask |= u16::from(hit(b)) << j;
        }

        if mask != 0 {
            return Some(i * 16 + mask.trailing_zeros() as usize);
        }
    }

    tail.iter()
        .position(|&b| hit(b))
        .map(|j| blocks.len() * 16 + j)
}

/// The index of the first CRLF.
#[inline]
pub(crate) fn crlf_position(bytes: &[u8]) -> Option<usize> {
    let mut from = 1;

    loop {
        let lf = from + position(bytes.get(from..)?, |b| b == LF)?;

        if bytes[lf - 1] == CR {
            return Some(lf - 1);
        }

        from = lf + 1;
    }
}

#[cfg(test)]
mod tests {
    use crate::scan::*;

    #[test]
    fn position_across_blocks_and_tail() {
        let mut bytes = [b'a'; 40];

        for at in 0..bytes.len() {
            bytes[at] = b':';
            assert_eq!(position(&bytes, |b| b == b':'), Some(at));
            bytes[at] = b'a';
        }

        assert_eq!(position(&bytes, |b| b == b':'), None);
    }

    #[test]
    fn crlf_position_skips_bare_line_feeds() {
        assert_eq!(crlf_position(b"\n5\nab\r\n"), Some(5));
        assert_eq!(crlf_position(b"\r\r\n"), Some(1));
        assert_eq!(crlf_position(b"\n\r"), None);
        assert_eq!(crlf_position(b""), None);
    }
}
