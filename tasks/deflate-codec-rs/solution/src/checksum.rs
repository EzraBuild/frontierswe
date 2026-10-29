//! Checksums used by the two container formats: Adler-32 for zlib (RFC 1950)
//! and CRC-32 for gzip (RFC 1952).

/// Adler-32 over `data`, starting from the standard initial value of 1.
pub fn adler32(data: &[u8]) -> u32 {
    const MOD: u32 = 65521;
    // Largest chunk for which the running sums cannot overflow a u32 before
    // the modulo is applied (same bound zlib uses).
    const NMAX: usize = 5552;
    let (mut a, mut b) = (1u32, 0u32);
    for chunk in data.chunks(NMAX) {
        for &byte in chunk {
            a += u32::from(byte);
            b += a;
        }
        a %= MOD;
        b %= MOD;
    }
    (b << 16) | a
}

/// Reflected CRC-32 (polynomial 0xEDB88320) as used by gzip, PNG and zip.
pub fn crc32(data: &[u8]) -> u32 {
    let mut c = !0u32;
    for &byte in data {
        c = CRC_TABLE[((c ^ u32::from(byte)) & 0xFF) as usize] ^ (c >> 8);
    }
    !c
}

static CRC_TABLE: [u32; 256] = build_crc_table();

const fn build_crc_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
            k += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vectors() {
        assert_eq!(adler32(b""), 1);
        assert_eq!(adler32(b"Wikipedia"), 0x11E6_0398);
        assert_eq!(crc32(b""), 0);
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }
}
