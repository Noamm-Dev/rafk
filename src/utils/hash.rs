use sha1::{Digest, Sha1};

pub fn server_hash(server_id: &str, secret: &[u8], public_key: &[u8]) -> String {
    let mut digest: [u8; 20] = Sha1::new()
        .chain_update(server_id)
        .chain_update(secret)
        .chain_update(public_key)
        .finalize()
        .into();

    let negative = digest[0] & 0x80 != 0;
    if negative {
        let mut carry = true;
        for byte in digest.iter_mut().rev() {
            *byte = !*byte;
            if carry {
                let (value, overflow) = byte.overflowing_add(1);
                *byte = value;
                carry = overflow;
            }
        }
    }

    let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    let hex = hex.trim_start_matches('0');
    if negative { format!("-{hex}") } else { hex.to_string() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_hash_matches_known_vectors() {
        assert_eq!(server_hash("Notch", &[], &[]), "4ed1f46bbe04bc756bcb17c0c7ce3e4632f06a48");
        assert_eq!(server_hash("jeb_", &[], &[]), "-7c9d5b0044c130109a5d7b5fb5c317c02b4e28c1");
        assert_eq!(server_hash("simon", &[], &[]), "88e16a1019277b15d58faf0541e11910eb756f6");
    }
}