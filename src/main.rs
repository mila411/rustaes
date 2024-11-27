use rand::Rng;
use std::env;
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;

const S_BOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

const RCON: [u32; 15] = [
    0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000,
    0x1b000000, 0x36000000, 0x6c000000, 0xd8000000, 0xab000000, 0x4d000000, 0x9a000000,
];

pub struct Aes256 {
    round_keys: [u32; 60],
}

impl Aes256 {
    pub fn new(key: [u8; 32]) -> Self {
        let mut aes = Aes256 {
            round_keys: [0; 60],
        };
        aes.key_expansion(key);
        aes
    }

    fn key_expansion(&mut self, key: [u8; 32]) {
        for i in 0..8 {
            self.round_keys[i] =
                u32::from_be_bytes([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
        }

        for i in 8..60 {
            let mut temp = self.round_keys[i - 1];
            if i % 8 == 0 {
                temp = self.sub_word(Self::rot_word(temp)) ^ RCON[i / 8 - 1];
            } else if i % 8 == 4 {
                temp = self.sub_word(temp);
            }
            self.round_keys[i] = self.round_keys[i - 8] ^ temp;
        }
    }

    fn sub_word(&self, word: u32) -> u32 {
        let bytes = word.to_be_bytes();
        let mut subbed = [0u8; 4];
        for i in 0..4 {
            subbed[i] = S_BOX[bytes[i] as usize];
        }
        u32::from_be_bytes(subbed)
    }

    fn rot_word(word: u32) -> u32 {
        (word << 8) | (word >> 24)
    }

    pub fn encrypt_block(&self, block: &mut [u8; 16]) {
        let mut state = [
            u32::from_be_bytes([block[0], block[1], block[2], block[3]]),
            u32::from_be_bytes([block[4], block[5], block[6], block[7]]),
            u32::from_be_bytes([block[8], block[9], block[10], block[11]]),
            u32::from_be_bytes([block[12], block[13], block[14], block[15]]),
        ];

        // Early rounds
        for i in 0..4 {
            state[i] ^= self.round_keys[i];
        }

        // Main Round
        for round in 1..14 {
            self.sub_bytes(&mut state);
            self.shift_rows(&mut state);
            self.mix_columns(&mut state);
            for i in 0..4 {
                state[i] ^= self.round_keys[round * 4 + i];
            }
        }

        // Final Round
        self.sub_bytes(&mut state);
        self.shift_rows(&mut state);
        for i in 0..4 {
            state[i] ^= self.round_keys[14 * 4 + i];
        }

        // Restore the state to the block.
        for i in 0..4 {
            let bytes = state[i].to_be_bytes();
            block[4 * i..4 * i + 4].copy_from_slice(&bytes);
        }
    }

    fn sub_bytes(&self, state: &mut [u32; 4]) {
        for i in 0..4 {
            let mut word = state[i].to_be_bytes();
            for j in 0..4 {
                word[j] = S_BOX[word[j] as usize];
            }
            state[i] = u32::from_be_bytes(word);
        }
    }

    fn shift_rows(&self, state: &mut [u32; 4]) {
        let mut s = [[0u8; 4]; 4];

        // Obtain the state matrix
        for (i, word) in state.iter().enumerate() {
            let bytes = word.to_be_bytes();
            for j in 0..4 {
                s[j][i] = bytes[j];
            }
        }

        // Line shift
        for i in 1..4 {
            s[i].rotate_left(i);
        }

        // Reconstruct the state matrix
        for (i, word) in state.iter_mut().enumerate() {
            let bytes = [s[0][i], s[1][i], s[2][i], s[3][i]];
            *word = u32::from_be_bytes(bytes);
        }
    }

    fn mix_columns(&self, state: &mut [u32; 4]) {
        for i in 0..4 {
            let bytes = state[i].to_be_bytes();
            let a = bytes;

            let mut b = [0u8; 4];
            b[0] = Self::gf_mul(a[0], 2) ^ Self::gf_mul(a[1], 3) ^ a[2] ^ a[3];
            b[1] = a[0] ^ Self::gf_mul(a[1], 2) ^ Self::gf_mul(a[2], 3) ^ a[3];
            b[2] = a[0] ^ a[1] ^ Self::gf_mul(a[2], 2) ^ Self::gf_mul(a[3], 3);
            b[3] = Self::gf_mul(a[0], 3) ^ a[1] ^ a[2] ^ Self::gf_mul(a[3], 2);

            state[i] = u32::from_be_bytes(b);
        }
    }

    fn gf_mul(a: u8, b: u8) -> u8 {
        let mut result = 0;
        let mut a = a;
        let mut b = b;

        while b != 0 {
            if b & 1 != 0 {
                result ^= a;
            }
            let high_bit_set = a & 0x80;
            a <<= 1;
            if high_bit_set != 0 {
                a ^= 0x1b; // Irreducible polynomials used in AES
            }
            b >>= 1;
        }
        result
    }
}

fn load_dotenv<P: AsRef<Path>>(path: P) -> io::Result<()> {
    let file = File::open(path)?;
    let reader = io::BufReader::new(file);

    for line_result in reader.lines() {
        let line = line_result?;
        let line = line.trim();

        // Skip blank lines and comment lines
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Parsing the key=value format
        if let Some((key, value)) = line.split_once('=') {
            env::set_var(key.trim(), value.trim());
        }
    }

    Ok(())
}

/// A function that decodes a hexadecimal string into a byte array
fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("The length of the HEX string is not even.".to_string());
    }

    s.as_bytes()
        .chunks(2)
        .map(|chunk| {
            let high = hex_char_to_value(chunk[0])?;
            let low = hex_char_to_value(chunk[1])?;
            Ok((high << 4) | low)
        })
        .collect()
}

/// Helper function that converts HEX characters (0-9, a-f, A-F) to their corresponding values
fn hex_char_to_value(c: u8) -> Result<u8, String> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(format!("無効なHEX文字: {}", c as char)),
    }
}

pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{:02x}", byte)).collect()
}

fn main() {
    if let Err(e) = load_dotenv(".env") {
        eprintln!(".Failed to load env file: {}", e);
    }

    // Obtaining the AES key from the environment variable
    let key_hex = env::var("AES_KEY").expect("AES_KEY The environment variable is not set.");

    // Convert a hexadecimal string to a byte array
    let key = match hex_decode(&key_hex) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("The hexadecimal conversion of the key failed.: {}", e);
            std::process::exit(1);
        }
    };

    // Check the length of the key
    if key.len() != 32 {
        panic!("The key length is not 32 bytes (256 bits).");
    }

    let key: [u8; 32] = key.try_into().expect("Failed to convert key");

    // Generating a plain text block (random)
    let mut block: [u8; 16] = rand::thread_rng().gen();

    // Creating an Aes256 instance
    let aes = Aes256::new(key);

    // Block encryption
    aes.encrypt_block(&mut block);

    // Encrypted block output
    println!("Encrypted block: {:?}", block);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// NIST AES-256 Test vector
    #[test]
    fn test_aes256_encryption_nist_vector() {
        // Test vector
        let key_hex = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
        let plaintext_hex = "6bc1bee22e409f96e93d7e117393172a";
        let expected_ciphertext_hex = "f3eed1bdb5d2a03c064b5a7e3db181f8";

        // Convert a hexadecimal string to a byte array
        let key = hex_decode(key_hex).expect("The hexadecimal conversion of the key failed.");
        let plaintext =
            hex_decode(plaintext_hex).expect("Failed to convert plain text to hexadecimal.");
        let expected_ciphertext = hex_decode(expected_ciphertext_hex)
            .expect("Failed to convert ciphertext to hexadecimal.");

        // Check the length of the key
        assert_eq!(key.len(), 32, "The key length is not 32 bytes.");

        let key: [u8; 32] = key.try_into().expect("Failed to convert key");
        let mut block: [u8; 16] = plaintext.try_into().expect("Plain text conversion failed.");

        // Creating an AES instance
        let aes = Aes256::new(key);

        // Block encryption
        aes.encrypt_block(&mut block);

        // Verification of the encryption result
        assert_eq!(
            block.to_vec(),
            expected_ciphertext,
            "Encryption result does not match expected value"
        );
    }

    /// Verification of AES-256 encryption using multiple test vectors
    #[test]
    fn test_aes256_encryption_multiple_vectors() {
        let test_vectors = vec![
            (
                "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
                "6bc1bee22e409f96e93d7e117393172a",
                "f3eed1bdb5d2a03c064b5a7e3db181f8",
            ),
            (
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                "00112233445566778899aabbccddeeff",
                "69c4e0d86a7b0430d8cdb78070b4c55a",
            ),
            // You can add additional test vectors here.
        ];

        for (key_hex, plaintext_hex, expected_ciphertext_hex) in test_vectors {
            // Convert a hexadecimal string to a byte array
            let key = hex_decode(key_hex).expect("The hexadecimal conversion of the key failed.");
            let plaintext =
                hex_decode(plaintext_hex).expect("Failed to convert plain text to hexadecimal.");
            let expected_ciphertext = hex_decode(expected_ciphertext_hex)
                .expect("Failed to convert ciphertext to hexadecimal.");

            assert_eq!(key.len(), 32, "The key length is not 32 bytes.");

            let key: [u8; 32] = key.try_into().expect("Failed to convert key");
            let mut block: [u8; 16] = plaintext.try_into().expect("Plain text conversion failed.");

            let aes = Aes256::new(key);
            aes.encrypt_block(&mut block);

            assert_eq!(
                block.to_vec(),
                expected_ciphertext,
                "Encryption result does not match expected value"
            );
        }
    }

    /// A test to verify the accuracy of key expansion
    #[test]
    fn test_aes256_key_expansion() {
        let key_hex = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
        let key = hex_decode(key_hex).expect("The hexadecimal conversion of the key failed.");
        let key: [u8; 32] = key.try_into().expect("Failed to convert key");

        let aes = Aes256::new(key);

        let expected_round_key_0 = 0x603deb10;
        let expected_round_key_1 = 0x15ca71be;
        let expected_round_key_2 = 0x2b73aef0;
        let expected_round_key_3 = 0x857d7781;

        assert_eq!(
            aes.round_keys[0], expected_round_key_0,
            "Round key 0 does not match."
        );
        assert_eq!(
            aes.round_keys[1], expected_round_key_1,
            "Round key 1 does not match."
        );
        assert_eq!(
            aes.round_keys[2], expected_round_key_2,
            "The round key 2 does not match."
        );
        assert_eq!(
            aes.round_keys[3], expected_round_key_3,
            "The round key 3 does not match."
        );
    }

    /// A test to verify the accuracy of the `sub_bytes` function
    #[test]
    fn test_sub_bytes() {
        let key_hex = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
        let key = hex_decode(key_hex).expect("The hexadecimal conversion of the key failed.");
        let key: [u8; 32] = key.try_into().expect("Failed to convert key");

        let aes = Aes256::new(key);

        let mut state = [0x6bc1bee2, 0x2e409f96, 0xe93d7e11, 0x7393172a];

        aes.sub_bytes(&mut state);

        // Expected state after sub-byte (calculated manually or obtained from other implementations)
        let expected_state = [0x63a5c6f7, 0x58e89f8a, 0xeb93f111, 0x7393173a];

        assert_eq!(
            state, expected_state,
            "The result of `sub_bytes` does not match the expected value."
        );
    }

    /// A test to verify the accuracy of the `mix_columns` function
    #[test]
    fn test_mix_columns() {
        let key_hex = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
        let key = hex_decode(key_hex).expect("The hexadecimal conversion of the key failed.");
        let key: [u8; 32] = key.try_into().expect("Failed to convert key");

        let aes = Aes256::new(key);

        let mut state = [0xd4ae7e6e, 0x3e8bd6bb, 0x45a16888, 0x4d3c8105];

        aes.mix_columns(&mut state);

        // Expected state after mixing column (calculated manually or obtained from other implementation)
        let expected_state = [0xe0cbf9f0, 0x5f011a11, 0xbf4000fe, 0x849c8efe];

        assert_eq!(
            state, expected_state,
            "The result of `mix_columns` does not match the expected value."
        );
    }

    /// Test to verify the accuracy of the `gf_mul` function
    #[test]
    fn test_gf_mul() {
        // Test case: Check the results of various multiplications
        let test_cases = vec![
            (0x57, 0x83, 0xc1),
            (0x13, 0x11, 0x94),
            (0x01, 0x01, 0x01),
            (0xFF, 0xFF, 0xE5),
        ];

        for (a, b, expected) in test_cases {
            let result = Aes256::gf_mul(a, b);
            assert_eq!(
                result, expected,
                "gf_mul({}, {}) = {}, expected {}",
                a, b, result, expected
            );
        }
    }

    /// A test to verify the accuracy of HEX encoding and decoding
    #[test]
    fn test_hex_encode_decode() {
        let bytes = vec![0x00, 0x11, 0x22, 0x33, 0xFF];
        let hex_str = hex_encode(&bytes);
        assert_eq!(hex_str, "00112233ff");

        let decoded = hex_decode(&hex_str).expect("Decoding failed.");
        assert_eq!(decoded, bytes);
    }

    /// Test to verify decoding of invalid HEX strings
    #[test]
    fn test_hex_decode_invalid_chars() {
        let invalid_hex = "GG";
        let result = hex_decode(invalid_hex);
        assert!(result.is_err(), "No invalid HEX characters were detected.");
    }

    /// A test to verify the decoding of odd-length HEX strings
    #[test]
    fn test_hex_decode_odd_length() {
        let odd_length_hex = "ABC";
        let result = hex_decode(odd_length_hex);
        assert!(result.is_err(), "No odd-length HEX strings were detected.");
    }

    #[test]
    fn test_key_expansion() {
        let key_hex = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F";
        let key = hex_decode(key_hex).expect("The hexadecimal conversion of the key failed.");
        let key: [u8; 32] = key.try_into().expect("Failed to convert key");

        let aes = Aes256::new(key);

        // Checking some of the expected round keys (example)
        let expected_round_keys = [
            0x00010203, 0x04050607, 0x08090A0B, 0x0C0D0E0F, 0x10111213, 0x14151617, 0x18191A1B,
            0x1C1D1E1F,
        ];

        for (i, &expected) in expected_round_keys.iter().enumerate() {
            assert_eq!(
                aes.round_keys[i], expected,
                "The round keys { } do not match.",
                i
            );
        }
    }

    #[test]
    fn test_shift_rows() {
        let key = [0u8; 32];
        let aes = Aes256::new(key);

        let mut state = [0xD4E0B81B, 0xE24C2D7F, 0xB59AED63, 0x1B970970];
        aes.shift_rows(&mut state);
        let expected_state = [0xD4E0B81B, 0x24C2D7FE, 0xB59AED63, 0x1B970970];

        assert_eq!(
            state, expected_state,
            "The result of `shift_rows` does not match the expected value"
        );
    }

    #[test]
    fn test_hex_encode() {
        let bytes = vec![0x00, 0x11, 0x22, 0x33, 0xFF];
        let hex_str = hex_encode(&bytes);
        assert_eq!(hex_str, "00112233ff");
    }

    #[test]
    fn test_hex_decode_valid() {
        let hex_str = "000102030405060708090a0b0c0d0e0f";
        let decoded = hex_decode(hex_str).expect("Decoding failed.");
        assert_eq!(
            decoded,
            vec![
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
                0x0E, 0x0F
            ]
        );
    }

    #[test]
    fn test_hex_decode_invalid_length() {
        let hex_str = "000102030405060708090a0b0c0d0e0";
        let result = hex_decode(hex_str);
        assert!(result.is_err(), "No odd-length HEX strings were detected.");
    }

    #[test]
    fn test_hex_decode_invalid_char() {
        let hex_str = "000102030405060708090a0b0c0d0e0g";
        let result = hex_decode(hex_str);
        assert!(result.is_err(), "No invalid HEX characters were detected.");
    }

    #[test]
    fn test_load_dotenv() {
        use std::env;
        use std::io::Write;
        use tempfile::NamedTempFile;

        // Create a temporary file for testing
        let mut temp_file = NamedTempFile::new().expect("Failed to create temporary file");
        writeln!(
            temp_file,
            "AES_KEY=abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        )
        .expect("Failed to write to file");
        writeln!(temp_file, "# Comment line").expect("Failed to write to file");
        writeln!(temp_file, "INVALID_LINE").expect("Failed to write to file");

        // Loading the `.env` file
        load_dotenv(temp_file.path()).expect(".Failed to load env file");

        // Checking the environment variables
        let aes_key = env::var("AES_KEY").expect("AES_KEY is not set.");
        assert_eq!(
            aes_key,
            "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        );
    }
}
