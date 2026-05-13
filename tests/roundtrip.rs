use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
use binary_encrypter::{FORMAT_MAGIC, FORMAT_VERSION, decrypt_from_reader, encrypt_to_writer};
use rand::RngCore as _;
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use sha2::Sha512;
use std::io::{Cursor, Read, Write};

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/// Generate a 3072-bit RSA keypair.  3072 bits matches the production key
/// size used by `binary_encrypter`/`binary_updater`.
fn generate_keypair() -> (RsaPrivateKey, RsaPublicKey) {
    let mut rng = rand::thread_rng();
    let private = RsaPrivateKey::new(&mut rng, 3072).expect("keygen failed");
    let public = RsaPublicKey::from(&private);
    (private, public)
}

/// Encrypt `plaintext` with `pub_key`, returning the raw artifact bytes.
fn encrypt_bytes(plaintext: &[u8], pub_key: &RsaPublicKey) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut buf = Vec::new();
    encrypt_to_writer(plaintext, pub_key, &mut rng, &mut buf).expect("encrypt failed");
    buf
}

/// Decrypt `artifact` with `priv_key`, returning the plaintext.
fn decrypt_bytes(artifact: &[u8], priv_key: &RsaPrivateKey) -> anyhow::Result<Vec<u8>> {
    let mut cursor = Cursor::new(artifact);
    decrypt_from_reader(&mut cursor, priv_key)
}

// ---------------------------------------------------------------------------
// Test cases
// ---------------------------------------------------------------------------

/// Encrypt then decrypt should reproduce the original plaintext exactly.
#[test]
fn happy_path_roundtrip() {
    let (priv_key, pub_key) = generate_keypair();
    let plaintext = b"the quick brown fox jumps over the lazy dog";

    let artifact = encrypt_bytes(plaintext, &pub_key);
    let recovered = decrypt_bytes(&artifact, &priv_key).expect("decrypt failed");

    assert_eq!(recovered, plaintext);
}

/// Flipping one byte in the ciphertext body must cause GCM authentication
/// failure (decrypt returns an error, not corrupted plaintext).
#[test]
fn tampered_ciphertext_fails() {
    let (priv_key, pub_key) = generate_keypair();
    let plaintext = b"sensitive payload";

    let mut artifact = encrypt_bytes(plaintext, &pub_key);

    // Corrupt the last byte (well inside the ciphertext body).
    let last = artifact.len() - 1;
    artifact[last] ^= 0xFF;

    let result = decrypt_bytes(&artifact, &priv_key);
    assert!(result.is_err(), "Expected auth failure but got Ok");
}

/// Flipping one byte of the nonce region must cause GCM authentication
/// failure.
#[test]
fn tampered_nonce_fails() {
    let (priv_key, pub_key) = generate_keypair();
    let plaintext = b"nonce tamper test";

    let artifact = encrypt_bytes(plaintext, &pub_key);

    // Layout: magic(4) + version(1) + keylen(4) + enckey(?) + nonce(12)
    let key_len = {
        let mut b = [0u8; 4];
        b.copy_from_slice(&artifact[5..9]);
        u32::from_be_bytes(b) as usize
    };
    let nonce_start = 4 + 1 + 4 + key_len;
    let mut tampered = artifact;
    tampered[nonce_start] ^= 0xFF;

    let result = decrypt_bytes(&tampered, &priv_key);
    assert!(result.is_err(), "Expected auth failure but got Ok");
}

/// Encrypting with key A and decrypting with key B must fail at RSA unwrap.
#[test]
fn wrong_key_fails() {
    let (_priv_a, pub_a) = generate_keypair();
    let (priv_b, _pub_b) = generate_keypair();

    let artifact = encrypt_bytes(b"secret", &pub_a);
    let result = decrypt_bytes(&artifact, &priv_b);
    assert!(result.is_err(), "Expected RSA error but got Ok");
}

/// Providing fewer bytes than a complete artifact header must return an error,
/// not panic.
#[test]
fn truncated_input_fails_cleanly() {
    let (priv_key, pub_key) = generate_keypair();
    let artifact = encrypt_bytes(b"truncation test", &pub_key);

    // Try several truncation points, all must error (not panic).
    for truncate_at in [0, 1, 4, 8, artifact.len() / 2] {
        let truncated = &artifact[..truncate_at];
        let result = decrypt_bytes(truncated, &priv_key);
        assert!(
            result.is_err(),
            "Expected error for truncation at {truncate_at}, got Ok"
        );
    }
}

/// Encrypting the same plaintext twice must yield different ciphertext because
/// a fresh nonce is generated each time.
#[test]
fn same_plaintext_yields_different_ciphertext() {
    let (_priv_key, pub_key) = generate_keypair();
    let plaintext = b"determinism check";

    let artifact1 = encrypt_bytes(plaintext, &pub_key);
    let artifact2 = encrypt_bytes(plaintext, &pub_key);

    // The two artifacts must differ (nonce randomness ensures this overwhelmingly).
    assert_ne!(
        artifact1, artifact2,
        "Two encryptions of identical plaintext produced identical ciphertext"
    );
}

/// Encrypting and decrypting a 10 MiB payload must succeed and round-trip
/// correctly.
#[test]
fn large_input_roundtrip() {
    let (priv_key, pub_key) = generate_keypair();

    // 10 MiB of pseudo-random data.
    let mut plaintext = vec![0u8; 10 * 1024 * 1024];
    rand::thread_rng().fill_bytes(&mut plaintext);

    let artifact = encrypt_bytes(&plaintext, &pub_key);
    let recovered = decrypt_bytes(&artifact, &priv_key).expect("large decrypt failed");

    assert_eq!(recovered, plaintext);
}

/// The first five bytes of every artifact must be `b"LNEC"` + `0x01`.
#[test]
fn format_magic_present() {
    let (_priv_key, pub_key) = generate_keypair();
    let artifact = encrypt_bytes(b"magic check", &pub_key);

    assert_eq!(&artifact[..4], &FORMAT_MAGIC, "Wrong magic bytes");
    assert_eq!(artifact[4], FORMAT_VERSION, "Wrong version byte");
}

/// Providing bytes whose first four bytes are NOT `b"LNEC"` must return a
/// specific error.
#[test]
fn wrong_magic_rejected() {
    let (priv_key, pub_key) = generate_keypair();
    let mut artifact = encrypt_bytes(b"magic rejection test", &pub_key);

    // Overwrite magic with garbage.
    artifact[..4].copy_from_slice(b"XXXX");

    let result = decrypt_bytes(&artifact, &priv_key);
    assert!(result.is_err(), "Expected magic rejection but got Ok");

    let msg = format!("{}", result.unwrap_err());
    assert!(
        msg.contains("Invalid magic bytes") || msg.contains("magic"),
        "Expected 'Invalid magic bytes' in error, got: {msg}"
    );
}

// ---------------------------------------------------------------------------
// Additional robustness tests
// ---------------------------------------------------------------------------

/// Wrong version byte (0x02) must be rejected with a clear error.
#[test]
fn wrong_version_rejected() {
    let (priv_key, pub_key) = generate_keypair();
    let mut artifact = encrypt_bytes(b"version rejection", &pub_key);

    // Version byte is at offset 4.
    artifact[4] = 0x02;

    let result = decrypt_bytes(&artifact, &priv_key);
    assert!(result.is_err(), "Expected version rejection but got Ok");

    let msg = format!("{}", result.unwrap_err());
    assert!(
        msg.contains("Unsupported format version") || msg.contains("version"),
        "Expected 'Unsupported format version' in error, got: {msg}"
    );
}

/// A completely empty input should encrypt (0-byte plaintext) and round-trip.
#[test]
fn empty_plaintext_roundtrip() {
    let (priv_key, pub_key) = generate_keypair();
    let artifact = encrypt_bytes(b"", &pub_key);
    let recovered = decrypt_bytes(&artifact, &priv_key).expect("empty decrypt failed");
    assert!(recovered.is_empty());
}

// ---------------------------------------------------------------------------
// Cross-check: hand-written decrypt that mirrors `binary_updater` logic
// ---------------------------------------------------------------------------

/// Verify that the artifact produced by `encrypt_to_writer` can also be
/// decoded by hand-written decrypt code that mirrors what `binary_updater` does
/// (minus the magic/version header, which `binary_updater` will be updated to
/// handle in a follow-up ticket).
///
/// This test decrypts the payload *after* stripping the 5-byte header, using
/// the same RSA-OAEP-SHA512 + AES-256-GCM logic as `binary_updater`'s
/// `decrypt_artifact`.
#[test]
fn manual_decrypt_matches_lib_decrypt() {
    let (priv_key, pub_key) = generate_keypair();
    let plaintext = b"cross-check payload";

    let artifact = encrypt_bytes(plaintext, &pub_key);

    // Strip magic (4) + version (1) = 5 bytes to get the legacy layout.
    let legacy = &artifact[5..];

    // Hand-roll the decrypt (mirrors binary_updater crypto.rs decrypt_artifact).
    let mut cursor = Cursor::new(legacy);

    let mut len_bytes = [0u8; 4];
    cursor.read_exact(&mut len_bytes).unwrap();
    let key_len = u32::from_be_bytes(len_bytes) as usize;

    let mut enc_key = vec![0u8; key_len];
    cursor.read_exact(&mut enc_key).unwrap();

    let mut nonce_bytes = [0u8; 12];
    cursor.read_exact(&mut nonce_bytes).unwrap();
    let nonce = Nonce::from_slice(&nonce_bytes);

    let mut ciphertext = Vec::new();
    cursor.read_to_end(&mut ciphertext).unwrap();

    let session_key = priv_key
        .decrypt(Oaep::new::<Sha512>(), &enc_key)
        .expect("RSA unwrap failed");
    let cipher = Aes256Gcm::new_from_slice(&session_key).unwrap();
    let recovered = cipher.decrypt(nonce, ciphertext.as_ref()).unwrap();

    assert_eq!(recovered, plaintext);
}

// ---------------------------------------------------------------------------
// Tempfile-based end-to-end test
// ---------------------------------------------------------------------------

/// Write an artifact to a real temp file, then read it back and decrypt.
/// This exercises `BufWriter` flush and file round-trips.
#[test]
fn file_roundtrip_via_tempfile() {
    use std::fs;

    let dir = tempfile::tempdir().expect("tempdir failed");
    let out_path = dir.path().join("artifact.lnec");

    let (priv_key, pub_key) = generate_keypair();
    let plaintext = b"tempfile round-trip check";

    // Encrypt directly to a file.
    let file = fs::File::create(&out_path).expect("create failed");
    let mut writer = std::io::BufWriter::new(file);
    let mut rng = rand::thread_rng();
    encrypt_to_writer(plaintext, &pub_key, &mut rng, &mut writer).expect("encrypt to file failed");
    writer.flush().expect("flush failed");

    // Read back and decrypt.
    let artifact = fs::read(&out_path).expect("read back failed");
    let recovered = decrypt_bytes(&artifact, &priv_key).expect("decrypt from file failed");

    assert_eq!(recovered, plaintext);
}
