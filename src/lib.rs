/// Four-byte magic prefix that identifies a `LiftNet` Encrypted artifact.
pub const FORMAT_MAGIC: [u8; 4] = *b"LNEC";

/// Current wire-format version.
pub const FORMAT_VERSION: u8 = 0x01;

/// Threshold below which the entire file is read into memory in one shot.
///
/// Files above this size are also read fully before encryption because
/// `aes-gcm` 0.10.x does not expose a streaming (chunked) AEAD API —
/// the whole plaintext must be in memory to compute a single authentication
/// tag. Using `BufReader`/`BufWriter` throughout still avoids redundant
/// kernel-to-userspace round-trips for I/O buffering.
pub const SINGLE_SHOT_LIMIT: u64 = 16 * 1024 * 1024; // 16 MiB

use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
use anyhow::{Context, Result, bail};
use rsa::{Oaep, RsaPublicKey};
use sha2::Sha512;
use std::io::{Read, Write};

/// Encrypt plaintext bytes and write the LNEC artifact to `writer`.
///
/// Wire format:
/// ```text
/// [Magic (4 B)]  b"LNEC"
/// [Version (1 B)] 0x01
/// [KeyLen (4 B big-endian)]
/// [EncryptedAESKey (KeyLen B)]
/// [Nonce (12 B)]
/// [Ciphertext + GCM tag]
/// ```
///
/// # Errors
///
/// Returns an error if RSA encryption, AES-GCM encryption, or any write
/// operation fails.
pub fn encrypt_to_writer<W: Write>(
    plaintext: &[u8],
    public_key: &RsaPublicKey,
    rng: &mut (impl rand::RngCore + rand::CryptoRng),
    writer: &mut W,
) -> Result<()> {
    // Generate a fresh AES-256-GCM session key and nonce.
    let aes_key = Aes256Gcm::generate_key(&mut *rng);
    let nonce_bytes = {
        let mut b = [0u8; 12];
        rng.fill_bytes(&mut b);
        b
    };
    let nonce = Nonce::from_slice(&nonce_bytes);

    tracing::debug!("AES session key generated");
    tracing::debug!("Nonce generated");

    // AES-256-GCM encrypt (single-shot — see SINGLE_SHOT_LIMIT doc comment).
    let cipher = Aes256Gcm::new(&aes_key);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("AES-GCM encryption failed: {e}"))?;

    tracing::debug!(ciphertext_len = ciphertext.len(), "Plaintext encrypted");

    // Wrap the AES key with RSA-OAEP-SHA512.
    let encrypted_aes_key = public_key
        .encrypt(rng, Oaep::new::<Sha512>(), aes_key.as_slice())
        .context("RSA key wrap failed")?;

    tracing::debug!(
        key_len = encrypted_aes_key.len(),
        "AES key wrapped with RSA-OAEP"
    );

    let key_len =
        u32::try_from(encrypted_aes_key.len()).context("Encrypted key length overflows u32")?;

    // Write magic + version.
    writer
        .write_all(&FORMAT_MAGIC)
        .context("Failed to write magic bytes")?;
    writer
        .write_all(&[FORMAT_VERSION])
        .context("Failed to write version byte")?;

    // Write key length + encrypted key.
    writer
        .write_all(&key_len.to_be_bytes())
        .context("Failed to write key length")?;
    writer
        .write_all(&encrypted_aes_key)
        .context("Failed to write encrypted AES key")?;

    // Write nonce + ciphertext.
    writer
        .write_all(&nonce_bytes)
        .context("Failed to write nonce")?;
    writer
        .write_all(&ciphertext)
        .context("Failed to write ciphertext")?;

    Ok(())
}

/// Decrypt a LNEC artifact produced by [`encrypt_to_writer`].
///
/// Accepts any `Read` source; the caller is responsible for buffering if
/// needed. Returns the plaintext on success.
///
/// # Errors
///
/// Returns an error if the magic or version bytes are wrong, if RSA
/// decryption fails, if GCM authentication fails, or if the data is
/// truncated.
pub fn decrypt_from_reader<R: Read>(
    reader: &mut R,
    private_key: &rsa::RsaPrivateKey,
) -> Result<Vec<u8>> {
    // Validate magic.
    let mut magic = [0u8; 4];
    reader
        .read_exact(&mut magic)
        .context("Failed to read magic bytes")?;
    if magic != FORMAT_MAGIC {
        bail!("Invalid magic bytes: expected {FORMAT_MAGIC:?}, got {magic:?}");
    }

    // Validate version.
    let mut version = [0u8; 1];
    reader
        .read_exact(&mut version)
        .context("Failed to read version byte")?;
    if version[0] != FORMAT_VERSION {
        bail!(
            "Unsupported format version: expected {FORMAT_VERSION}, got {}",
            version[0]
        );
    }

    // Read key length.
    let mut len_bytes = [0u8; 4];
    reader
        .read_exact(&mut len_bytes)
        .context("Failed to read key length")?;
    let key_len =
        usize::try_from(u32::from_be_bytes(len_bytes)).context("Key length overflows usize")?;

    // Read encrypted AES key.
    let mut enc_aes_key = vec![0u8; key_len];
    reader
        .read_exact(&mut enc_aes_key)
        .context("Failed to read encrypted AES key")?;

    // Read nonce.
    let mut nonce_bytes = [0u8; 12];
    reader
        .read_exact(&mut nonce_bytes)
        .context("Failed to read nonce")?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Read ciphertext.
    let mut ciphertext = Vec::new();
    reader
        .read_to_end(&mut ciphertext)
        .context("Failed to read ciphertext")?;

    // Unwrap AES key with RSA-OAEP-SHA512.
    let session_key = private_key
        .decrypt(Oaep::new::<Sha512>(), &enc_aes_key)
        .context("RSA key unwrap failed")?;

    // AES-256-GCM decrypt (authenticates ciphertext + tag).
    let cipher =
        Aes256Gcm::new_from_slice(&session_key).context("Invalid AES key length from RSA")?;
    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|e| anyhow::anyhow!("AES-GCM decryption / authentication failed: {e}"))?;

    Ok(plaintext)
}
