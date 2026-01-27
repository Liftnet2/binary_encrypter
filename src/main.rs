use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
use clap::Parser;
use rsa::{Oaep, RsaPublicKey, pkcs8::DecodePublicKey};
use sha2::Sha256;
use std::{fs, io::Write, path::PathBuf};

// Include the generated VERSION_STRING and other metadata from build.rs
include!(concat!(env!("OUT_DIR"), "/version_generated.rs"));

/// Hybrid encryption tool: Encrypts a file using AES-256-GCM and wraps the key with RSA.
#[derive(Parser, Debug)]
#[command(author, version = VERSION_STRING, about, long_about = None)]
struct Args {
    /// Path to the file you want to encrypt
    #[arg(short, long, value_name = "FILE")]
    input: PathBuf,

    /// Path to the RSA Public Key (PEM format)
    #[arg(short, long, value_name = "PEM")]
    key: PathBuf,

    /// Destination path for the encrypted binary
    #[arg(short, long, value_name = "OUTPUT")]
    output: PathBuf,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // 1. Load RSA Public Key
    let pem = fs::read_to_string(&args.key)
        .map_err(|e| anyhow::anyhow!("Failed to read public key: {e}"))?;
    let public_key = RsaPublicKey::from_public_key_pem(&pem)
        .map_err(|e| anyhow::anyhow!("Failed to parse RSA public key: {e}"))?;

    // 2. Prepare AES-256-GCM
    let mut rng = rand::thread_rng();
    let aes_key = Aes256Gcm::generate_key(&mut rng);
    let nonce_bytes = rand::random::<[u8; 12]>();
    let nonce = Nonce::from_slice(&nonce_bytes);

    // 3. Encrypt File Data
    let file_data =
        fs::read(&args.input).map_err(|e| anyhow::anyhow!("Failed to read input file: {e}"))?;

    let cipher = Aes256Gcm::new(&aes_key);
    let ciphertext = cipher
        .encrypt(nonce, file_data.as_ref())
        .map_err(|e| anyhow::anyhow!("AES encryption failure: {e}"))?;

    // 4. Wrap AES Key with RSA-OAEP
    let encrypted_aes_key = public_key
        .encrypt(&mut rng, Oaep::new::<Sha256>(), aes_key.as_slice())
        .map_err(|e| anyhow::anyhow!("RSA key wrap failure: {e}"))?;

    // 5. Write binary package
    // Format: [KeyLen (4b)][EncKey][Nonce (12b)][Ciphertext]
    let mut out = fs::File::create(&args.output)?;
    out.write_all(&u32::try_from(encrypted_aes_key.len())?.to_be_bytes())?;
    out.write_all(&encrypted_aes_key)?;
    out.write_all(&nonce_bytes)?;
    out.write_all(&ciphertext)?;

    println!("Successfully encrypted to {}", args.output.display());
    Ok(())
}
