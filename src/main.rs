use binary_encrypter::{SINGLE_SHOT_LIMIT, encrypt_to_writer};
use clap::Parser;
use rsa::{RsaPublicKey, pkcs8::DecodePublicKey};
use std::{
    fs,
    io::{BufReader, BufWriter, Read, Write},
    path::PathBuf,
};
use tracing::debug;

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
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();

    // 1. Load RSA Public Key
    debug!(path = %args.key.display(), "Reading RSA public key");
    let pem = fs::read_to_string(&args.key)
        .map_err(|e| anyhow::anyhow!("Failed to read public key: {e}"))?;
    let public_key = RsaPublicKey::from_public_key_pem(&pem)
        .map_err(|e| anyhow::anyhow!("Failed to parse RSA public key: {e}"))?;

    debug!("RSA public key parsed");

    // 2. Read input file via BufReader.
    //    For files ≤ SINGLE_SHOT_LIMIT the data fits comfortably in RAM.
    //    For larger files we also read fully — see lib.rs doc comment for the
    //    rationale (aes-gcm 0.10.x does not support streaming AEAD).
    debug!(path = %args.input.display(), "Reading input file");
    let input_file = fs::File::open(&args.input)
        .map_err(|e| anyhow::anyhow!("Failed to open input file: {e}"))?;
    let file_size = input_file.metadata().map_or(0, |m| m.len());
    if file_size > SINGLE_SHOT_LIMIT {
        tracing::warn!(
            file_size,
            limit = SINGLE_SHOT_LIMIT,
            "Input file exceeds single-shot limit; reading fully into memory (aes-gcm 0.10.x limitation)"
        );
    }
    let mut reader = BufReader::new(input_file);
    let mut file_data = Vec::with_capacity(usize::try_from(file_size).unwrap_or(0));
    reader
        .read_to_end(&mut file_data)
        .map_err(|e| anyhow::anyhow!("Failed to read input file: {e}"))?;

    debug!(bytes = file_data.len(), "Input file read");

    // 3. Encrypt and write output via BufWriter.
    debug!(path = %args.output.display(), "Opening output file");
    let out_file = fs::File::create(&args.output)
        .map_err(|e| anyhow::anyhow!("Failed to create output file: {e}"))?;
    let mut writer = BufWriter::new(out_file);

    let mut rng = rand::thread_rng();
    encrypt_to_writer(&file_data, &public_key, &mut rng, &mut writer)?;

    // Flush the BufWriter explicitly so write errors surface here.
    writer
        .flush()
        .map_err(|e| anyhow::anyhow!("Failed to flush output: {e}"))?;

    tracing::info!(output = %args.output.display(), "Successfully encrypted");
    Ok(())
}
