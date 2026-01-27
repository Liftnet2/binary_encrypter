use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
use rsa::{Oaep, RsaPublicKey, pkcs8::DecodePublicKey};
use sha2::Sha256;
use std::fs;
use std::io::Write;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        eprintln!("Usage: encryptor <input_file> <public_key_pem> <output_file>");
        std::process::exit(1);
    }

    let input_path = &args[1];
    let key_path = &args[2];
    let output_path = &args[3];

    // 1. Load RSA Public Key
    let pem = fs::read_to_string(key_path)?;
    let public_key = RsaPublicKey::from_public_key_pem(&pem)?;

    // 2. Generate random AES-256 key and Nonce
    let aes_key = Aes256Gcm::generate_key(&mut rand::thread_rng());
    let nonce_bytes = rand::random::<[u8; 12]>();
    let nonce = Nonce::from_slice(&nonce_bytes);

    // 3. Encrypt File with AES-GCM
    let file_data = fs::read(input_path)?;
    let cipher = Aes256Gcm::new(&aes_key);
    let ciphertext = cipher
        .encrypt(nonce, file_data.as_ref())
        .map_err(|e| anyhow::anyhow!("AES encryption failure: {}", e))?;

    // 4. Encrypt AES Key with RSA-OAEP (SHA-256)
    let mut rng = rand::thread_rng();
    let encrypted_aes_key =
        public_key.encrypt(&mut rng, Oaep::new::<Sha256>(), aes_key.as_slice())?;

    // 5. Write Output: [KeyLen (4b)][EncKey][Nonce (12b)][Ciphertext]
    let mut out = fs::File::create(output_path)?;
    out.write_all(&(encrypted_aes_key.len() as u32).to_be_bytes())?;
    out.write_all(&encrypted_aes_key)?;
    out.write_all(&nonce_bytes)?;
    out.write_all(&ciphertext)?;

    println!("Successfully encrypted to {}", output_path);
    Ok(())
}
