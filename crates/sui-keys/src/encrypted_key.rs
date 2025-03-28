// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use std::str::FromStr;
use anyhow::{anyhow, Context};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use rand::rngs::OsRng;
use rand::RngCore;
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey, NONCE_LEN};
use ring::pbkdf2;
use serde::{Deserialize, Serialize};
use shared_crypto::intent::{Intent, IntentMessage};
use std::fs;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use sui_types::base_types::SuiAddress;
use sui_types::crypto::{EncodeDecodeBase64, Signature, SuiKeyPair};
use sui_types::transaction::SenderSignedData;

// Encryption-related constants
const PBKDF2_ITERATIONS: u32 = 100_000;
const SALT_SIZE: usize = 16;
const KEY_SIZE: usize = 32;

/// Structure defining the file format of the encrypted keystore
#[derive(Serialize, Deserialize)]
pub struct EncryptedKeyData {
    /// Encryption version (for future version upgrades)
    pub version: u8,
    /// IV used for encryption (Base64 encoded)
    pub iv: String,
    /// Salt used for key derivation from password (Base64 encoded)
    pub salt: String,
    /// The encryption cipher used
    pub cipher: String,
    /// Number of iterations for PBKDF2
    pub iterations: u32,
    /// The Sui address corresponding to this key
    pub address: String,
    /// The ciphertext (Base64 encoded)
    pub ciphertext: String,
}

/// Data structure for secure signing results using encrypted key
#[derive(Serialize, Deserialize, Debug)]
pub struct SignEncryptedData {
    /// SUI address of the signer
    pub sui_address: SuiAddress,
    
    /// Base64 encoded transaction data serialization string
    pub raw_tx_data: String,
    
    /// Intent structure used
    pub intent: Intent,
    
    /// Base64 encoded serialized IntentMessage in the form of (intent || message)
    pub raw_intent_msg: String,
    
    /// Blake2b hash of the signed intent message (Base64 encoded)
    pub digest: String,
    
    /// Base64 encoded string of complete Sui signature (flag || signature || pubkey)
    pub sui_signature: String,
    
    /// Signed transaction
    pub signed_data: SenderSignedData,
}

/// Load EncryptedKeyData from file
/// Reads and parses an encrypted key file in the standard format (.encrypted).
/// Only supports version 1 of the encryption format.
/// Future versions may add support for different encryption algorithms.
pub fn load_encrypted_key_data(key_file: &Path) -> Result<EncryptedKeyData, anyhow::Error> {
    // Read encrypted data from file
    let json = fs::read_to_string(key_file)
        .map_err(|e| anyhow!("Failed to read key file: {}", e))?;
    
    // Parse into encrypted data structure
    let encrypted_data: EncryptedKeyData = serde_json::from_str(&json)
        .map_err(|e| anyhow!("Invalid key file format: {}", e))?;
    
    // Verify encryption version
    if encrypted_data.version != 1 {
        return Err(anyhow!("Unsupported encryption version: {}", encrypted_data.version));
    }
    
    Ok(encrypted_data)
}

/// Decrypt keypair from EncryptedKeyData
/// This function securely decrypts the keypair using the provided password.
/// It uses PBKDF2 for key derivation and AES-256-GCM for decryption.
/// Sensitive data is zeroed from memory after use.
pub fn decrypt_key_pair(encrypted_data: &EncryptedKeyData, password: &str) -> Result<SuiKeyPair, anyhow::Error> {
    // Prepare decryption parameter
    if encrypted_data.cipher != "aes-256-gcm" {
        return Err(anyhow!("Unsupported cipher: {}", encrypted_data.cipher));
    }
    
    let ciphertext = BASE64.decode(&encrypted_data.ciphertext)
        .map_err(|e| anyhow!("Failed to decode ciphertext: {}", e))?;
    
    let iv = BASE64.decode(&encrypted_data.iv)
        .map_err(|e| anyhow!("Failed to decode IV: {}", e))?;
    
    let salt = BASE64.decode(&encrypted_data.salt)
        .map_err(|e| anyhow!("Failed to decode salt: {}", e))?;
    
    if iv.len() != NONCE_LEN {
        return Err(anyhow!("Invalid IV length"));
    }
    
    // Derive key from password
    let iterations = NonZeroU32::new(encrypted_data.iterations)
        .ok_or_else(|| anyhow!("Invalid iteration count"))?;
    
    let mut derived_key = [0u8; KEY_SIZE];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256, 
        iterations, 
        &salt, 
        password.as_bytes(), 
        &mut derived_key
    );
    
    // Create a scope to ensure sensitive memory is zeroed
    let result = {
        // Decrypt
        let unbound_key = UnboundKey::new(&aead::AES_256_GCM, &derived_key)
            .map_err(|_| anyhow!("Failed to create decryption key"))?;
        let less_safe_key = LessSafeKey::new(unbound_key);
        
        let mut nonce_bytes = [0u8; NONCE_LEN];
        nonce_bytes.copy_from_slice(&iv);
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let aad = Aad::empty();
        
        let mut ciphertext_copy = ciphertext.clone();
        let plaintext = less_safe_key
            .open_in_place(nonce, aad, &mut ciphertext_copy)
            .map_err(|_| anyhow!("Decryption failed - wrong password or corrupted data"))?;
        
        // Restore keypair
        let plaintext_str = std::str::from_utf8(plaintext)
            .map_err(|e| anyhow!("Failed to convert key data: {}", e))?;
        
        SuiKeyPair::decode_base64(plaintext_str)
            .map_err(|e| anyhow!("Failed to restore keypair: {}", e))
    };
    
    // Zero out sensitive data from memory
    derived_key.iter_mut().for_each(|b| *b = 0);
    
    result
}

/// Verify keypair address matches address in encrypted data
/// This is a critical security check to ensure the decrypted key corresponds
/// to the expected address stored in the encrypted file, protecting against
/// potential tampering or corruption of the key file.
pub fn verify_key_address(keypair: &SuiKeyPair, encrypted_data: &EncryptedKeyData) -> Result<SuiAddress, anyhow::Error> {
    let address_from_keypair: SuiAddress = (&keypair.public()).into();
    let expected_address: SuiAddress = SuiAddress::from_str(&encrypted_data.address)?;
    
    if address_from_keypair != expected_address {
        return Err(anyhow!(
            "Address mismatch: file stored address {}, actual key address {}", 
            expected_address, address_from_keypair
        ));
    }
    
    Ok(address_from_keypair)
}

/// Sign transaction data with encrypted key data
/// This function securely signs transaction data using password-protected encrypted key.
/// The key is temporarily decrypted in memory and immediately zeroed after signing.
pub fn sign_encrypted<T>(
    key_data: &EncryptedKeyData,
    password: &str,
    msg: &T,
    intent: Intent,
) -> Result<Signature, anyhow::Error> 
where
    T: Serialize,
{
    // Decrypt the key and verify the address
    let keypair = decrypt_key_pair(key_data, password)?;
    verify_key_address(&keypair, key_data)?;
    
    Ok(Signature::new_secure(
        &IntentMessage::new(intent, msg),
        &keypair,
    ))
}

/// Create a new encrypted key file
/// Encrypts the provided keypair with the given password using AES-256-GCM
/// and writes it to a file named with the SUI address.
pub fn create_encrypted_key_file(
    output_dir: &Path,
    password: &str,
    keypair: &SuiKeyPair
) -> Result<(PathBuf, SuiAddress), anyhow::Error> {
    let sui_address: SuiAddress = (&keypair.public()).into();
    
    // Check output directory and create if needed
    if !output_dir.exists() {
        fs::create_dir_all(output_dir)
            .with_context(|| format!("Failed to create output directory: {:?}", output_dir))?;
    }
    
    // Generate encryption parameters
    let mut salt = [0u8; SALT_SIZE];
    let mut rng = OsRng;
    rng.fill_bytes(&mut salt);
    
    let mut iv = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut iv);
    
    // Create encrypted key file path
    let encrypted_file_name = format!("{}.encrypted", sui_address);
    let encrypted_file_path = output_dir.join(&encrypted_file_name);
    
    // Encrypt and save
    encrypt_keypair_to_file(keypair, password, &encrypted_file_path, &salt, &iv)?;
    
    Ok((encrypted_file_path, sui_address))
}

/// Internal function to encrypt and save keypair to file
fn encrypt_keypair_to_file(
    keypair: &SuiKeyPair,
    password: &str,
    file_path: &PathBuf,
    salt: &[u8],
    iv: &[u8; NONCE_LEN]
) -> Result<(), anyhow::Error> {
    // Derive encryption key from password
    let iterations = NonZeroU32::new(PBKDF2_ITERATIONS).unwrap();
    
    let mut derived_key = [0u8; KEY_SIZE]; // AES-256 key size
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256, 
        iterations, 
        salt, 
        password.as_bytes(), 
        &mut derived_key
    );
    
    // Serialize key pair
    let serialized_keypair = keypair.encode_base64();
    
    // Encrypt
    let unbound_key = UnboundKey::new(&aead::AES_256_GCM, &derived_key)
        .map_err(|_| anyhow!("Failed to create encryption key"))?;
    let less_safe_key = LessSafeKey::new(unbound_key);
    
    let nonce = Nonce::assume_unique_for_key(*iv);
    let aad = Aad::empty(); // No additional authentication data
    
    let mut serialized_data = serialized_keypair.as_bytes().to_vec();
    less_safe_key
        .seal_in_place_append_tag(nonce, aad, &mut serialized_data)
        .map_err(|_| anyhow!("Encryption failed"))?;
    
    // Address for verification
    let address: SuiAddress = (&keypair.public()).into();
    
    // Create encrypted data structure
    let encrypted_data = EncryptedKeyData {
        version: 1,
        iv: BASE64.encode(iv),
        salt: BASE64.encode(salt),
        cipher: "aes-256-gcm".to_string(),
        iterations: PBKDF2_ITERATIONS,
        address: address.to_string(),
        ciphertext: BASE64.encode(&serialized_data),
    };
    
    // Serialize to JSON and save to file
    let json = serde_json::to_string_pretty(&encrypted_data)?;
    fs::write(file_path, json)?;
    
    Ok(())
}

/// Load keypair from keystore using password
pub fn load_key_from_keystore(
    key_file: &Path,
    password: &str
) -> Result<(SuiKeyPair, SuiAddress), anyhow::Error> {
    // Load encrypted data
    let encrypted_data = load_encrypted_key_data(key_file)?;
    
    // Decrypt keypair
    let keypair = decrypt_key_pair(&encrypted_data, password)?;
    
    // Verify address
    let address = verify_key_address(&keypair, &encrypted_data)?;
    
    // Return in expected order: keypair first, then address
    Ok((keypair, address))
}