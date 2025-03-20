// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::key_derive::{derive_key_pair_from_path, generate_new_key};
use crate::random_names::{random_name, random_names};
use anyhow::{anyhow, bail, ensure, Context};
use bip32::DerivationPath;
use bip39::{Language, Mnemonic, Seed};
use rand::{rngs::StdRng, SeedableRng, RngCore};
use regex::Regex;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use shared_crypto::intent::{Intent, IntentMessage};
use std::collections::{BTreeMap, HashSet};
use std::fmt::Write;
use std::fmt::{Display, Formatter};
use std::fs;
use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use sui_types::base_types::SuiAddress;
use sui_types::crypto::get_key_pair_from_rng;
use sui_types::crypto::{
    enum_dispatch, EncodeDecodeBase64, PublicKey, Signature, SignatureScheme, SuiKeyPair,
};
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey, NONCE_LEN};
use ring::pbkdf2;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use rand::rngs::OsRng;
use std::num::NonZeroU32;
use hex;
use sui_types::crypto::DefaultHash;
use sui_types::transaction::{Transaction, TransactionData};
use fastcrypto::hash::HashFunction;

/// Data structure for secure signing results using encrypted keystore
#[derive(Serialize, Deserialize, Debug)]
pub struct SecureSignData {
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
    pub signed_transaction: String,
}

#[derive(Serialize, Deserialize)]
#[enum_dispatch(AccountKeystore)]
pub enum Keystore {
    File(FileBasedKeystore),
    InMem(InMemKeystore),
    Encrypted(EncryptedFileBasedKeystore),
}
#[enum_dispatch]
pub trait AccountKeystore: Send + Sync {
    fn add_key(&mut self, alias: Option<String>, keypair: SuiKeyPair) -> Result<(), anyhow::Error>;
    fn keys(&self) -> Vec<PublicKey>;
    fn get_key(&self, address: &SuiAddress) -> Result<&SuiKeyPair, anyhow::Error>;

    fn sign_hashed(&self, address: &SuiAddress, msg: &[u8]) -> Result<Signature, signature::Error>;

    fn sign_secure<T>(
        &self,
        address: &SuiAddress,
        msg: &T,
        intent: Intent,
    ) -> Result<Signature, signature::Error>
    where
        T: Serialize;
    fn addresses(&self) -> Vec<SuiAddress> {
        self.keys().iter().map(|k| k.into()).collect()
    }
    fn addresses_with_alias(&self) -> Vec<(&SuiAddress, &Alias)>;
    fn aliases(&self) -> Vec<&Alias>;
    fn aliases_mut(&mut self) -> Vec<&mut Alias>;
    fn alias_names(&self) -> Vec<&str> {
        self.aliases()
            .into_iter()
            .map(|a| a.alias.as_str())
            .collect()
    }
    /// Get alias of address
    fn get_alias_by_address(&self, address: &SuiAddress) -> Result<String, anyhow::Error>;
    fn get_address_by_alias(&self, alias: String) -> Result<&SuiAddress, anyhow::Error>;
    /// Check if an alias exists by its name
    fn alias_exists(&self, alias: &str) -> bool {
        self.alias_names().contains(&alias)
    }

    fn create_alias(&self, alias: Option<String>) -> Result<String, anyhow::Error>;

    fn update_alias(
        &mut self,
        old_alias: &str,
        new_alias: Option<&str>,
    ) -> Result<String, anyhow::Error>;

    // Internal function. Use update_alias instead
    fn update_alias_value(
        &mut self,
        old_alias: &str,
        new_alias: Option<&str>,
    ) -> Result<String, anyhow::Error> {
        if !self.alias_exists(old_alias) {
            bail!("The provided alias {old_alias} does not exist");
        }
        let new_alias_name = self.create_alias(new_alias.map(str::to_string))?;
        for a in self.aliases_mut() {
            if a.alias == old_alias {
                let pk = &a.public_key_base64;
                *a = Alias {
                    alias: new_alias_name.clone(),
                    public_key_base64: pk.clone(),
                };
            }
        }
        Ok(new_alias_name)
    }

    fn generate_and_add_new_key(
        &mut self,
        key_scheme: SignatureScheme,
        alias: Option<String>,
        derivation_path: Option<DerivationPath>,
        word_length: Option<String>,
    ) -> Result<(SuiAddress, String, SignatureScheme), anyhow::Error> {
        let (address, kp, scheme, phrase) =
            generate_new_key(key_scheme, derivation_path, word_length)?;
        self.add_key(alias, kp)?;
        Ok((address, phrase, scheme))
    }

    fn import_from_mnemonic(
        &mut self,
        phrase: &str,
        key_scheme: SignatureScheme,
        derivation_path: Option<DerivationPath>,
        alias: Option<String>,
    ) -> Result<SuiAddress, anyhow::Error> {
        let mnemonic = Mnemonic::from_phrase(phrase, Language::English)
            .map_err(|e| anyhow::anyhow!("Invalid mnemonic phrase: {:?}", e))?;
        let seed = Seed::new(&mnemonic, "");
        match derive_key_pair_from_path(seed.as_bytes(), derivation_path, &key_scheme) {
            Ok((address, kp)) => {
                self.add_key(alias, kp)?;
                Ok(address)
            }
            Err(e) => Err(anyhow!("error getting keypair {:?}", e)),
        }
    }
}

impl Display for Keystore {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut writer = String::new();
        match self {
            Keystore::File(file) => {
                writeln!(writer, "Keystore Type : File")?;
                write!(writer, "Keystore Path : {:?}", file.path)?;
                write!(f, "{}", writer)
            }
            Keystore::InMem(_) => {
                writeln!(writer, "Keystore Type : InMem")?;
                write!(f, "{}", writer)
            }
            Keystore::Encrypted(encrypted) => {
                writeln!(writer, "Keystore Type : Encrypted")?;
                write!(writer, "Keystore Path : {:?}", encrypted.path)?;
                write!(f, "{}", writer)
            }
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Alias {
    pub alias: String,
    pub public_key_base64: String,
}

#[derive(Default)]
pub struct FileBasedKeystore {
    keys: BTreeMap<SuiAddress, SuiKeyPair>,
    aliases: BTreeMap<SuiAddress, Alias>,
    path: Option<PathBuf>,
}

impl Serialize for FileBasedKeystore {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(
            self.path
                .as_ref()
                .unwrap_or(&PathBuf::default())
                .to_str()
                .unwrap_or(""),
        )
    }
}

impl<'de> Deserialize<'de> for FileBasedKeystore {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        FileBasedKeystore::new(&PathBuf::from(String::deserialize(deserializer)?))
            .map_err(D::Error::custom)
    }
}

impl AccountKeystore for FileBasedKeystore {
    fn sign_hashed(&self, address: &SuiAddress, msg: &[u8]) -> Result<Signature, signature::Error> {
        Ok(Signature::new_hashed(
            msg,
            self.keys.get(address).ok_or_else(|| {
                signature::Error::from_source(format!("Cannot find key for address: [{address}]"))
            })?,
        ))
    }
    fn sign_secure<T>(
        &self,
        address: &SuiAddress,
        msg: &T,
        intent: Intent,
    ) -> Result<Signature, signature::Error>
    where
        T: Serialize,
    {
        Ok(Signature::new_secure(
            &IntentMessage::new(intent, msg),
            self.keys.get(address).ok_or_else(|| {
                signature::Error::from_source(format!("Cannot find key for address: [{address}]"))
            })?,
        ))
    }

    fn add_key(&mut self, alias: Option<String>, keypair: SuiKeyPair) -> Result<(), anyhow::Error> {
        let address: SuiAddress = (&keypair.public()).into();
        let alias = self.create_alias(alias)?;
        self.aliases.insert(
            address,
            Alias {
                alias,
                public_key_base64: keypair.public().encode_base64(),
            },
        );
        self.keys.insert(address, keypair);
        self.save()?;
        Ok(())
    }

    /// Return an array of `Alias`, consisting of every alias and its corresponding public key.
    fn aliases(&self) -> Vec<&Alias> {
        self.aliases.values().collect()
    }

    fn addresses_with_alias(&self) -> Vec<(&SuiAddress, &Alias)> {
        self.aliases.iter().collect::<Vec<_>>()
    }

    /// Return an array of `Alias`, consisting of every alias and its corresponding public key.
    fn aliases_mut(&mut self) -> Vec<&mut Alias> {
        self.aliases.values_mut().collect()
    }

    fn keys(&self) -> Vec<PublicKey> {
        self.keys.values().map(|key| key.public()).collect()
    }

    /// This function returns an error if the provided alias already exists. If the alias
    /// has not already been used, then it returns the alias.
    /// If no alias has been passed, it will generate a new alias.
    fn create_alias(&self, alias: Option<String>) -> Result<String, anyhow::Error> {
        match alias {
            Some(a) if self.alias_exists(&a) => {
                bail!("Alias {a} already exists. Please choose another alias.")
            }
            Some(a) => validate_alias(&a),
            None => Ok(random_name(
                &self
                    .alias_names()
                    .into_iter()
                    .map(|x| x.to_string())
                    .collect::<HashSet<_>>(),
            )),
        }
    }

    /// Get the address by its alias
    fn get_address_by_alias(&self, alias: String) -> Result<&SuiAddress, anyhow::Error> {
        self.addresses_with_alias()
            .iter()
            .find(|x| x.1.alias == alias)
            .ok_or_else(|| anyhow!("Cannot resolve alias {alias} to an address"))
            .map(|x| x.0)
    }

    /// Get the alias if it exists, or return an error if it does not exist.
    fn get_alias_by_address(&self, address: &SuiAddress) -> Result<String, anyhow::Error> {
        match self.aliases.get(address) {
            Some(alias) => Ok(alias.alias.clone()),
            None => bail!("Cannot find alias for address {address}"),
        }
    }

    fn get_key(&self, address: &SuiAddress) -> Result<&SuiKeyPair, anyhow::Error> {
        match self.keys.get(address) {
            Some(key) => Ok(key),
            None => Err(anyhow!("Cannot find key for address: [{address}]")),
        }
    }

    /// Updates an old alias to the new alias and saves it to the alias file.
    /// If the new_alias is None, it will generate a new random alias.
    fn update_alias(
        &mut self,
        old_alias: &str,
        new_alias: Option<&str>,
    ) -> Result<String, anyhow::Error> {
        // Step 1: Find address
        let addr_opt = {
            let mut addr = None;
            for (address, alias) in &self.aliases {
                if alias.alias == old_alias {
                    addr = Some(*address);
                    break;
                }
            }
            addr
        };
        
        let address = match addr_opt {
            Some(address) => address,
            None => bail!("Cannot find an address for alias {old_alias}"),
        };
        
        // Step 2: Set new alias
        let new_alias_name = match new_alias {
            Some(a) if self.alias_exists(a) && a != old_alias => {
                bail!("Alias {a} already exists. Please choose another alias.")
            }
            Some(a) => validate_alias(a)?,
            None => random_name(
                &self
                    .alias_names()
                    .into_iter()
                    .map(|x| x.to_string())
                    .collect::<HashSet<_>>(),
            ),
        };
        
        // Step 3: Update
        if let Some(alias_struct) = self.aliases.get_mut(&address) {
            alias_struct.alias = new_alias_name.clone();
        } else {
            bail!("Cannot find an alias for address {address}");
        }
        
        self.save_aliases()?;
        Ok(new_alias_name)
    }
}

impl FileBasedKeystore {
    pub fn new(path: &PathBuf) -> Result<Self, anyhow::Error> {
        let keys = if path.exists() {
            let reader =
                BufReader::new(File::open(path).with_context(|| {
                    format!("Cannot open the keystore file: {}", path.display())
                })?);
            let kp_strings: Vec<String> = serde_json::from_reader(reader).with_context(|| {
                format!("Cannot deserialize the keystore file: {}", path.display(),)
            })?;
            kp_strings
                .iter()
                .map(|kpstr| {
                    let key = SuiKeyPair::decode_base64(kpstr);
                    key.map(|k| (SuiAddress::from(&k.public()), k))
                })
                .collect::<Result<BTreeMap<_, _>, _>>()
                .map_err(|e| anyhow!("Invalid keystore file: {}. {}", path.display(), e))?
        } else {
            BTreeMap::new()
        };

        // check aliases
        let mut aliases_path = path.clone();
        aliases_path.set_extension("aliases");

        let aliases = if aliases_path.exists() {
            let file = File::open(&aliases_path).with_context(|| {
                format!(
                    "Cannot open alias file at path: {}",
                    aliases_path.display()
                )
            })?;
            
            let reader = BufReader::new(file);
            let alias_vec: Vec<Alias> = serde_json::from_reader(reader).with_context(|| {
                format!(
                    "Cannot deserialize aliases from file: {}",
                    aliases_path.display()
                )
            })?;

            // Convert alias information to BTreeMap
            let mut aliases_map = BTreeMap::new();
            for alias in alias_vec {
                if let Ok(public_key) = PublicKey::decode_base64(&alias.public_key_base64) {
                    let address: SuiAddress = (&public_key).into();
                    aliases_map.insert(address, alias);
                }
            }
            aliases_map
        } else if keys.is_empty() {
            BTreeMap::new()
        } else {
            let names: Vec<String> = random_names(HashSet::new(), keys.len());
            let mut aliases_map = BTreeMap::new();
            for ((sui_address, skp), alias) in keys.iter().zip(names) {
                let public_key_base64 = skp.public().encode_base64();
                aliases_map.insert(
                    *sui_address,
                    Alias {
                        alias,
                        public_key_base64,
                    },
                );
            }
            let aliases_store = serde_json::to_string_pretty(&aliases_map.values().collect::<Vec<_>>())
                .with_context(|| {
                    format!(
                        "Cannot serialize aliases to file in keystore: {}",
                        aliases_path.display()
                    )
                })?;
            fs::write(aliases_path, aliases_store)?;
            aliases_map
        };

        Ok(Self {
            keys,
            aliases,
            path: Some(path.to_path_buf()),
        })
    }

    pub fn set_path(&mut self, path: &Path) {
        self.path = Some(path.to_path_buf());
    }

    pub fn save_aliases(&self) -> Result<(), anyhow::Error> {
        if let Some(path) = &self.path {
            let aliases_store =
                serde_json::to_string_pretty(&self.aliases.values().collect::<Vec<_>>())
                    .with_context(|| {
                        format!(
                            "Cannot serialize aliases to file in keystore: {}",
                            path.display()
                        )
                    })?;

            let mut aliases_path = path.clone();
            aliases_path.set_extension("aliases");
            fs::write(aliases_path, aliases_store)?
        }
        Ok(())
    }

    /// Keys saved as Base64 with 33 bytes `flag || privkey` ($BASE64_STR).
    /// To see Bech32 format encoding, use `sui keytool export $SUI_ADDRESS` where
    /// $SUI_ADDRESS can be found with `sui keytool list`. Or use `sui keytool convert $BASE64_STR`
    pub fn save_keystore(&self) -> Result<(), anyhow::Error> {
        if let Some(path) = &self.path {
            let store = serde_json::to_string_pretty(
                &self
                    .keys
                    .values()
                    .map(|k| k.encode_base64())
                    .collect::<Vec<_>>(),
            )
            .with_context(|| format!("Cannot serialize keystore to file: {}", path.display()))?;
            fs::write(path, store)?;
        }
        Ok(())
    }

    pub fn save(&self) -> Result<(), anyhow::Error> {
        self.save_aliases()?;
        self.save_keystore()?;
        Ok(())
    }

    pub fn key_pairs(&self) -> Vec<&SuiKeyPair> {
        self.keys.values().collect()
    }
}

#[derive(Default, Serialize, Deserialize)]
pub struct InMemKeystore {
    aliases: BTreeMap<SuiAddress, Alias>,
    keys: BTreeMap<SuiAddress, SuiKeyPair>,
}

impl AccountKeystore for InMemKeystore {
    fn sign_hashed(&self, address: &SuiAddress, msg: &[u8]) -> Result<Signature, signature::Error> {
        Ok(Signature::new_hashed(
            msg,
            self.keys.get(address).ok_or_else(|| {
                signature::Error::from_source(format!("Cannot find key for address: [{address}]"))
            })?,
        ))
    }
    fn sign_secure<T>(
        &self,
        address: &SuiAddress,
        msg: &T,
        intent: Intent,
    ) -> Result<Signature, signature::Error>
    where
        T: Serialize,
    {
        Ok(Signature::new_secure(
            &IntentMessage::new(intent, msg),
            self.keys.get(address).ok_or_else(|| {
                signature::Error::from_source(format!("Cannot find key for address: [{address}]"))
            })?,
        ))
    }

    fn add_key(&mut self, alias: Option<String>, keypair: SuiKeyPair) -> Result<(), anyhow::Error> {
        let address: SuiAddress = (&keypair.public()).into();
        let alias = alias.unwrap_or_else(|| {
            random_name(
                &self
                    .aliases()
                    .iter()
                    .map(|x| x.alias.clone())
                    .collect::<HashSet<_>>(),
            )
        });

        let public_key_base64 = keypair.public().encode_base64();
        let alias = Alias {
            alias,
            public_key_base64,
        };
        self.aliases.insert(address, alias);
        self.keys.insert(address, keypair);
        Ok(())
    }

    /// Get all aliases objects
    fn aliases(&self) -> Vec<&Alias> {
        self.aliases.values().collect()
    }

    fn addresses_with_alias(&self) -> Vec<(&SuiAddress, &Alias)> {
        self.aliases.iter().collect::<Vec<_>>()
    }

    fn keys(&self) -> Vec<PublicKey> {
        self.keys.values().map(|key| key.public()).collect()
    }

    fn get_key(&self, address: &SuiAddress) -> Result<&SuiKeyPair, anyhow::Error> {
        match self.keys.get(address) {
            Some(key) => Ok(key),
            None => Err(anyhow!("Cannot find key for address: [{address}]")),
        }
    }

    /// Get alias of address
    fn get_alias_by_address(&self, address: &SuiAddress) -> Result<String, anyhow::Error> {
        match self.aliases.get(address) {
            Some(alias) => Ok(alias.alias.clone()),
            None => bail!("Cannot find alias for address {address}"),
        }
    }

    /// Get the address by its alias
    fn get_address_by_alias(&self, alias: String) -> Result<&SuiAddress, anyhow::Error> {
        self.addresses_with_alias()
            .iter()
            .find(|x| x.1.alias == alias)
            .ok_or_else(|| anyhow!("Cannot resolve alias {alias} to an address"))
            .map(|x| x.0)
    }

    /// This function returns an error if the provided alias already exists. If the alias
    /// has not already been used, then it returns the alias.
    /// If no alias has been passed, it will generate a new alias.
    fn create_alias(&self, alias: Option<String>) -> Result<String, anyhow::Error> {
        match alias {
            Some(a) if self.alias_exists(&a) => {
                bail!("Alias {a} already exists. Please choose another alias.")
            }
            Some(a) => validate_alias(&a),
            None => Ok(random_name(
                &self
                    .alias_names()
                    .into_iter()
                    .map(|x| x.to_string())
                    .collect::<HashSet<_>>(),
            )),
        }
    }

    fn aliases_mut(&mut self) -> Vec<&mut Alias> {
        self.aliases.values_mut().collect()
    }

    /// Updates an old alias to the new alias. If the new_alias is None,
    /// it will generate a new random alias.
    fn update_alias(
        &mut self,
        old_alias: &str,
        new_alias: Option<&str>,
    ) -> Result<String, anyhow::Error> {
        self.update_alias_value(old_alias, new_alias)
    }
}

impl InMemKeystore {
    pub fn new_insecure_for_tests(initial_key_number: usize) -> Self {
        let mut rng = StdRng::from_seed([0; 32]);
        let keys = (0..initial_key_number)
            .map(|_| get_key_pair_from_rng(&mut rng))
            .map(|(ad, k)| (ad, SuiKeyPair::Ed25519(k)))
            .collect::<BTreeMap<SuiAddress, SuiKeyPair>>();

        let aliases = keys
            .iter()
            .zip(random_names(HashSet::new(), keys.len()))
            .map(|((sui_address, skp), alias)| {
                let public_key_base64 = skp.public().encode_base64();
                (
                    *sui_address,
                    Alias {
                        alias,
                        public_key_base64,
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();

        Self { aliases, keys }
    }
}

fn validate_alias(alias: &str) -> Result<String, anyhow::Error> {
    let re = Regex::new(r"^[A-Za-z][A-Za-z0-9-_\.]*$")
        .map_err(|_| anyhow!("Cannot build the regex needed to validate the alias naming"))?;
    let alias = alias.trim();
    ensure!(
        re.is_match(alias),
        "Invalid alias. A valid alias must start with a letter and can contain only letters, digits, hyphens (-), dots (.), or underscores (_)."
    );
    Ok(alias.to_string())
}

#[cfg(test)]
mod tests {
    use crate::keystore::validate_alias;

    #[test]
    fn validate_alias_test() {
        // OK
        assert!(validate_alias("A.B_dash").is_ok());
        assert!(validate_alias("A.B-C1_dash").is_ok());
        assert!(validate_alias("abc_123.sui").is_ok());
        // Not allowed
        assert!(validate_alias("A.B-C_dash!").is_err());
        assert!(validate_alias(".B-C_dash!").is_err());
        assert!(validate_alias("_test").is_err());
        assert!(validate_alias("123").is_err());
        assert!(validate_alias("@@123").is_err());
        assert!(validate_alias("@_Ab").is_err());
        assert!(validate_alias("_Ab").is_err());
        assert!(validate_alias("^A").is_err());
        assert!(validate_alias("-A").is_err());
    }
}

/// Structure defining the file format of the encrypted keystore
#[derive(Serialize, Deserialize)]
pub struct EncryptedKeyData {
    /// Encryption version (for future version upgrades)
    pub version: u8,
    /// Encrypted key data (Base64 encoded)
    pub encrypted_data: String,
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

/// Encrypted file based keystore implementation
#[derive(Default, Serialize, Deserialize)]
pub struct EncryptedFileBasedKeystore {
    keys: BTreeMap<SuiAddress, SuiKeyPair>,
    aliases: BTreeMap<SuiAddress, Alias>,
    path: Option<PathBuf>,
    /// Whether to keep decrypted keys in memory
    #[serde(default)]
    keep_in_memory: bool,
}

impl EncryptedFileBasedKeystore {
    /// Create a new encrypted keystore
    pub fn new(path: &PathBuf, password: &str, keep_in_memory: bool) -> Result<Self, anyhow::Error> {
        let mut keystore = Self {
            keys: BTreeMap::new(),
            aliases: BTreeMap::new(),
            path: Some(path.to_path_buf()),
            keep_in_memory,
        };
        
        // Load keystore from file system
        if let Some(path) = &keystore.path {
            let key_dir = path.parent().ok_or_else(|| anyhow!("Invalid keystore path"))?;
            if !key_dir.exists() {
                fs::create_dir_all(key_dir)?;
            }
            
            // Check if there are already encrypted key files and load
            if key_dir.exists() && key_dir.is_dir() {
                for entry in fs::read_dir(key_dir)? {
                    let entry = entry?;
                    let file_path = entry.path();
                    
                    // Only process files with .encrypted extension
                    if file_path.extension().map_or(false, |ext| ext == "encrypted") {
                        let (address, keypair) = keystore.load_and_decrypt_key(&file_path, password)
                            .with_context(|| format!("Failed to decrypt key file: {}", file_path.display()))?;
                            
                        // If memory storage option is turned on, store decrypted key in memory
                        if keystore.keep_in_memory {
                            keystore.keys.insert(address, keypair);
                        }
                    }
                }
            }

            // Try to load alias file
            let mut aliases_path = path.clone();
            aliases_path.set_extension("aliases");
            
            if aliases_path.exists() {
                let file = File::open(&aliases_path).with_context(|| {
                    format!(
                        "Cannot open alias file at path: {}",
                        aliases_path.display()
                    )
                })?;
                
                let reader = BufReader::new(file);
                let alias_vec: Vec<Alias> = serde_json::from_reader(reader).with_context(|| {
                    format!(
                        "Cannot deserialize aliases from file: {}",
                        aliases_path.display()
                    )
                })?;

                // Get alias information
                for alias in alias_vec {
                    if let Ok(public_key) = PublicKey::decode_base64(&alias.public_key_base64) {
                        let address: SuiAddress = (&public_key).into();
                        keystore.aliases.insert(address, alias);
                    }
                }
            }
        }
        
        Ok(keystore)
    }

    /// Encrypt and save key pair with password
    pub fn encrypt_and_save_keypair(&self, keypair: &SuiKeyPair, password: &str) -> Result<(), anyhow::Error> {
        let address: SuiAddress = (&keypair.public()).into();
        
        // Check directory path and create if it doesn't exist
        if let Some(path) = &self.path {
            let key_dir = path.parent().ok_or_else(|| anyhow!("Invalid keystore path"))?;
            if !key_dir.exists() {
                fs::create_dir_all(key_dir)?;
            }
            
            // Create key file path
            let mut key_path = key_dir.to_path_buf();
            key_path.push(format!("{}.encrypted", address));
            
            // Generate encryption parameters
            let mut salt = [0u8; 16];
            OsRng.fill_bytes(&mut salt);
            
            let mut iv = [0u8; NONCE_LEN];
            OsRng.fill_bytes(&mut iv);
            
            // Derive encryption key from password
            const ITERATIONS: u32 = 100_000; // Enough iterations
            let iterations = NonZeroU32::new(ITERATIONS).unwrap();
            
            let mut derived_key = [0u8; 32]; // AES-256 key size
            pbkdf2::derive(
                pbkdf2::PBKDF2_HMAC_SHA256, 
                iterations, 
                &salt, 
                password.as_bytes(), 
                &mut derived_key
            );
            
            // Serialize key pair
            let serialized_keypair = keypair.encode_base64();
            
            // Encrypt
            let unbound_key = UnboundKey::new(&aead::AES_256_GCM, &derived_key)
                .map_err(|_| anyhow!("Failed to create encryption key"))?;
            let less_safe_key = LessSafeKey::new(unbound_key);
            
            let nonce = Nonce::assume_unique_for_key(iv);
            let aad = Aad::empty(); // No additional authentication data
            
            let mut serialized_data = serialized_keypair.as_bytes().to_vec();
            less_safe_key
                .seal_in_place_append_tag(nonce, aad, &mut serialized_data)
                .map_err(|_| anyhow!("Encryption failed"))?;
            
            // Create encrypted data structure
            let encrypted_data = EncryptedKeyData {
                version: 1,
                encrypted_data: BASE64.encode(&serialized_data),
                iv: BASE64.encode(&iv),
                salt: BASE64.encode(&salt),
                cipher: "aes-256-gcm".to_string(),
                iterations: ITERATIONS,
                address: address.to_string(),
                ciphertext: BASE64.encode(&serialized_data),
            };
            
            // Serialize to JSON and save to file
            let json = serde_json::to_string_pretty(&encrypted_data)?;
            fs::write(key_path, json)?;
            
            Ok(())
        } else {
            Err(anyhow!("Keystore path is not set"))
        }
    }
    
    /// Decrypt encrypted key file with password
    fn load_and_decrypt_key(&self, key_path: &Path, password: &str) -> Result<(SuiAddress, SuiKeyPair), anyhow::Error> {
        // Read encrypted data from file
        let json = fs::read_to_string(key_path)?;
        let encrypted_data: EncryptedKeyData = serde_json::from_str(&json)?;
        
        // Only version 1 is supported
        if encrypted_data.version != 1 {
            return Err(anyhow!("Unsupported encryption version: {}", encrypted_data.version));
        }
        
        // Only aes-256-gcm is supported
        if encrypted_data.cipher != "aes-256-gcm" {
            return Err(anyhow!("Unsupported cipher: {}", encrypted_data.cipher));
        }
        
        // Base64 decode
        let ciphertext = BASE64.decode(&encrypted_data.ciphertext)?;
        let iv = BASE64.decode(&encrypted_data.iv)?;
        let salt = BASE64.decode(&encrypted_data.salt)?;
        
        if iv.len() != NONCE_LEN {
            return Err(anyhow!("Invalid IV length"));
        }
        
        // Derive encryption key from password
        let iterations = NonZeroU32::new(encrypted_data.iterations)
            .ok_or_else(|| anyhow!("Invalid iteration count"))?;
        
        let mut derived_key = [0u8; 32];
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256, 
            iterations, 
            &salt, 
            password.as_bytes(), 
            &mut derived_key
        );
        
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
        
        // Restore key pair
        let plaintext_str = std::str::from_utf8(plaintext)?;
        let keypair = SuiKeyPair::decode_base64(plaintext_str)?;
        
        // Address verification
        let address: SuiAddress = (&keypair.public()).into();
        let expected_address = parse_sui_address(&encrypted_data.address)?;
        
        if address != expected_address {
            return Err(anyhow!("Address mismatch after decryption"));
        }
        
        Ok((address, keypair))
    }
    
    /// Add key to keystore (encrypt and save)
    pub fn add_key_with_password(
        &mut self, 
        alias: Option<String>, 
        keypair: SuiKeyPair, 
        password: &str
    ) -> Result<(), anyhow::Error> {
        let address: SuiAddress = (&keypair.public()).into();
        let alias = self.create_alias(alias)?;
        
        // Save alias information
        self.aliases.insert(
            address,
            Alias {
                alias,
                public_key_base64: keypair.public().encode_base64(),
            },
        );
        
        // Encrypt and save to file
        self.encrypt_and_save_keypair(&keypair, password)?;
        
        // Optionally store key in memory
        if self.keep_in_memory {
            self.keys.insert(address, keypair);
        }
        
        // Save alias file
        self.save_aliases()?;
        
        Ok(())
    }
    
    /// Decrypt key with password and load it into memory for reference
    pub fn get_key_with_password(
        &mut self, 
        address: &SuiAddress, 
        password: &str
    ) -> Result<(), anyhow::Error> {
        // Success if already in memory
        if self.keys.contains_key(address) {
            return Ok(());
        }
        
        // If not in memory, decrypt from file
        if let Some(path) = &self.path {
            let key_dir = path.parent().ok_or_else(|| anyhow!("Invalid keystore path"))?;
            let key_path = key_dir.join(format!("{}.encrypted", address));
            
            if key_path.exists() {
                let (_, keypair) = self.load_and_decrypt_key(&key_path, password)?;
                
                // Store in memory
                self.keys.insert(*address, keypair);
                Ok(())
            } else {
                Err(anyhow!("Key file not found for address: {}", address))
            }
        } else {
            Err(anyhow!("Keystore path is not set"))
        }
    }
    
    /// Remove all keys from memory (for security)
    pub fn clear_all_keys(&mut self) -> Result<(), anyhow::Error> {
        self.keys.clear();
        Ok(())
    }
    
    /// Permanently remove all keys (delete files)
    pub fn delete_all_keys(&mut self) -> Result<(), anyhow::Error> {
        // Remove keys from memory
        self.keys.clear();
        self.aliases.clear();
        
        // Remove keys from file system
        if let Some(path) = &self.path {
            let key_dir = path.parent().ok_or_else(|| anyhow!("Invalid keystore path"))?;
            if key_dir.exists() && key_dir.is_dir() {
                for entry in fs::read_dir(key_dir)? {
                    let entry = entry?;
                    let file_path = entry.path();
                    if file_path.extension().map_or(false, |ext| ext == "encrypted") {
                        fs::remove_file(file_path)?;
                    }
                }
            }
            
            // Remove alias file
            let mut aliases_path = path.clone();
            aliases_path.set_extension("aliases");
            if aliases_path.exists() {
                fs::remove_file(aliases_path)?;
            }
        }
        
        Ok(())
    }
    
    /// Set memory storage option
    pub fn set_keep_in_memory(&mut self, keep_in_memory: bool) {
        self.keep_in_memory = keep_in_memory;
        
        // If option is turned off, remove keys from memory
        if !keep_in_memory {
            self.keys.clear();
        }
    }
    
    // FileBasedKeystore methods
    pub fn set_path(&mut self, path: &Path) {
        self.path = Some(path.to_path_buf());
    }

    pub fn save_aliases(&self) -> Result<(), anyhow::Error> {
        if let Some(path) = &self.path {
            let aliases_store =
                serde_json::to_string_pretty(&self.aliases.values().collect::<Vec<_>>())
                    .with_context(|| {
                        format!(
                            "Cannot serialize aliases to file in keystore: {}",
                            path.display()
                        )
                    })?;

            let mut aliases_path = path.clone();
            aliases_path.set_extension("aliases");
            fs::write(aliases_path, aliases_store)?
        }
        Ok(())
    }

    /// Import key from mnemonic and add to encrypted keystore
    pub fn import_from_mnemonic(
        &mut self, 
        mnemonic: &str,
        key_scheme: Option<SignatureScheme>,
        derivation_path: Option<DerivationPath>,
        alias: Option<String>,
        password: &str,
    ) -> Result<SuiAddress, anyhow::Error> {
        // Generate mnemonic
        let m = Mnemonic::from_phrase(mnemonic, Language::English)
            .map_err(|e| anyhow!("Invalid mnemonic phrase: {}", e))?;
        
        // Generate seed
        let seed = Seed::new(&m, "");
        
        // Derive key pair
        let scheme = key_scheme.unwrap_or(SignatureScheme::ED25519);
        let (address, keypair) = derive_key_pair_from_path(
            seed.as_bytes(), 
            derivation_path,
            &scheme
        )?;
        
        // Add to keystore
        self.add_key_with_password(alias, keypair, password)?;
        
        Ok(address)
    }

    /// Convenience function for signing
    /// Sign transaction data and return signature information
    pub fn secure_sign(
        &mut self, 
        address: &SuiAddress, 
        data: &str, 
        password: &str,
        intent: Option<Intent>
    ) -> Result<SecureSignData, anyhow::Error> {
        // Load key into memory (decrypt with password)
        self.get_key_with_password(address, password)?;
        
        // Set intent
        let intent = intent.unwrap_or_else(Intent::sui_transaction);
        let intent_clone = intent.clone();
        
        // Decode transaction data
        let msg: TransactionData = bcs::from_bytes(&BASE64.decode(data)
            .map_err(|e| anyhow!("Cannot deserialize transaction data: {:?}", e))?)?;
        
        // Generate intent message
        let intent_msg = IntentMessage::new(intent, msg);
        let raw_intent_msg = BASE64.encode(bcs::to_bytes(&intent_msg)?);
        
        // Calculate hash
        let mut hasher = DefaultHash::default();
        hasher.update(bcs::to_bytes(&intent_msg)?);
        let digest = hasher.finalize().digest;
        
        // Sign
        let sui_signature = self.sign_secure(
            address, 
            &intent_msg.value, 
            intent_msg.intent
        )?;
        
        // Create signed transaction
        let signed_tx = Transaction::from_data(
            intent_msg.value, 
            vec![sui_signature.clone()]
        );
        let signed_tx_bytes = bcs::to_bytes(&signed_tx)?;
        let signed_tx_base64 = BASE64.encode(signed_tx_bytes);
        
        // Optionally remove key from memory after signing
        // self.clear_all_keys()?;
        
        // Return result
        Ok(SecureSignData {
            sui_address: *address,
            raw_tx_data: data.to_owned(),
            intent: intent_clone,
            raw_intent_msg,
            digest: BASE64.encode(digest),
            sui_signature: sui_signature.encode_base64(),
            signed_transaction: signed_tx_base64,
        })
    }
}

// AccountKeystore trait implementation
impl AccountKeystore for EncryptedFileBasedKeystore {
    fn sign_hashed(&self, address: &SuiAddress, msg: &[u8]) -> Result<Signature, signature::Error> {
        // This implementation can only use keys in memory.
        // For actual use, a prompt for entering the password is needed.
        if let Some(key) = self.keys.get(address) {
            Ok(Signature::new_hashed(msg, key))
        } else {
            Err(signature::Error::from_source(format!("Cannot find key for address: [{address}] - Please use get_key_with_password first")))
        }
    }
    
    fn sign_secure<T>(
        &self,
        address: &SuiAddress,
        msg: &T,
        intent: Intent,
    ) -> Result<Signature, signature::Error>
    where
        T: Serialize,
    {
        // This implementation can only use keys in memory.
        if let Some(key) = self.keys.get(address) {
            Ok(Signature::new_secure(&IntentMessage::new(intent, msg), key))
        } else {
            Err(signature::Error::from_source(format!("Cannot find key for address: [{address}] - Please use get_key_with_password first")))
        }
    }

    fn add_key(&mut self, _alias: Option<String>, _keypair: SuiKeyPair) -> Result<(), anyhow::Error> {
        // This method cannot be used without a password
        Err(anyhow!("For EncryptedFileBasedKeystore, use add_key_with_password instead"))
    }

    fn keys(&self) -> Vec<PublicKey> {
        // Return public keys from memory + public keys from encrypted storage in keystore
        let mut result: Vec<PublicKey> = self.keys.values().map(|key| key.public()).collect();
        
        // Add alias public keys (include keys not in memory)
        for alias in self.aliases.values() {
            if let Ok(pubkey) = PublicKey::decode_base64(&alias.public_key_base64) {
                if !result.iter().any(|k| k == &pubkey) {
                    result.push(pubkey);
                }
            }
        }
        
        result
    }

    fn get_key(&self, address: &SuiAddress) -> Result<&SuiKeyPair, anyhow::Error> {
        // This implementation can only return keys in memory.
        match self.keys.get(address) {
            Some(key) => Ok(key),
            None => Err(anyhow!("Key not found in memory. Use get_key_with_password to load it from encrypted storage.")),
        }
    }

    fn aliases(&self) -> Vec<&Alias> {
        self.aliases.values().collect()
    }

    fn addresses_with_alias(&self) -> Vec<(&SuiAddress, &Alias)> {
        self.aliases.iter().collect::<Vec<_>>()
    }

    fn aliases_mut(&mut self) -> Vec<&mut Alias> {
        self.aliases.values_mut().collect()
    }

    fn get_alias_by_address(&self, address: &SuiAddress) -> Result<String, anyhow::Error> {
        match self.aliases.get(address) {
            Some(alias) => Ok(alias.alias.clone()),
            None => bail!("Cannot find alias for address {address}"),
        }
    }

    fn get_address_by_alias(&self, alias: String) -> Result<&SuiAddress, anyhow::Error> {
        self.addresses_with_alias()
            .iter()
            .find(|x| x.1.alias == alias)
            .ok_or_else(|| anyhow!("Cannot resolve alias {alias} to an address"))
            .map(|x| x.0)
    }

    fn create_alias(&self, alias: Option<String>) -> Result<String, anyhow::Error> {
        match alias {
            Some(a) if self.alias_exists(&a) => {
                bail!("Alias {a} already exists. Please choose another alias.")
            }
            Some(a) => validate_alias(&a),
            None => Ok(random_name(
                &self
                    .alias_names()
                    .into_iter()
                    .map(|x| x.to_string())
                    .collect::<HashSet<_>>(),
            )),
        }
    }

    fn update_alias(
        &mut self,
        old_alias: &str,
        new_alias: Option<&str>,
    ) -> Result<String, anyhow::Error> {
        let new_alias_name = self.update_alias_value(old_alias, new_alias)?;
        self.save_aliases()?;
        Ok(new_alias_name)
    }
}

// Helper function to parse SuiAddress from string
fn parse_sui_address(s: &str) -> Result<SuiAddress, anyhow::Error> {
    // Check if string starts with 0x
    let s = if s.starts_with("0x") { &s[2..] } else { s };
    
    // Convert hex string to byte array
    let bytes = hex::decode(s)
        .map_err(|e| anyhow!("Invalid hex string for SuiAddress: {}", e))?;
    
    // Create SuiAddress
    SuiAddress::try_from(bytes.as_slice())
        .map_err(|e| anyhow!("Failed to convert bytes to SuiAddress: {}", e))
}

// Helper function to parse a private key string to SuiKeyPair
pub fn keypair_from_str(s: &str) -> Result<SuiKeyPair, anyhow::Error> {
    // Bech32 decoding support etc. This function needs to be implemented for actual use.
    // For now, assume Base64 encoded key
    if s.starts_with("suiprivkey") {
        // TODO: Implement Bech32
        return Err(anyhow!("Bech32 format not implemented yet"));
    }
    
    // Assume Base64 encoded key
    SuiKeyPair::decode_base64(s)
        .map_err(|e| anyhow!("Failed to decode private key: {}", e))
}
