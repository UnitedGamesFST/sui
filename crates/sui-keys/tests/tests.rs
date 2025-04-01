// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::str::FromStr;

use fastcrypto::hash::HashFunction;
use fastcrypto::traits::EncodeDecodeBase64;
use sui_keys::key_derive::generate_new_key;
use tempfile::TempDir;

use sui_keys::keystore::{AccountKeystore, FileBasedKeystore, InMemKeystore, Keystore};
use sui_types::crypto::{DefaultHash, SignatureScheme, SuiKeyPair, SuiSignatureInner, Signature};
use sui_types::{
    base_types::{SuiAddress, SUI_ADDRESS_LENGTH},
    crypto::Ed25519SuiSignature,
};

// Encrypted keystore tests
use rand::rngs::StdRng;
use rand::SeedableRng;
use sui_keys::encrypted_keystore::{
    AccountEncryptedKeystore, EncryptedKeystore, EncryptedFileBasedKeystore, 
    create_encrypted_key, decrypt_key_pair, sign_encrypted,
};
use shared_crypto::intent::{Intent, IntentMessage};
use sui_types::crypto::get_key_pair_from_rng;

#[test]
fn alias_exists_test() {
    let temp_dir = TempDir::new().unwrap();
    let keystore_path = temp_dir.path().join("sui.keystore");
    let mut keystore = Keystore::from(FileBasedKeystore::new(&keystore_path).unwrap());
    keystore
        .generate_and_add_new_key(
            SignatureScheme::ED25519,
            Some("my_alias_test".to_string()),
            None,
            None,
        )
        .unwrap();
    let aliases = keystore.alias_names();
    assert_eq!(1, aliases.len());
    assert_eq!(vec!["my_alias_test"], aliases);
    assert!(!aliases.contains(&"alias_does_not_exist"));
}

#[test]
fn create_alias_keystore_file_test() {
    let temp_dir = TempDir::new().unwrap();
    let mut keystore_path = temp_dir.path().join("sui.keystore");
    let mut keystore = Keystore::from(FileBasedKeystore::new(&keystore_path).unwrap());
    keystore
        .generate_and_add_new_key(SignatureScheme::ED25519, None, None, None)
        .unwrap();
    keystore_path.set_extension("aliases");
    assert!(keystore_path.exists());

    keystore_path = temp_dir.path().join("myfile.keystore");
    let mut keystore = Keystore::from(FileBasedKeystore::new(&keystore_path).unwrap());
    keystore
        .generate_and_add_new_key(SignatureScheme::ED25519, None, None, None)
        .unwrap();
    keystore_path.set_extension("aliases");
    assert!(keystore_path.exists());
}

#[test]
fn check_reading_aliases_file_correctly() {
    // when reading the alias file containing alias + public key base 64,
    // make sure the addresses are correctly converted back from pk

    let temp_dir = TempDir::new().unwrap();
    let mut keystore_path = temp_dir.path().join("sui.keystore");
    let keystore_path_keep = temp_dir.path().join("sui.keystore");
    let mut keystore = Keystore::from(FileBasedKeystore::new(&keystore_path).unwrap());
    let kp = keystore
        .generate_and_add_new_key(SignatureScheme::ED25519, None, None, None)
        .unwrap();
    keystore_path.set_extension("aliases");
    assert!(keystore_path.exists());

    let new_keystore = Keystore::from(FileBasedKeystore::new(&keystore_path_keep).unwrap());
    let addresses = new_keystore.addresses_with_alias();
    assert_eq!(kp.0, *addresses.first().unwrap().0)
}

#[test]
fn create_alias_if_not_exists_test() {
    let temp_dir = TempDir::new().unwrap();
    let keystore_path = temp_dir.path().join("sui.keystore");
    let mut keystore = Keystore::from(FileBasedKeystore::new(&keystore_path).unwrap());

    let alias = Some("my_alias_test".to_string());
    keystore
        .generate_and_add_new_key(SignatureScheme::ED25519, alias.clone(), None, None)
        .unwrap();

    // test error first
    let create_alias_result = keystore.create_alias(alias);
    assert!(create_alias_result.is_err());
    // test expected result
    let create_alias_result = keystore.create_alias(Some("test".to_string()));
    assert_eq!("test".to_string(), create_alias_result.unwrap());
    assert!(keystore.create_alias(Some("_test".to_string())).is_err());
    assert!(keystore.create_alias(Some("-A".to_string())).is_err());
    assert!(keystore.create_alias(Some("1A".to_string())).is_err());
    assert!(keystore.create_alias(Some("&&AA".to_string())).is_err());
}

#[test]
fn keystore_no_aliases() {
    // this tests if when calling FileBasedKeystore::new, it creates a
    // sui.aliases file with the existing address in the sui.keystore,
    // and a new alias for it.
    // This idea is to test the correct conversion
    // from the old type (which only contains keys and an optional path)
    // to the new type which contains keys and aliases (and an optional path), and if it creates the aliases file.

    let temp_dir = TempDir::new().unwrap();
    let mut keystore_path = temp_dir.path().join("sui.keystore");
    let (_, keypair, _, _) = generate_new_key(SignatureScheme::ED25519, None, None).unwrap();
    let private_keys = vec![keypair.encode_base64()];
    let keystore_data = serde_json::to_string_pretty(&private_keys).unwrap();
    fs::write(&keystore_path, keystore_data).unwrap();

    let keystore = Keystore::from(FileBasedKeystore::new(&keystore_path).unwrap());
    keystore_path.set_extension("aliases");
    assert!(keystore_path.exists());
    assert_eq!(1, keystore.aliases().len());
}

#[test]
fn update_alias_test() {
    let temp_dir = TempDir::new().unwrap();
    let keystore_path = temp_dir.path().join("sui.keystore");
    let mut keystore = Keystore::from(FileBasedKeystore::new(&keystore_path).unwrap());
    keystore
        .generate_and_add_new_key(
            SignatureScheme::ED25519,
            Some("my_alias_test".to_string()),
            None,
            None,
        )
        .unwrap();
    let aliases = keystore.alias_names();
    assert_eq!(1, aliases.len());
    assert_eq!(vec!["my_alias_test"], aliases);

    // read the alias file again and check if it was saved
    let keystore1 = Keystore::from(FileBasedKeystore::new(&keystore_path).unwrap());
    let aliases1 = keystore1.alias_names();
    assert_eq!(vec!["my_alias_test"], aliases1);

    let update = keystore.update_alias("alias_does_not_exist", None);
    assert!(update.is_err());

    let _ = keystore.update_alias("my_alias_test", Some("new_alias"));
    let aliases = keystore.alias_names();
    assert_eq!(vec!["new_alias"], aliases);

    // check that it errors on empty alias
    assert!(keystore.update_alias("new_alias", Some(" ")).is_err());
    assert!(keystore.update_alias("new_alias", Some("   ")).is_err());
    // check that alias is trimmed
    assert!(keystore.update_alias("new_alias", Some("  o ")).is_ok());
    assert_eq!(vec!["o"], keystore.alias_names());
    // check the regex works and new alias can be only [A-Za-z][A-Za-z0-9-_]*
    assert!(keystore.update_alias("o", Some("_alias")).is_err());
    assert!(keystore.update_alias("o", Some("-alias")).is_err());
    assert!(keystore.update_alias("o", Some("123")).is_err());

    let update = keystore.update_alias("o", None).unwrap();
    let aliases = keystore.alias_names();
    assert_eq!(vec![&update], aliases);

    // check that updating alias does not allow duplicates
    keystore
        .generate_and_add_new_key(
            SignatureScheme::ED25519,
            Some("my_alias_test".to_string()),
            None,
            None,
        )
        .unwrap();
    assert!(keystore
        .update_alias("my_alias_test", Some(&update))
        .is_err());
}

#[test]
fn update_alias_in_memory_test() {
    let mut keystore = Keystore::InMem(InMemKeystore::new_insecure_for_tests(0));
    keystore
        .generate_and_add_new_key(
            SignatureScheme::ED25519,
            Some("my_alias_test".to_string()),
            None,
            None,
        )
        .unwrap();
    let aliases = keystore.alias_names();
    assert_eq!(1, aliases.len());
    assert_eq!(vec!["my_alias_test"], aliases);

    let update = keystore.update_alias("alias_does_not_exist", None);
    assert!(update.is_err());

    let _ = keystore.update_alias("my_alias_test", Some("new_alias"));
    let aliases = keystore.alias_names();
    assert_eq!(vec!["new_alias"], aliases);

    let update = keystore.update_alias("new_alias", None).unwrap();
    let aliases = keystore.alias_names();
    assert_eq!(vec![&update], aliases);
}

#[test]
fn mnemonic_test() {
    let temp_dir = TempDir::new().unwrap();
    let keystore_path = temp_dir.path().join("sui.keystore");
    let mut keystore = Keystore::from(FileBasedKeystore::new(&keystore_path).unwrap());
    let (address, phrase, scheme) = keystore
        .generate_and_add_new_key(SignatureScheme::ED25519, None, None, None)
        .unwrap();

    let keystore_path_2 = temp_dir.path().join("sui2.keystore");
    let mut keystore2 = Keystore::from(FileBasedKeystore::new(&keystore_path_2).unwrap());
    let imported_address = keystore2
        .import_from_mnemonic(&phrase, SignatureScheme::ED25519, None, None)
        .unwrap();
    assert_eq!(scheme.flag(), Ed25519SuiSignature::SCHEME.flag());
    assert_eq!(address, imported_address);
}

/// This test confirms rust's implementation of mnemonic is the same with the Sui Wallet
#[test]
fn sui_wallet_address_mnemonic_test() -> Result<(), anyhow::Error> {
    let phrase = "result crisp session latin must fruit genuine question prevent start coconut brave speak student dismiss";
    let expected_address =
        SuiAddress::from_str("0x936accb491f0facaac668baaedcf4d0cfc6da1120b66f77fa6a43af718669973")?;

    let temp_dir = TempDir::new().unwrap();
    let keystore_path = temp_dir.path().join("sui.keystore");
    let mut keystore = Keystore::from(FileBasedKeystore::new(&keystore_path).unwrap());

    keystore
        .import_from_mnemonic(phrase, SignatureScheme::ED25519, None, None)
        .unwrap();

    let pubkey = keystore.keys()[0].clone();
    assert_eq!(pubkey.flag(), Ed25519SuiSignature::SCHEME.flag());

    let mut hasher = DefaultHash::default();
    hasher.update([pubkey.flag()]);
    hasher.update(pubkey);
    let g_arr = hasher.finalize();
    let mut res = [0u8; SUI_ADDRESS_LENGTH];
    res.copy_from_slice(&AsRef::<[u8]>::as_ref(&g_arr)[..SUI_ADDRESS_LENGTH]);
    let address = SuiAddress::try_from(res.as_slice())?;

    assert_eq!(expected_address, address);

    Ok(())
}

#[test]
fn keystore_display_test() -> Result<(), anyhow::Error> {
    let temp_dir = TempDir::new().unwrap();
    let keystore_path = temp_dir.path().join("sui.keystore");
    let keystore = Keystore::from(FileBasedKeystore::new(&keystore_path).unwrap());
    assert!(keystore.to_string().contains("sui.keystore"));
    assert!(!keystore.to_string().contains("keys:"));
    Ok(())
}

#[test]
fn get_alias_by_address_test() {
    let temp_dir = TempDir::new().unwrap();
    let keystore_path = temp_dir.path().join("sui.keystore");
    let mut keystore = Keystore::from(FileBasedKeystore::new(&keystore_path).unwrap());
    let alias = "my_alias_test".to_string();
    let keypair = keystore
        .generate_and_add_new_key(SignatureScheme::ED25519, Some(alias.clone()), None, None)
        .unwrap();
    assert_eq!(alias, keystore.get_alias_by_address(&keypair.0).unwrap());

    // Test getting an alias of an address that is not in keystore
    let address = generate_new_key(SignatureScheme::ED25519, None, None).unwrap();
    assert!(keystore.get_alias_by_address(&address.0).is_err())
}

#[test]
fn test_encrypt_decrypt_cycle() {
    // 테스트용 키 생성
    let mut rng = StdRng::from_seed([0; 32]);
    let (address, kp) = get_key_pair_from_rng(&mut rng);
    let sui_key_pair = SuiKeyPair::Ed25519(kp);

    // 패스워드 및 암호화
    let password = "test_password";
    let encrypted_data = create_encrypted_key(password, &sui_key_pair).unwrap();

    // 주소 확인
    let expected_address: SuiAddress = (&sui_key_pair.public()).into();
    assert_eq!(expected_address, address);
    assert_eq!(encrypted_data.address, address.to_string());

    // 복호화
    let decrypted_keypair = decrypt_key_pair(&encrypted_data, password).unwrap();
    let decrypted_address: SuiAddress = (&decrypted_keypair.public()).into();

    // 주소 일치 확인
    assert_eq!(decrypted_address, address);

    // 잘못된 패스워드로 복호화 시도
    let wrong_password = "wrong_password";
    let decryption_result = decrypt_key_pair(&encrypted_data, wrong_password);
    assert!(decryption_result.is_err());
}

#[test]
fn test_encrypted_keystore_operations() {
    // 임시 디렉토리 생성
    let temp_dir = TempDir::new().unwrap();
    let keystore_path = temp_dir.path().join("sui.encrypted.keystore");

    // 키스토어 생성
    let mut keystore = EncryptedFileBasedKeystore::new(&keystore_path).unwrap();
    
    // 테스트용 키 생성
    let password = "test_password";
    let alias = Some("test_key".to_string());
    
    // Ed25519 키페어 생성 및 추가
    let mut rng = StdRng::from_seed([1; 32]);
    let (address, kp) = get_key_pair_from_rng(&mut rng);
    let sui_key_pair = SuiKeyPair::Ed25519(kp);
    
    // 키 암호화 및 저장
    let encrypted_data = create_encrypted_key(password, &sui_key_pair).unwrap();
    keystore.add_key(alias, encrypted_data).unwrap();
    
    // 저장된 키 확인
    let stored_keys = keystore.keys();
    assert_eq!(stored_keys.len(), 1);
    
    // 저장된 주소 확인
    let stored_addresses = keystore.encrypted_addresses();
    assert_eq!(stored_addresses.len(), 1);
    assert_eq!(stored_addresses[0], address);
    
    // 별칭 확인
    let alias_name = keystore.get_alias_by_address(&address).unwrap();
    assert_eq!(alias_name, "test_key");
    
    // 파일에 저장
    keystore.save().unwrap();
    
    // 파일에서 다시 로드
    let reloaded_keystore = EncryptedFileBasedKeystore::new(&keystore_path).unwrap();
    let reloaded_keys = reloaded_keystore.keys();
    assert_eq!(reloaded_keys.len(), 1);
    
    // 로드된 키 주소 확인
    let reloaded_addresses = reloaded_keystore.encrypted_addresses();
    assert_eq!(reloaded_addresses.len(), 1);
    assert_eq!(reloaded_addresses[0], address);
}

#[test]
fn test_sign_encrypted() {
    // 테스트용 키 생성
    let mut rng = StdRng::from_seed([2; 32]);
    let (_address, kp) = get_key_pair_from_rng(&mut rng);
    let sui_key_pair = SuiKeyPair::Ed25519(kp);

    // 패스워드 및 암호화
    let password = "test_password";
    let encrypted_data = create_encrypted_key(password, &sui_key_pair).unwrap();

    // 테스트 메시지 생성
    let test_message = "test message for signing";
    
    // 메시지 해시화를 위한 직접 서명 (복호화된 키페어 사용)
    let keypair = decrypt_key_pair(&encrypted_data, password).unwrap();
    let direct_signature = Signature::new_secure(
        &IntentMessage::new(Intent::sui_transaction(), test_message),
        &keypair,
    );
    
    // 암호화된 키데이터로 서명
    let encrypted_signature = sign_encrypted(
        &encrypted_data,
        password,
        &test_message,
        Intent::sui_transaction()
    ).unwrap();
    
    // 서명 결과 비교
    assert_eq!(direct_signature.as_ref(), encrypted_signature.as_ref());
    
    // 잘못된 패스워드로 서명 시도
    let wrong_password = "wrong_password";
    let wrong_sign_result = sign_encrypted(
        &encrypted_data,
        wrong_password,
        &test_message,
        Intent::sui_transaction()
    );
    
    assert!(wrong_sign_result.is_err());
}

#[test]
fn test_encrypted_alias_exists() {
    let temp_dir = TempDir::new().unwrap();
    let keystore_path = temp_dir.path().join("sui.encrypted.keystore");
    let mut keystore = EncryptedKeystore::from(EncryptedFileBasedKeystore::new(&keystore_path).unwrap());
    
    // 테스트용 키 생성
    let mut rng = StdRng::from_seed([3; 32]);
    let (_address, kp) = get_key_pair_from_rng(&mut rng);
    let sui_key_pair = SuiKeyPair::Ed25519(kp);
    
    // 키 암호화
    let password = "test_password";
    let encrypted_data = create_encrypted_key(password, &sui_key_pair).unwrap();
    
    // 별칭과 함께 키 추가
    let alias = "my_encrypted_alias";
    keystore.add_key(Some(alias.to_string()), encrypted_data).unwrap();
    
    // 별칭 확인
    let aliases = keystore.alias_names();
    assert_eq!(1, aliases.len());
    assert_eq!(vec![alias], aliases);
    assert!(keystore.alias_exists(alias));
    assert!(!keystore.alias_exists("alias_does_not_exist"));
}

#[test]
fn test_create_encrypted_alias_file() {
    let temp_dir = TempDir::new().unwrap();
    let mut keystore_path = temp_dir.path().join("sui.encrypted.keystore");
    
    // 키스토어 생성
    let mut keystore = EncryptedKeystore::from(EncryptedFileBasedKeystore::new(&keystore_path).unwrap());
    
    // 테스트용 키 생성 및 추가
    let mut rng = StdRng::from_seed([4; 32]);
    let (_address, kp) = get_key_pair_from_rng(&mut rng);
    let sui_key_pair = SuiKeyPair::Ed25519(kp);
    
    // 키 암호화
    let password = "test_password";
    let encrypted_data = create_encrypted_key(password, &sui_key_pair).unwrap();
    
    // 키 추가
    keystore.add_key(None, encrypted_data).unwrap();
    
    // 별칭 파일 확인
    keystore_path.set_extension("aliases");
    assert!(keystore_path.exists());
    
    // 다른 파일명으로도 테스트
    keystore_path = temp_dir.path().join("my_encrypted.keystore");
    let mut keystore = EncryptedKeystore::from(EncryptedFileBasedKeystore::new(&keystore_path).unwrap());
    
    // 다른 테스트용 키 생성 및 추가
    let mut rng = StdRng::from_seed([5; 32]);
    let (_address, kp) = get_key_pair_from_rng(&mut rng);
    let sui_key_pair = SuiKeyPair::Ed25519(kp);
    
    // 키 암호화
    let encrypted_data = create_encrypted_key(password, &sui_key_pair).unwrap();
    
    // 키 추가
    keystore.add_key(None, encrypted_data).unwrap();
    
    // 별칭 파일 확인
    keystore_path.set_extension("aliases");
    assert!(keystore_path.exists());
}

#[test]
fn test_encrypted_check_reading_aliases() {
    // 키스토어 파일을 생성하고 다시 읽었을 때 주소가 올바르게 복원되는지 확인
    let temp_dir = TempDir::new().unwrap();
    let mut keystore_path = temp_dir.path().join("sui.encrypted.keystore");
    let keystore_path_keep = keystore_path.clone();
    
    // 첫 번째 키스토어 생성
    let mut keystore = EncryptedKeystore::from(EncryptedFileBasedKeystore::new(&keystore_path).unwrap());
    
    // 테스트용 키 생성 및 추가
    let mut rng = StdRng::from_seed([6; 32]);
    let (address, kp) = get_key_pair_from_rng(&mut rng);
    let sui_key_pair = SuiKeyPair::Ed25519(kp);
    
    // 키 암호화
    let password = "test_password";
    let encrypted_data = create_encrypted_key(password, &sui_key_pair).unwrap();
    
    // 키 추가
    keystore.add_key(Some("test_alias".to_string()), encrypted_data).unwrap();
    
    // 별칭 파일 확인
    keystore_path.set_extension("aliases");
    assert!(keystore_path.exists());
    
    // 새 키스토어 객체 생성해서 같은 파일 로드
    let new_keystore = EncryptedKeystore::from(EncryptedFileBasedKeystore::new(&keystore_path_keep).unwrap());
    let addresses = new_keystore.addresses_with_alias();
    
    // 주소 확인
    assert_eq!(1, addresses.len());
    assert_eq!(address, *addresses[0].0);
}

#[test]
fn test_encrypted_update_alias() {
    let temp_dir = TempDir::new().unwrap();
    let keystore_path = temp_dir.path().join("sui.encrypted.keystore");
    let mut keystore = EncryptedKeystore::from(EncryptedFileBasedKeystore::new(&keystore_path).unwrap());
    
    // 테스트용 키 생성
    let mut rng = StdRng::from_seed([7; 32]);
    let (_address, kp) = get_key_pair_from_rng(&mut rng);
    let sui_key_pair = SuiKeyPair::Ed25519(kp);
    
    // 키 암호화
    let password = "test_password";
    let encrypted_data = create_encrypted_key(password, &sui_key_pair).unwrap();
    
    // 별칭과 함께 키 추가
    keystore.add_key(Some("my_alias_test".to_string()), encrypted_data).unwrap();
    
    // 별칭 확인
    let aliases = keystore.alias_names();
    assert_eq!(1, aliases.len());
    assert_eq!(vec!["my_alias_test"], aliases);
    
    // 재로드 후 별칭 확인
    let keystore1 = EncryptedKeystore::from(EncryptedFileBasedKeystore::new(&keystore_path).unwrap());
    let aliases1 = keystore1.alias_names();
    assert_eq!(vec!["my_alias_test"], aliases1);
    
    // 존재하지 않는 별칭 업데이트 시도
    let update = keystore.update_alias("alias_does_not_exist", None);
    assert!(update.is_err());
    
    // 별칭 업데이트
    let _ = keystore.update_alias("my_alias_test", Some("new_encrypted_alias"));
    let aliases = keystore.alias_names();
    assert_eq!(vec!["new_encrypted_alias"], aliases);
    
    // 빈 별칭으로 업데이트 시도
    assert!(keystore.update_alias("new_encrypted_alias", Some(" ")).is_err());
    assert!(keystore.update_alias("new_encrypted_alias", Some("   ")).is_err());
    
    // 공백 제거 확인
    assert!(keystore.update_alias("new_encrypted_alias", Some("  o ")).is_ok());
    assert_eq!(vec!["o"], keystore.alias_names());
    
    // 유효하지 않은 별칭으로 업데이트 시도
    assert!(keystore.update_alias("o", Some("_alias")).is_err());
    assert!(keystore.update_alias("o", Some("-alias")).is_err());
    assert!(keystore.update_alias("o", Some("123")).is_err());
    
    // 랜덤 별칭으로 업데이트
    let update = keystore.update_alias("o", None).unwrap();
    let aliases = keystore.alias_names();
    assert_eq!(vec![&update], aliases);
    
    // 중복 별칭 확인
    // 새 키 생성 및 추가
    let mut rng = StdRng::from_seed([8; 32]);
    let (_address2, kp2) = get_key_pair_from_rng(&mut rng);
    let sui_key_pair2 = SuiKeyPair::Ed25519(kp2);
    let encrypted_data2 = create_encrypted_key(password, &sui_key_pair2).unwrap();
    
    keystore.add_key(Some("my_alias_test".to_string()), encrypted_data2).unwrap();
    assert!(keystore.update_alias("my_alias_test", Some(&update)).is_err());
}

#[test]
fn test_encrypted_get_alias_by_address() {
    let temp_dir = TempDir::new().unwrap();
    let keystore_path = temp_dir.path().join("sui.encrypted.keystore");
    let mut keystore = EncryptedKeystore::from(EncryptedFileBasedKeystore::new(&keystore_path).unwrap());
    
    // 테스트용 키 생성
    let mut rng = StdRng::from_seed([9; 32]);
    let (address, kp) = get_key_pair_from_rng(&mut rng);
    let sui_key_pair = SuiKeyPair::Ed25519(kp);
    
    // 키 암호화
    let password = "test_password";
    let encrypted_data = create_encrypted_key(password, &sui_key_pair).unwrap();
    
    // 별칭 설정
    let alias = "my_alias_test".to_string();
    keystore.add_key(Some(alias.clone()), encrypted_data).unwrap();
    
    // 주소로 별칭 조회
    assert_eq!(alias, keystore.get_alias_by_address(&address).unwrap());
    
    // 존재하지 않는 주소 조회
    // 테스트 목적으로 유효한 SuiAddress 생성
    let fake_bytes = [1u8; 32];
    let random_address = SuiAddress::try_from(&fake_bytes[..]).unwrap();
    assert!(keystore.get_alias_by_address(&random_address).is_err());
}
