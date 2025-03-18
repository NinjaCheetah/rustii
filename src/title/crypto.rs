// title/crypto.rs from rustii-lib (c) 2025 NinjaCheetah & Contributors
// https://github.com/NinjaCheetah/rustii-lib
//
// Implements the common crypto functions required to handle Wii content encryption.

use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use aes::cipher::block_padding::ZeroPadding;
use crate::title::commonkeys::get_common_key;

// Convert a Title ID into the format required for use as the Title Key decryption IV.
fn title_id_to_iv(title_id: [u8; 8]) -> [u8; 16] {
    let mut iv: Vec<u8> = Vec::from(title_id);
    iv.resize(16, 0);
    iv.as_slice().try_into().unwrap()
}

// Decrypt a Title Key using the specified common key.
pub fn decrypt_title_key(title_key_enc: [u8; 16], common_key_index: u8, title_id: [u8; 8]) -> [u8; 16] {
    let iv = title_id_to_iv(title_id);
    type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
    let decryptor = Aes128CbcDec::new(&get_common_key(common_key_index, None).into(), &iv.into());
    let mut title_key = title_key_enc;
    decryptor.decrypt_padded_mut::<ZeroPadding>(&mut title_key).unwrap();
    title_key
}

// Encrypt a Title Key using the specified common key.
pub fn encrypt_title_key(title_key_dec: [u8; 16], common_key_index: u8, title_id: [u8; 8]) -> [u8; 16] {
    let iv = title_id_to_iv(title_id);
    type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
    let encryptor = Aes128CbcEnc::new(&get_common_key(common_key_index, None).into(), &iv.into());
    let mut title_key = title_key_dec;
    encryptor.encrypt_padded_mut::<ZeroPadding>(&mut title_key, 16).unwrap();
    title_key
}
