//! In Module 1, we discussed Block ciphers like AES. Block ciphers have a fixed length input.
//! Real world data that we wish to encrypt _may_ be exactly the right length, but is probably not.
//! When your data is too short, you can simply pad it up to the correct length.
//! When your data is too long, you have some options.
//!
//! In this exercise, we will explore a few of the common ways that large pieces of data can be
//! broken up and combined in order to encrypt it with a fixed-length block cipher.
//!
//! WARNING: ECB MODE IS NOT SECURE.
//! Seriously, ECB is NOT secure. Don't use it irl. We are implementing it here to understand _why_
//! it is not secure and make the point that the most straight-forward approach isn't always the
//! best, and can sometimes be trivially broken.
#![allow(unused_variables)]
#![allow(unused_imports)]
#![allow(dead_code)]

use aes::{
    cipher::{generic_array::GenericArray, BlockCipher, BlockDecrypt, BlockEncrypt, KeyInit},
    Aes128,
};
use rand::Rng;

///We're using AES 128 which has 16-byte (128 bit) blocks.
const BLOCK_SIZE: usize = 16;

/// Simple AES encryption
/// Helper function to make the core AES block cipher easier to understand.
fn aes_encrypt(data: [u8; BLOCK_SIZE], key: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    // Convert the inputs to the necessary data type
    let mut block = GenericArray::from(data);
    let key = GenericArray::from(*key);

    let cipher = Aes128::new(&key);

    cipher.encrypt_block(&mut block);

    block.into()
}

/// Simple AES encryption
/// Helper function to make the core AES block cipher easier to understand.
fn aes_decrypt(data: [u8; BLOCK_SIZE], key: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    // Convert the inputs to the necessary data type
    let mut block = GenericArray::from(data);
    let key = GenericArray::from(*key);

    let cipher = Aes128::new(&key);

    cipher.decrypt_block(&mut block);

    block.into()
}

/// Before we can begin encrypting our raw data, we need it to be a multiple of the
/// block length which is 16 bytes (128 bits) in AES128.
///
/// The padding algorithm here is actually not trivial. The trouble is that if we just
/// naively throw a bunch of zeros on the end, there is no way to know, later, whether
/// those zeros are padding, or part of the message, or some of each.
///
/// The scheme works like this. If the data is not a multiple of the block length,  we
/// compute how many pad bytes we need, and then write that number into the last several bytes.
/// Later we look at the last byte, and remove that number of bytes.
///
/// But if the data _is_ a multiple of the block length, then we have a problem. We don't want
/// to later look at the last byte and remove part of the data. Instead, in this case, we add
/// another entire block containing the block length in each byte. In our case,
/// [16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16]
fn pad(mut data: Vec<u8>) -> Vec<u8> {
    // When we have a multiple the second term is 0
    let number_pad_bytes = BLOCK_SIZE - data.len() % BLOCK_SIZE;

    for _ in 0..number_pad_bytes {
        data.push(number_pad_bytes as u8);
    }

    data
}

/// Does the opposite of the pad function.
fn unpad(data: Vec<u8>) -> Vec<u8> {
    if data.is_empty() {
        return data;
    }

    let number_pad_bytes = data.last().cloned().unwrap() as usize;

    if number_pad_bytes > data.len() {
        return data;
    }

    data[..data.len() - number_pad_bytes].to_vec()
}


/// Groups the data into BLOCK_SIZE blocks. Assumes the data is already
/// a multiple of the block size. If this is not the case, call `pad` first.
fn group(data: Vec<u8>) -> Vec<[u8; BLOCK_SIZE]> {
    let mut blocks = Vec::new();
    let mut i = 0;
    while i < data.len() {
        let mut block: [u8; BLOCK_SIZE] = Default::default();
        block.copy_from_slice(&data[i..i + BLOCK_SIZE]);
        blocks.push(block);

        i += BLOCK_SIZE;
    }

    blocks
}

/// Does the opposite of the group function
fn ungroup(blocks: Vec<[u8; BLOCK_SIZE]>) -> Vec<u8> {
    let mut data = Vec::new();
    for block in blocks {
        data.extend_from_slice(&block);
    }
    data
}


/// The first mode we will implement is the Electronic Code Book, or ECB mode.
/// Warning: THIS MODE IS NOT SECURE!!!!
///
/// This is probably the first thing you think of when considering how to encrypt
/// large data. In this mode we simply encrypt each block of data under the same key.
/// One good thing about this mode is that it is parallelizable. But to see why it is
/// insecure look at: https://www.ubiqsecurity.com/wp-content/uploads/2022/02/ECB2.png
fn ecb_encrypt(plain_text: Vec<u8>, key: [u8; 16]) -> Vec<u8> {
    let padded_text = pad(plain_text);
    let blocks = group(padded_text);

    let encrypted_blocks: Vec<[u8; BLOCK_SIZE]> = blocks
        .into_iter()
        .map(|block| aes_encrypt(block, &key))
        .collect();

    ungroup(encrypted_blocks)
}

/// Opposite of ecb_encrypt.
fn ecb_decrypt(cipher_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
    let blocks = group(cipher_text);

    let decrypted_blocks: Vec<[u8; BLOCK_SIZE]> = blocks
        .into_iter()
        .map(|block| aes_decrypt(block, &key))
        .collect();

    unpad(ungroup(decrypted_blocks))
}

/// The next mode, which you can implement on your own is cipherblock chaining.
/// This mode actually is secure, and it often used in real world applications.
///
/// In this mode, the ciphertext from the first block is XORed with the
/// plaintext of the next block before it is encrypted.
///
/// For more information, and a very clear diagram,
/// see https://de.wikipedia.org/wiki/Cipher_Block_Chaining_Mode
///
/// You will need to generate a random initialization vector (IV) to encrypt the
/// very first block because it doesn't have a previous block. Typically this IV
/// is inserted as the first block of ciphertext.
fn xor(block1: [u8; BLOCK_SIZE], block2: [u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    let mut result: [u8; BLOCK_SIZE] = [0; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        result[i] = block1[i] ^ block2[i];
    }
    result
}

fn cbc_encrypt(plain_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
    // Remember to generate a random initialization vector for the first block.

    let mut rng = rand::thread_rng();
    let mut iv: [u8; BLOCK_SIZE] = [0; BLOCK_SIZE];
    rng.fill(&mut iv);

    let padded_text = pad(plain_text);
    let blocks = group(padded_text);

    let mut previous_ciphertext_block = iv; // first key is just the IV
    let mut encrypted_blocks: Vec<[u8; BLOCK_SIZE]> = Vec::new();
    for block in blocks.iter() {
        let xor_block: [u8; BLOCK_SIZE] = xor(*block, previous_ciphertext_block);
        previous_ciphertext_block = aes_encrypt(xor_block, &key);
        encrypted_blocks.push(previous_ciphertext_block);
    }

    let mut ciphertext = ungroup(encrypted_blocks);

    // Prepend the IV to the ciphertext
    ciphertext.splice(0..0, iv.iter().cloned());

    ciphertext
}

fn cbc_decrypt(cipher_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
    // Extract the IV from the first block of the ciphertext
    let iv: Vec<u8> = cipher_text[0..BLOCK_SIZE].to_vec();
    let iv: [u8; BLOCK_SIZE] = iv.try_into().expect("Wrong IV length");
    let mut previous_ciphertext_block = iv;

    let blocks = group(cipher_text);

    // Decrypt each block
    let mut decrypted_blocks: Vec<[u8; BLOCK_SIZE]> = Vec::new();
    for block in blocks[1..].iter() {
        let decrypted_block = aes_decrypt(*block, &key);
        let xor_block = xor(decrypted_block, previous_ciphertext_block);
        previous_ciphertext_block = *block;
        decrypted_blocks.push(xor_block);
    }

    unpad(ungroup(decrypted_blocks))
}

/// Another mode which you can implement on your own is counter mode.
/// This mode is secure as well, and is used in real world applications.
/// It allows parallelized encryption and decryption, as well as random read access when decrypting.
///
/// In this mode, there is an index for each block being encrypted (the "counter"), as well as a random nonce.
/// For a 128-bit cipher, the nonce is 64 bits long.
///
/// For the ith block, the 128-bit value V of `nonce | counter` is constructed, where | denotes
/// concatenation. Then, V is encrypted with the key using ECB mode. Finally, the encrypted V is
/// XOR'd with the plaintext to produce the ciphertext.
///
/// A very clear diagram is present here:
/// https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)
///
/// Once again, you will need to generate a random nonce which is 64 bits long. This should be
/// inserted as the first block of the ciphertext.
fn ctr_encrypt(plain_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
    // Remember to generate a random nonce
    let mut rng = rand::thread_rng();
    let mut nonce: [u8; BLOCK_SIZE / 2] = [0; BLOCK_SIZE / 2];
    rng.fill(&mut nonce);

    let padded_text = pad(plain_text);
    let blocks = group(padded_text);

    // need half nonce, half counter. first half nonce does not change block to block, only counter does.
    let mut v: [u8; BLOCK_SIZE] = [0; BLOCK_SIZE];
    v[..BLOCK_SIZE / 2].copy_from_slice(&nonce);

    let mut encrypted_blocks: Vec<[u8; BLOCK_SIZE]> = Vec::new();
    for (i, block) in blocks.iter().enumerate() {
        v[BLOCK_SIZE / 2..].copy_from_slice(&(i as u64).to_ne_bytes());

        let block_v = aes_encrypt(v, &key);
        encrypted_blocks.push(xor(*block, block_v));
    }

    let mut ciphertext = ungroup(encrypted_blocks);

    // Prepend the IV to the ciphertext, in this case it's only half the block size, so we need to pad it first
    ciphertext.splice(0..0, pad(nonce.to_vec()).iter().cloned());

    ciphertext
}

fn ctr_decrypt(cipher_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
    let nonce: Vec<u8> = cipher_text[0..BLOCK_SIZE / 2].to_vec();
    let nonce: [u8; BLOCK_SIZE / 2] = nonce.try_into().expect("Wrong nonce length");

    let blocks = group(cipher_text);

    let mut v: [u8; BLOCK_SIZE] = [0; BLOCK_SIZE];
    v[..BLOCK_SIZE / 2].copy_from_slice(&nonce);

    let mut decrypted_blocks: Vec<[u8; BLOCK_SIZE]> = Vec::new();
    for (i, block) in blocks[1..].iter().enumerate() {
        v[BLOCK_SIZE / 2..].copy_from_slice(&(i as u64).to_ne_bytes());

        let block_v = aes_encrypt(v, &key);
        decrypted_blocks.push(xor(*block, block_v));
    }

    unpad(ungroup(decrypted_blocks))
}

/// This function is not graded. It is just for collecting feedback.
/// On a scale from 0 - 100, with zero being extremely easy and 100 being extremely hard, how hard
/// did you find the exercises in this section?
pub fn how_hard_was_this_section() -> u8 {
    70
}

/// This function is not graded. It is just for collecting feedback.
/// About how much time (in hours) did you spend on the exercises in this section?
pub fn how_many_hours_did_you_spend_on_this_section() -> f32 {
    1.5
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_KEY: [u8; 16] = [
        6, 108, 74, 203, 170, 212, 94, 238, 171, 104, 19, 17, 248, 197, 127, 138,
    ];

    #[test]
    fn ungroup_test() {
        let data: Vec<u8> = (0..48).collect();
        let grouped = group(data.clone());
        let ungrouped = ungroup(grouped);
        assert_eq!(data, ungrouped);
    }

    #[test]
    fn unpad_test() {
        // An exact multiple of block size
        let data: Vec<u8> = (0..48).collect();
        let padded = pad(data.clone());
        let unpadded = unpad(padded);
        assert_eq!(data, unpadded);

        // A non-exact multiple
        let data: Vec<u8> = (0..53).collect();
        let padded = pad(data.clone());
        let unpadded = unpad(padded);
        assert_eq!(data, unpadded);
    }

    #[test]
    fn ecb_encrypt_test() {
        let plaintext = b"Polkadot Blockchain Academy!".to_vec();
        let encrypted = ecb_encrypt(plaintext, TEST_KEY);
        assert_eq!(
            "12d4105e43c4426e1f3e9455bb39c8fc0a4667637c9de8bad43ee801d313a555".to_string(),
            hex::encode(encrypted)
        );
    }

    #[test]
    fn ecb_decrypt_test() {
        let plaintext = b"Polkadot Blockchain Academy!".to_vec();
        let ciphertext =
            hex::decode("12d4105e43c4426e1f3e9455bb39c8fc0a4667637c9de8bad43ee801d313a555")
                .unwrap();
        assert_eq!(plaintext, ecb_decrypt(ciphertext, TEST_KEY))
    }

    #[test]
    fn cbc_roundtrip_test() {
        // Because CBC uses randomness, the round trip has to be tested
        let plaintext = b"Polkadot Blockchain Academy!".to_vec();
        let ciphertext = cbc_encrypt(plaintext.clone(), TEST_KEY);
        let decrypted = cbc_decrypt(ciphertext.clone(), TEST_KEY);
        assert_eq!(plaintext.clone(), decrypted);

        let mut modified_ciphertext = ciphertext.clone();
        modified_ciphertext[18] = 0;
        let decrypted_bad = cbc_decrypt(modified_ciphertext, TEST_KEY);
        assert_ne!(plaintext, decrypted_bad);
    }

    #[test]
    fn ctr_roundtrip_test() {
        // adding a test for CTR using CBC template above
        let plaintext = b"Polkadot Blockchain Academy!".to_vec();
        let ciphertext = ctr_encrypt(plaintext.clone(), TEST_KEY);
        let decrypted = ctr_decrypt(ciphertext.clone(), TEST_KEY);
        assert_eq!(plaintext.clone(), decrypted);

        let mut modified_ciphertext = ciphertext.clone();
        modified_ciphertext[18] = 0;
        let decrypted_bad = cbc_decrypt(modified_ciphertext, TEST_KEY);
        assert_ne!(plaintext, decrypted_bad);
    }
}
