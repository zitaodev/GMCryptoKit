//
//  GMSm4Cryptor.m
//  GMCryptoKit
//
//  Created by zitaodev's Laptop on 2024/3/26.
//  Copyright © 2024 zitaodev. All rights reserved.
//

#import "GMSm4Cryptor.h"
#import "GMRandomGenerator.h"
#import <gmssl/sm4.h>
@implementation GMSm4Cryptor

+ (NSData *_Nullable)gm_createSm4Key {
    return [GMRandomGenerator gm_secRandomDataWithLength:SM4_KEY_SIZE];
}

+ (NSData *_Nullable)gm_sm4CbcPaddingEncryptData:(NSData *)plaintextData
                                         withKey:(NSData *)key
                                          withIv:(NSData *)iv {
    NSParameterAssert(plaintextData != nil);
    NSParameterAssert(plaintextData.length != 0);
    NSParameterAssert(key != nil);
    NSParameterAssert(key.length == SM4_KEY_SIZE);
    NSParameterAssert(iv != nil);
    NSParameterAssert(iv.length == SM4_KEY_SIZE);

    uint8_t *plaintext_bytes = (uint8_t *)plaintextData.bytes;
    size_t plaintext_len = plaintextData.length;
    
    uint8_t *key_bytes = (uint8_t *)key.bytes;
    size_t key_len = key.length;
    
    uint8_t *iv_bytes = (uint8_t *)iv.bytes;
    size_t iv_len = iv.length;
    
    u_int8_t raw_key[key_len];
    memcpy(raw_key, key_bytes, key_len);
    
    u_int8_t raw_iv[iv_len];
    memcpy(raw_iv, iv_bytes, iv_len);
    
    SM4_KEY sm4_key;
    sm4_set_encrypt_key(&sm4_key, raw_key);

    uint8_t cipher_buf[plaintext_len + SM4_BLOCK_SIZE];
    size_t cipher_len;
    sm4_cbc_padding_encrypt(&sm4_key, raw_iv, plaintext_bytes, plaintext_len, cipher_buf, &cipher_len);
    
    NSData *cipher_data = [NSData dataWithBytes:cipher_buf length:cipher_len];
    if (!cipher_data || cipher_data.length == 0) {
        return nil;
    }
    return cipher_data;
}

+ (NSData *_Nullable)gm_sm4CbcPaddingDecryptData:(NSData *)cipherData
                                         withKey:(NSData *)key
                                          withIv:(NSData *)iv {
    NSParameterAssert(cipherData != nil);
    NSParameterAssert(cipherData.length != 0);
    NSParameterAssert(key != nil);
    NSParameterAssert(key.length == SM4_KEY_SIZE);
    NSParameterAssert(iv != nil);
    NSParameterAssert(iv.length == SM4_KEY_SIZE);
    
    uint8_t *cipher_bytes = (uint8_t *)cipherData.bytes;
    size_t cipher_len = cipherData.length;
    
    uint8_t *key_bytes = (uint8_t *)key.bytes;
    size_t key_len = key.length;
    
    uint8_t *iv_bytes = (uint8_t *)iv.bytes;
    size_t iv_len = iv.length;
    
    u_int8_t raw_key[key_len];
    memcpy(raw_key, key_bytes, key_len);
    
    u_int8_t raw_iv[iv_len];
    memcpy(raw_iv, iv_bytes, iv_len);
    
    SM4_KEY sm4_key;
    sm4_set_decrypt_key(&sm4_key, raw_key);

    uint8_t plaintext_buf[cipher_len];
    size_t plaintext_len;
    sm4_cbc_padding_decrypt(&sm4_key, raw_iv, cipher_bytes, cipher_len, plaintext_buf, &plaintext_len);
    
    NSData *plaintext_data = [NSData dataWithBytes:plaintext_buf length:plaintext_len];
    if (!plaintext_data || plaintext_data.length == 0) {
        return nil;
    }
    return plaintext_data;
}


@end
