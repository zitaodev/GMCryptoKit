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
    if (plaintextData == nil || plaintextData.length == 0 || key == nil || key.length != 16 || iv == nil || iv.length != 16) {
        return nil;
    }
    
    uint8_t *plaintext_bytes = (uint8_t *)plaintextData.bytes;
    uint8_t *key_bytes = (uint8_t *)key.bytes;
    uint8_t *iv_bytes = (uint8_t *)iv.bytes;
    
    size_t plaintext_len = plaintextData.length;
    size_t key_len = key.length;
    size_t iv_len = iv.length;
    
    SM4_KEY sm4_key;
    u_int8_t raw_key[key_len];
    memcpy(raw_key, key_bytes, key_len);
    sm4_set_encrypt_key(&sm4_key, raw_key);

    unsigned char cbuf[plaintext_len + SM4_BLOCK_SIZE];
    size_t clen;
    sm4_cbc_padding_encrypt(&sm4_key, iv_bytes, plaintext_bytes, plaintext_len, cbuf, &clen);
    NSData *cipher_data = [NSData dataWithBytes:cbuf length:clen];
    if (!cipher_data || cipher_data.length == 0) {
        return nil;
    }
    return cipher_data;
}

+ (NSData *_Nullable)gm_sm4CbcPaddingDecryptData:(NSData *)cipherData
                                         withKey:(NSData *)key
                                          withIv:(NSData *)iv {
    if (cipherData == nil || cipherData.length == 0 || key == nil || key.length != 16 || iv == nil || iv.length != 16) {
        return nil;
    }
    
    uint8_t *cipher_bytes = (uint8_t *)cipherData.bytes;
    uint8_t *key_bytes = (uint8_t *)key.bytes;
    uint8_t *iv_bytes = (uint8_t *)iv.bytes;
    
    size_t cipher_len = cipherData.length;
    size_t key_len = key.length;
    size_t iv_len = iv.length;
    
    SM4_KEY sm4_key;
    u_int8_t raw_key[key_len];
    memcpy(raw_key, key_bytes, key_len);
    sm4_set_decrypt_key(&sm4_key, raw_key);

    unsigned char pbuf[cipher_len];
    size_t plen;
    sm4_cbc_padding_decrypt(&sm4_key, iv_bytes, cipher_bytes, cipher_len, pbuf, &plen);

    // 移除PKCS#7填充
    // 参考:https://github.com/guanzhi/GmSSL/issues/1483
    unsigned char padding_count = pbuf[plen - 1];
    uint8_t count = 0;
    uint8_t i = 0;

    for(i= plen - padding_count; i < plen; i++) {
        if(pbuf[i] != padding_count) {
            break;
        } else { count ++; }
    }

    if (count != padding_count) return nil;
    for(i= plen - padding_count; i < plen; i++) {
        pbuf[i] = 0;
    }

    NSData *cipher_data = [NSData dataWithBytes:pbuf length:plen];
    if (!cipher_data || cipher_data.length == 0) {
        return nil;
    }
    return cipher_data;
}


@end
