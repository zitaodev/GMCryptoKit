//
//  GMSm3Digest.m
//  GMCryptoKit
//
//  Created by zitaodev's Laptop on 2024/3/18.
//  Copyright © 2024 zitaodev. All rights reserved.
//

#import "GMSm3Digest.h"
#import <gmssl/sm3.h>
@implementation GMSm3Digest

+ (NSData *_Nullable)gm_hmacSm3DigestWithData:(NSData *)plaintextData keyData:(NSData *)keyData {
    NSParameterAssert(plaintextData != nil);
    NSParameterAssert(plaintextData.length != 0);
    NSParameterAssert(keyData != nil);
    NSParameterAssert(keyData.length != 0);
    
    uint8_t *plaintext_bytes = (uint8_t *)plaintextData.bytes;
    size_t plaintext_len = plaintextData.length;
    
    uint8_t *key_bytes = (uint8_t *)keyData.bytes;
    size_t key_len = keyData.length;
    
    unsigned char hmac[SM3_HMAC_SIZE];
    memset(hmac, 0, SM3_HMAC_SIZE);
    
    // 计算摘要
    sm3_hmac(key_bytes, key_len, plaintext_bytes, plaintext_len, hmac);
    
    // 转为 NSData格式
    NSData *hmac_data = [NSData dataWithBytes:hmac length:SM3_DIGEST_SIZE];
    if (!hmac_data || hmac_data.length == 0) {
        return nil;
    }
    return hmac_data;
}

+ (NSData *_Nullable)gm_sm3DigestWithData:(NSData *)plaintextData {
    NSParameterAssert(plaintextData != nil);
    NSParameterAssert(plaintextData.length != 0);
    // 原文
    uint8_t *plaintext_bytes = (uint8_t *)plaintextData.bytes;
    size_t plaintext_len = plaintextData.length;
    // 摘要结果
    unsigned char dgst[SM3_DIGEST_SIZE];
    memset(dgst, 0, SM3_DIGEST_SIZE);
    
    // 计算摘要
    sm3_digest(plaintext_bytes, plaintext_len, dgst);
    
    // 转为 NSData格式
    NSData *dgst_data = [NSData dataWithBytes:dgst length:SM3_DIGEST_SIZE];
    if (!dgst_data || dgst_data.length == 0) {
        return nil;
    }
    return dgst_data;
}

@end
