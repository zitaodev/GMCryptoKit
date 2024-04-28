//
//  GMSm3Digest.m
//  GMCryptoKit
//
//  Created by zitaodev's Laptop on 2024/3/18.
//  Copyright © 2024 zitaodev. All rights reserved.
//

#import "GMSm3Digest.h"
#import "GMUtilities.h"
#import <gmssl/sm3.h>

@implementation GMSm3Digest

#pragma mark - 基于SM3算法的HMAC计算

+ (NSString *_Nullable)hmacSm3DigestWithText:(NSString *)plaintext
                                         key:(NSString *)key {
    NSData *plainData = [GMUtilities stringToData:plaintext];
    NSData *keyData = [GMUtilities hexStringToData:key];
    NSData *hmacData = [self hmacSm3DigestWithData:plainData key:keyData];
    return [GMUtilities dataToBase64String:hmacData];
}

+ (NSString *_Nullable)hmacSm3DigestWithHexText:(NSString *)plaintextHex
                                            key:(NSString *)key {
    NSData *plainData = [GMUtilities hexStringToData:plaintextHex];
    NSData *keyData = [GMUtilities hexStringToData:key];
    NSData *hmacData = [self hmacSm3DigestWithData:plainData key:keyData];
    return [GMUtilities dataToHexString:hmacData];
}

+ (NSData *_Nullable)hmacSm3DigestWithData:(NSData *)plainData
                                       key:(NSData *)key {
    NSParameterAssert(plainData != nil);
    NSParameterAssert(plainData.length != 0);
    NSParameterAssert(key != nil);
    NSParameterAssert(key.length != 0);
    
    uint8_t *plaintext_bytes = (uint8_t *)plainData.bytes;
    size_t plaintext_len = plainData.length;
    uint8_t *key_bytes = (uint8_t *)key.bytes;
    size_t key_len = key.length;
    
    uint8_t hmac[SM3_HMAC_SIZE];
    memset(hmac, 0, SM3_HMAC_SIZE);
    sm3_hmac(key_bytes, key_len, plaintext_bytes, plaintext_len, hmac);

    NSData *hmac_data = [NSData dataWithBytes:hmac length:SM3_DIGEST_SIZE];
    if (!hmac_data || hmac_data.length == 0) {
        return nil;
    }
    return hmac_data;
}

#pragma mark -  SM3 密码杂凑算法

+ (NSString *_Nullable)sm3DigestWithText:(NSString *)plaintext {
    NSData *plaintextData = [GMUtilities stringToData:plaintext];
    NSData *digestData = [self sm3DigestWithData:plaintextData];
    return [GMUtilities dataToBase64String:digestData];
}

+ (NSString *_Nullable)sm3DigestWithHexText:(NSString *)plaintextHex {
    NSData *plaintextData = [GMUtilities hexStringToData:plaintextHex];
    NSData *digestData = [self sm3DigestWithData:plaintextData];
    return [GMUtilities dataToHexString:digestData];
}

+ (NSData *_Nullable)sm3DigestWithData:(NSData *)plainData {
    NSParameterAssert(plainData != nil);
    NSParameterAssert(plainData.length != 0);

    uint8_t *plaintext_bytes = (uint8_t *)plainData.bytes;
    size_t plaintext_len = plainData.length;
    
    uint8_t dgst[SM3_DIGEST_SIZE];
    memset(dgst, 0, SM3_DIGEST_SIZE);
    sm3_digest(plaintext_bytes, plaintext_len, dgst);
    
    NSData *dgst_data = [NSData dataWithBytes:dgst length:SM3_DIGEST_SIZE];
    if (!dgst_data || dgst_data.length == 0) {
        return nil;
    }
    return dgst_data;
}

@end
