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

+ (NSString *_Nullable)gm_hmacSm3DigestWithText:(NSString *)plaintext
                                      base64Key:(NSString *)base64Key {
    NSData *plaintextData = [GMUtilities stringToData:plaintext];
    NSData *keyData = [GMUtilities base64StringToData:base64Key];
    NSData *hmacData = [self gm_hmacSm3DigestWithData:plaintextData keyData:keyData];
    return [GMUtilities dataToBase64String:hmacData];
}

+ (NSString *_Nullable)gm_hmacSm3DigestWithHexText:(NSString *)hexPlaintext
                                            hexKey:(NSString *)hexKey {
    NSData *plaintextData = [GMUtilities hexStringToData:hexPlaintext];
    NSData *keyData = [GMUtilities hexStringToData:hexKey];
    NSData *hmacData = [self gm_hmacSm3DigestWithData:plaintextData keyData:keyData];
    return [GMUtilities dataToHexString:hmacData];
}

+ (NSData *_Nullable)gm_hmacSm3DigestWithData:(NSData *)plaintextData
                                      keyData:(NSData *)keyData {
    NSParameterAssert(plaintextData != nil);
    NSParameterAssert(plaintextData.length != 0);
    NSParameterAssert(keyData != nil);
    NSParameterAssert(keyData.length != 0);
    
    uint8_t *plaintext_bytes = (uint8_t *)plaintextData.bytes;
    size_t plaintext_len = plaintextData.length;
    uint8_t *key_bytes = (uint8_t *)keyData.bytes;
    size_t key_len = keyData.length;
    
    uint8_t hmac[SM3_HMAC_SIZE];
    memset(hmac, 0, SM3_HMAC_SIZE);
    sm3_hmac(key_bytes, key_len, plaintext_bytes, plaintext_len, hmac);

    NSData *hmac_data = [NSData dataWithBytes:hmac length:SM3_DIGEST_SIZE];
    if (!hmac_data || hmac_data.length == 0) {
        return nil;
    }
    return hmac_data;
}

#pragma mark -  SM3 摘要算法

+ (NSString *_Nullable)gm_sm3DigestWithText:(NSString *)plaintext {
    NSData *plaintextData = [GMUtilities stringToData:plaintext];
    NSData *digestData = [self gm_sm3DigestWithData:plaintextData];
    return [GMUtilities dataToBase64String:digestData];
}

+ (NSString *_Nullable)gm_sm3DigestWithHexText:(NSString *)hexPlaintext {
    NSData *plaintextData = [GMUtilities hexStringToData:hexPlaintext];
    NSData *digestData = [self gm_sm3DigestWithData:plaintextData];
    return [GMUtilities dataToHexString:digestData];
}

+ (NSData *_Nullable)gm_sm3DigestWithData:(NSData *)plaintextData {
    NSParameterAssert(plaintextData != nil);
    NSParameterAssert(plaintextData.length != 0);

    uint8_t *plaintext_bytes = (uint8_t *)plaintextData.bytes;
    size_t plaintext_len = plaintextData.length;
    
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
