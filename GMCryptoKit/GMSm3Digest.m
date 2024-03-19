//
//  GMSm3Digest.m
//  GMCryptoKit
//
//  Created by Joe's Laptop on 2024/3/18.
//

#import "GMSm3Digest.h"
#import <gmssl/sm3.h>
@implementation GMSm3Digest

+ (NSData *_Nullable)gm_sm3DigestWithData:(NSData *)plaintextData {
    if (plaintextData.length == 0) {
        return nil;
    }
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
