//
//  GMSm3Digest.h
//  GMCryptoKit
//
//  Created by zitaodev's Laptop on 2024/3/18.
//  Copyright © 2024 zitaodev. All rights reserved.

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface GMSm3Digest : NSObject

/**
 SM3 摘要算法
 
 @param plaintext     NSString类型待计算数据（UTF-8编码）
        hexPlaintext  NSString类型待计算数据（Hex编码）
        plaintextData NSData类型待计算数据  （UTF-8编码）
 @return 成功则返回摘要值，分别是：
         NSString类型摘要值（Base64编码）
         NSString类型摘要值（Hex格式）
         NSData类型摘要值  （UTF-8编码）
         失败则返回nil
 */
+ (NSString *_Nullable)gm_sm3DigestWithText:(NSString *)plaintext;
+ (NSString *_Nullable)gm_sm3DigestWithHexText:(NSString *)hexPlaintext;
+ (NSData *_Nullable)gm_sm3DigestWithData:(NSData *)plaintextData;

/**
 基于SM3算法的HMAC计算
 
 @param plaintext     NSString类型待计算数据（UTF-8编码）
        hexPlaintext  NSString类型待计算数据（Hex编码）
        plaintextData NSData类型待计算数据  （UTF-8编码）
 @param base64Key     NSString类型密钥（Base64编码）
        hexKey        NSString类型密钥（Hex编码）
        keyData       NSData类型密钥  （UTF-8编码）
 @return 成功则返回HMAC值，分别是：
         NSString类型HMAC值（Base64编码）
         NSString类型HMAC值（Hex编码）
         NSData类型HMAC值  （UTF-8编码）
         失败则返回nil
 */
+ (NSString *_Nullable)gm_hmacSm3DigestWithText:(NSString *)plaintext
                                      base64Key:(NSString *)base64Key;
+ (NSString *_Nullable)gm_hmacSm3DigestWithHexText:(NSString *)hexPlaintext
                                            hexKey:(NSString *)hexKey;
+ (NSData *_Nullable)gm_hmacSm3DigestWithData:(NSData *)plaintextData
                                      keyData:(NSData *)keyData;
@end

NS_ASSUME_NONNULL_END
