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
 将任意长度的输入数据计算为固定32字节长度的哈希值。
 
 @param plaintext 待计算哈希的数据，输入格式分别是：plaintext UTF-8编码字符串、plaintextHex Hex编码字符串、 plainData UTF-8编码二进制数据
 @return 哈希值，输出格式分别是Base64编码字符串、Hex编码字符串、UTF-8编码二进制数据，失败则返回nil
 */
+ (NSString *_Nullable)sm3DigestWithText:(NSString *)plaintext;
+ (NSString *_Nullable)sm3DigestWithHexText:(NSString *)plaintextHex;
+ (NSData *_Nullable)sm3DigestWithData:(NSData *)plainData;

/**
 基于SM3算法的HMAC计算
 密钥长度建议采用32字节（等同于SM3哈希值的长度），
 不应少于16字节，采用比32字节更长的密钥长度会增加计算开销而不会增加安全性。
 
 @param plaintext 待计算HMAC的数据,输入格式分别是：plaintext UTF-8编码字符串、plainHexText Hex编码字符串、 plainData UTF-8编码二进制数据
 @param key       密钥,输入格式分别是Hex编码字符串或者UTF-8编码二进制数据
 @return HMAC值,输出格式分别是Base64编码字符串、Hex编码字符串、UTF-8编码二进制数据，失败则返回nil
 */
+ (NSString *_Nullable)hmacSm3DigestWithText:(NSString *)plaintext key:(NSString *)key;
+ (NSString *_Nullable)hmacSm3DigestWithHexText:(NSString *)plaintextHex key:(NSString *)key;
+ (NSData *_Nullable)hmacSm3DigestWithData:(NSData *)plainData key:(NSData *)key;
@end

NS_ASSUME_NONNULL_END
