//
//  GMSm4Cryptor.h
//  GMCryptoKit
//
//  Created by zitaodev's Laptop on 2024/3/26.
//  Copyright © 2024 zitaodev. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface GMSm4Cryptor : NSObject

/**
 SM4 生成密钥。也可以调用该方法生成SM4 CBC模式的初始化向量iv，iv长度和key长度一致

 @return 密钥，输出格式分别是32字节Hex编码字符串或者16字节的二进制数据
 */
+ (NSString *_Nullable)createSm4HexKey;
+ (NSData *_Nullable)createSm4Key;

/**
 SM4 对称加解密。CBC模式加密，使用PKCS#7填充标准
 
 @param plaintext 待加密的明文,输入格式分别是：plaintext UTF-8编码字符串、plaintextHex Hex编码字符串、 plainData 二进制数据
 @param key 32字节Hex编码字符串的密钥
 @param iv 32字节Hex编码字符串的初始化向量
 @return 密文,输出格式分别是Base64编码字符串、Hex编码字符串、二进制数据
 */
+ (NSString *_Nullable)sm4CbcPaddingEncryptText:(NSString *)plaintext withKey:(NSString *)key withIv:(NSString *)iv;
+ (NSString *_Nullable)sm4CbcPaddingEncryptHexText:(NSString *)plaintextHex withKey:(NSString *)key withIv:(NSString *)iv;
+ (NSData *_Nullable)sm4CbcPaddingEncryptData:(NSData *)plainData withKey:(NSData *)key withIv:(NSData *)iv;

/**
 SM4 对称加解密。CBC模式解密，使用PKCS#7填充标准
 
 @param ciphertextBase64 待加密的密文，输入格式分别是：ciphertextBase64 Base64编码字符串、ciphertextHex Hex编码字符串、 cipherData 二进制数据
 @param key 32字节Hex编码字符串的密钥
 @param iv  32字节Hex编码字符串的初始化向量
 @return 解密后的明文,输出格式分别是UTF-8编码字符串、Hex编码字符串、二进制数据
 */
+ (NSString *_Nullable)sm4CbcPaddingDecryptText:(NSString *)ciphertextBase64 withKey:(NSString *)key withIv:(NSString *)iv;
+ (NSString *_Nullable)sm4CbcPaddingDecryptHexText:(NSString *)ciphertextHex withKey:(NSString *)key withIv:(NSString *)iv;
+ (NSData *_Nullable)sm4CbcPaddingDecryptData:(NSData *)cipherData withKey:(NSData *)key withIv:(NSData *)iv;

@end

NS_ASSUME_NONNULL_END
