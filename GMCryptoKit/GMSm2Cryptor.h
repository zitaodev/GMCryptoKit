//
//  GMSm2Cryptor.h
//  GMCryptoKit
//
//  Created by zitaodev's Laptop on 2024/3/13.
//  Copyright © 2024 zitaodev. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface GMSm2Cryptor : NSObject

/**
 SM2 生成密钥对，私钥为256bit的大整数(64字节Hex编码字符串或32字节TF-8编码二进制数据)，公钥格式为 X | Y，其中X和Y为256bit大整数(128字节Hex编码字符串或64字节UTF-8编码二进制数据)
 
 @return 字典实例密钥对: [0] 为SM2公钥, [1] 为SM2私钥,输出格式分别是Hex编码字符串、UTF-8编码二进制数据，失败则返回nil
 */
+ (NSArray<NSString *> *_Nullable)createSm2HexKeyPair;
+ (NSArray<NSData *> *_Nullable)createSm2DataKeyPair;

/**
 SM2 非对称加密算法，加密
 
 @param plaintext 待加密的内容,输入格式分别是：plaintext UTF-8编码字符串、plaintextHex Hex编码字符串、 plainData UTF-8编码二进制数据
 @param publicKey 公钥,输入格式分别是128字节Hex编码字符串或64字节UTF-8编码二进制数据
 @return 密文（04||C1||C3||C2）,输出格式分别是Base64编码字符串、Hex编码字符串、UTF-8编码二进制数据;失败则返回nil
 */
+ (NSString *_Nullable)sm2EncryptText:(NSString *)plaintext withPublicKey:(NSString *)publicKey;
+ (NSString *_Nullable)sm2EncryptHexText:(NSString *)plaintextHex withPublicKey:(NSString *)publicKey;
+ (NSData *_Nullable)sm2EncryptData:(NSData *)plainData withPublicKey:(NSData *)publicKey;

/**
 SM2 非对称加密算法，解密
 
 @param ciphertextBase64 待解密密文（04||C1||C3||C2）,输入格式分别是：ciphertextBase64 Base64编码字符串、ciphertextHex Hex编码字符串、 cipherData UTF-8编码二进制数据
 @param privateKey 私钥,输入格式分别是64字节Hex编码字符串或32字节TF-8编码二进制数据
 @return 解密结果，输出格式分别是UTF-8编码字符串、Hex编码字符串、UTF-8编码二进制数据;失败则返回nil
 */
+ (NSString *_Nullable)sm2DecryptText:(NSString *)ciphertextBase64 withPrivateKey:(NSString *)privateKey;
+ (NSString *_Nullable)sm2DecryptHexText:(NSString *)ciphertextHex withPrivateKey:(NSString *)privateKey;
+ (NSData *_Nullable)sm2DecryptData:(NSData *)cipherData withPrivateKey:(NSData *)privateKey;

/**
 SM2 签名验签算法，签名
 
 @param message 待签名消息,输入格式分别是：message UTF-8编码字符串、messageHex Hex编码字符串、 messageData UTF-8编码二进制数据
 @param privateKey 私钥,输入格式分别是64字节Hex编码字符串或32字节TF-8编码二进制数据
 @return 签名结果，输出格式分别是Base64编码字符串、Hex编码字符串、UTF-8编码二进制数据;失败则返回nil
 */
+ (NSString *_Nullable)sm2SignText:(NSString *)message withPrivateKey:(NSString *)privateKey;
+ (NSString *_Nullable)sm2SignHexText:(NSString *)messageHex withPrivateKey:(NSString *)privateKey;
+ (NSData *_Nullable)sm2SignData:(NSData *)messageData withPrivateKey:(NSData *)privateKey;

/**
 SM2 签名验签算法，验签
 
 @param signatureBase64 签名结果，输入格式分别是：signatureBase64 Base64编码字符串、signatureHex Hex编码字符串、 signatureData UTF-8编码二进制数据
 @param message 待验签内容，输入格式分别是：message UTF-8编码字符串、messageHex Hex编码字符串、 messageData UTF-8编码二进制数据
 @param publicKey 公钥,输入格式分别是128字节Hex编码字符串或64字节UTF-8编码二进制数据
 @return 验签结果,YES 表示验签成功,NO 表示验签失败
 */
+ (BOOL)sm2VerifyText:(NSString *)signatureBase64 forMessage:(NSString *)message withPublicKey:(NSString *)publicKey;
+ (BOOL)sm2VerifyHexText:(NSString *)signatureHex forMessageHex:(NSString *)messageHex withPublicKey:(NSString *)publicKey;
+ (BOOL)sm2VerifyData:(NSData *)signatureData forMessageData:(NSData *)messageData withPublicKey:(NSData *)publicKey;
@end

NS_ASSUME_NONNULL_END
