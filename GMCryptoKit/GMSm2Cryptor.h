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
 SM2 生成密钥对
 
 SM2公钥: NSString类型（Base64编码，88字节长度）
         NSString类型（Hex格式，128字节长度）
         NSData类型  （UTF-8编码，64字节长度）
 SM2私钥: NSString类型（Base64编码，44字节长度）
         NSString类型（Hex格式，64字节长度）
         NSData类型  （UTF-8编码，32字节长度）
 @return 返回值：成功则返回密钥对字典实例 @{@"publicKey" : SM2公钥, @"privateKey" : SM2私钥}
         失败则返回nil
 */
+ (NSDictionary<NSString *, NSString *> *_Nullable)createSm2Base64KeyPair;
+ (NSDictionary<NSString *, NSString *> *_Nullable)createSm2HexKeyPair;
+ (NSDictionary<NSString *, NSData *> *_Nullable)createSm2DataKeyPair;
/**
 SM2 非对称加密算法，加密
 
 @param plaintext       NSString类型待加密明文（UTF-8编码）
        hexPlaintext    NSString类型待加密明文（Hex格式）
        plaintextData   NSData类型待加密明文  （UTF-8编码）
 @param base64PublicKey NSString类型公钥（Base64编码，必须是88字节长度）
        hexPublicKey    NSString类型公钥（Hex格式，必须是128字节长度）
        publicKey       NSData类型公钥  （UTF-8编码，必须是64字节长度）
 @return 返回值：成功则返回密文，分别是：
        NSString类型密文（Base64编码）
        NSString类型密文（Hex格式）
        NSData类型密文  （UTF-8编码）
        密文格式是04标识 + C1C3C2
        失败则返回nil
 */
+ (NSString *_Nullable)sm2EncryptText:(NSString *)plaintext withBase64PublicKey:(NSString *)base64PublicKey;
+ (NSString *_Nullable)sm2EncryptHexText:(NSString *)hexPlaintext withHexPublicKey:(NSString *)hexPublicKey;
+ (NSData *_Nullable)sm2EncryptData:(NSData *)plaintextData withPublicKey:(NSData *)publicKey;

/**
 SM2 非对称加密算法，解密
 
 @param base64Ciphertext NSString类型待解密密文（Base64编码）
        hexCiphertext    NSString类型待解密密文（Hex格式）
        cipherData       NSData类型待解密密文  （UTF-8编码）
        密文格式必须是04标识 + C1C3C2
 @param base64PrivateKey NSString类型私钥（Base64编码，必须是44字节长度）
        hexPrivateKey    NSString类型私钥（Hex格式，必须是64字节长度）
        privateKey       NSData类型私钥  （UTF-8编码，必须是32字节长度）
 @return 返回值：成功则返回明文，分别是：
        NSString类型（UTF-8编码）
        NSString类型（Hex格式）
        NSData类型  （UTF-8编码）
        失败则返回nil
 */
+ (NSString *_Nullable)sm2DecryptText:(NSString *)base64Ciphertext withBase64PrivateKey:(NSString *)base64PrivateKey;
+ (NSString *_Nullable)sm2DecryptHexText:(NSString *)hexCiphertext withHexPrivateKey:(NSString *)hexPrivateKey;
+ (NSData *_Nullable)sm2DecryptData:(NSData *)cipherData withPrivateKey:(NSData *)privateKey;

/**
 SM2 签名验签算法，签名
 
 @param message     NSString类型待签名消息（UTF-8编码）
        hexMessage  NSString类型待签名消息（Hex格式）
        messageData NSData类型待签名消息  （UTF-8编码）
 @param base64PrivateKey NSString类型私钥（Base64编码，必须是44字节长度）
        hexPrivateKey    NSString类型私钥（Hex格式，必须是64字节长度）
        privateKey       NSData类型私钥  （UTF-8编码，必须是32字节长度）
 @return 返回值：成功则返回签名结果，分别是：
         NSString类型签名（Base64编码）
         NSString类型签名（Hex格式）
         NSData类型签名  （UTF-8编码）
         签名结果是R+S组成
         失败则返回nil
 
 */
+ (NSString *_Nullable)sm2SignText:(NSString *)message withBase64PrivateKey:(NSString *)base64PrivateKey;
+ (NSString *_Nullable)sm2SignHexText:(NSString *)hexMessage withHexPrivateKey:(NSString *)hexPrivateKey;
+ (NSData *_Nullable)sm2SignData:(NSData *)messageData withPrivateKey:(NSData *)privateKey;

/**
 SM2 签名验签算法，验签
 
 @param base64Signature NSString类型签名（Base64编码）
        hexSignature    NSString类型签名（Hex格式）
        signatureData   NSData类型签名  （UTF-8编码）
 @param message         NSString类型待签名消息（UTF-8编码）
        hexMessage      NSString类型待签名消息（Hex格式）
        messageData     NSData类型待签名消息  （UTF-8编码）
 @param base64PublicKey NSString类型公钥（Base64编码，必须是88字节长度）
        hexPublicKey    NSString类型公钥（Hex格式，必须是128字节长度）
        publicKey       NSData类型公钥  （UTF-8编码，必须是64字节长度）
 @return 验签结果,YES 表示验签成功,NO 表示验签失败
 */
+ (BOOL)sm2VerifySignature:(NSString *)base64Signature forMessage:(NSString *)message withBase64PublicKey:(NSString *)base64PublicKey;
+ (BOOL)sm2VerifyHexSignature:(NSString *)hexSignature forHexMessage:(NSString *)hexMessage withHexPublicKey:(NSString *)hexPublicKey;
+ (BOOL)sm2VerifySignature:(NSData *)signatureData forData:(NSData *)messageData withPublicKey:(NSData *)publicKey;
@end

NS_ASSUME_NONNULL_END
