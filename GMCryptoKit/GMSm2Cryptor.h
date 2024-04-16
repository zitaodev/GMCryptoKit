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
 
 密钥对数据类型说明如下：
 SM2公钥: NSString类型（Base64编码，88字节长度）；NSString类型（Hex格式，128字节长度）；NSData类型（UTF-8编码，64字节长度）
 SM2私钥: NSString类型（Base64编码，44字节长度）；NSString类型（Hex格式，64字节长度）；NSData类型（UTF-8编码，32字节长度）
 @return 返回值：成功则返回密钥对字典实例 @{@"publicKey" : SM2公钥, @"privateKey" : SM2私钥}，失败则返回nil
 */
+ (NSDictionary<NSString *, NSString *> *_Nullable)gm_createSm2KeyPairBase64;
+ (NSDictionary<NSString *, NSString *> *_Nullable)gm_createSm2KeyPairHex;
+ (NSDictionary<NSString *, NSData *> *_Nullable)gm_createSm2KeyPairData;

/**
 SM2 非对称加密算法，加密
 
 @param plaintext NSString类型待加密明文（UTF-8编码）；hexPlaintext NSString类型待加密明文（Hex格式）；plaintextData NSData类型待加密明文（UTF-8编码）
 @param base64PublicKey NSString类型公钥（Base64编码，必须是88字节长度）；hexPublicKey NSString类型（Hex格式，必须是128字节长度）；publicKey NSData类型（UTF-8编码，64字节长度）
 @return 返回值：成功则返回密文，分别是：NSString类型（Base64编码）、NSString类型（Hex格式）、NSData类型（UTF-8编码），密文格式是04标识 + C1C3C2；失败则返回nil
 */
+ (NSString *_Nullable)gm_sm2EncryptText:(NSString *)plaintext
                     withBase64PublicKey:(NSString *)base64PublicKey;
+ (NSString *_Nullable)gm_sm2EncryptHexText:(NSString *)hexPlaintext
                           withHexPublicKey:(NSString *)hexPublicKey;
+ (NSData *_Nullable)gm_sm2EncryptData:(NSData *)plaintextData
                         withPublicKey:(NSData *)publicKey;

/**
 SM2 非对称加密算法，解密
 
 @param base64Ciphertext NSString类型待解密密文（Base64编码）；hexCiphertext NSString类型待解密密文（Hex格式）；cipherData NSData类型待解密密文（UTF-8编码），密文格式必须是04标识 + C1C3C2
 @param base64PrivateKey NSString类型私钥（Base64编码，必须是44字节长度）；hexPrivateKey NSString类型（Hex格式，必须是64字节长度）；privateKey NSData类型（UTF-8编码，32字节长度）
 @return 返回值：成功则返回明文，分别是：NSString类型（UTF-8编码）、NSString类型（Hex格式）、NSData类型（UTF-8编码）；失败则返回nil
 */
+ (NSString *_Nullable)gm_sm2DecryptText:(NSString *)base64Ciphertext
                    withBase64PrivateKey:(NSString *)base64PrivateKey;
+ (NSString *_Nullable)gm_sm2DecryptHexText:(NSString *)hexCiphertext
                          withHexPrivateKey:(NSString *)hexPrivateKey;
+ (NSData *_Nullable)gm_sm2DecryptData:(NSData *)cipherData
                        withPrivateKey:(NSData *)privateKey;

/**
 SM2 签名验签算法，签名
 
 @param messageData 待签名消息,NSData格式
 @param privateKey SM2私钥（32 字节）,NSData格式
 @return 数字签名(r|s格式,共64 字节,前 32 字节是 r,后 32 字节是 s),NSData格式
 */
+ (NSData *_Nullable)gm_sm2SignData:(NSData *)messageData
                     withPrivateKey:(NSData *)privateKey;

/**
 SM2 签名验签算法，验签
 
 @param signatureData 数字签名(r|s格式,共64 字节,前 32 字节是 r,后 32 字节是 s),NSData格式
 @param messageData 待签名消息,NSData格式
 @param publicKey SM2公钥（64 字节）,NSData格式
 @return 验签结果,YES 表示验签成功,NO 表示验签失败
 */
+ (BOOL)gm_sm2VerifySignature:(NSData *)signatureData
                      forData:(NSData *)messageData
                withPublicKey:(NSData *)publicKey;
@end

NS_ASSUME_NONNULL_END
