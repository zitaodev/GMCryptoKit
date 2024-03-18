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

 @"publicKey"  : SM2公钥（64 字节）,NSData格式
 @"privateKey" : SM2私钥（32 字节）,NSData格式
 @return 密钥对字典 @{NSString : NSData}
 */
+ (NSDictionary<NSString *, NSData *> *_Nullable)gm_createSm2KeyPair;

/**
 SM2 非对称加密
 
 @param plaintextData 待加密的明文,NSData格式
 @param publicKey SM2公钥（64 字节）,NSData格式
 @return 密文(04|c1|c3|c2格式),NSData格式
 */
+ (NSData *_Nullable)gm_sm2EncryptData:(NSData *)plaintextData
                         withPublicKey:(NSData *)publicKey;

/**
 SM2 非对称解密
 
 @param cipherData 密文(04|c1|c3|c2格式),NSData格式
 @param privateKey SM2私钥（32 字节）,NSData格式
 @return 解密后的明文,NSData格式
 */
+ (NSData *_Nullable)gm_sm2DecryptData:(NSData *)cipherData 
                        withPrivateKey:(NSData *)privateKey;

/**
 SM2 数字签名
 
 @param messageData 待签名消息,NSData格式
 @param privateKey SM2私钥（32 字节）,NSData格式
 @return 数字签名(r|s格式,共64 字节,前 32 字节是 r,后 32 字节是 s),NSData格式
 */
+ (NSData *_Nullable)gm_sm2SignData:(NSData *)messageData
                     withPrivateKey:(NSData *)privateKey;

/**
 SM2 验证签名
 
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
