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
 SM2 生成密钥对

 @return 密钥(16字节),NSData格式
 */
+ (NSData *_Nullable)gm_createSm4Key;

/**
 SM4 对称加解密。CBC模式加密，使用PKCS#7填充标准
 
 @param plaintextData 待加密的明文,NSData格式
 @param key 密钥（16 字节）,NSData格式
 @param iv 初始化向量,NSData格式
 @return 密文,NSData格式
 */
+ (NSData *_Nullable)gm_sm4CbcPaddingEncryptData:(NSData *)plaintextData
                                         withKey:(NSData *)key
                                          withIv:(NSData *)iv;

/**
 SM4 对称加解密。CBC模式解密，使用PKCS#7填充标准
 
 @param cipherData 密文,NSData格式
 @param key 密钥（16 字节）,NSData格式
 @param iv 初始化向量,NSData格式
 @return 解密后的明文,NSData格式
 */
+ (NSData *_Nullable)gm_sm4CbcPaddingDecryptData:(NSData *)cipherData
                                         withKey:(NSData *)key
                                          withIv:(NSData *)iv;

@end

NS_ASSUME_NONNULL_END
