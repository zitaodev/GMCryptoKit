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
 SM3 计算摘要
 
 @param plaintextData 待计算的消息明文,NSData格式
 @return 计算后的摘要值,NSData格式
 */
+ (NSData *_Nullable)gm_sm3DigestWithData:(NSData *)plaintextData;

/**
 基于SM3算法的HMAC计算
 
 @param plaintextData 待计算的消息明文,NSData格式
 @param keyData 密钥,NSData格式
 @return 计算后的摘要值,NSData格式
 */
+ (NSData *_Nullable)gm_hmacSm3DigestWithData:(NSData *)plaintextData keyData:(NSData *)keyData;
@end

NS_ASSUME_NONNULL_END
