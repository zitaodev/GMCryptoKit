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
 SM3 提取摘要
 
 @param plaintextData 待提取摘要数据,NSData格式
 @return 摘要值(32字节),NSData格式
 */
+ (NSData *_Nullable)gm_sm3DigestWithData:(NSData *)plaintextData;
@end

NS_ASSUME_NONNULL_END
