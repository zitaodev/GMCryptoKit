//
//  GMRandomGenerator.h
//  GMCryptoKit
//
//  Created by zitaodev's Laptop on 2024/3/15.
//  Copyright © 2024 zitaodev. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface GMRandomGenerator : NSObject

/**
 生成指定字节长度的加密安全随机数
 
 @param length 指定的随机数长度
 @return 填充指定字节长度的NSData格式随机数
 */
+ (NSData *_Nullable)gm_secRandomDataWithLength:(NSUInteger)length;
@end

NS_ASSUME_NONNULL_END
