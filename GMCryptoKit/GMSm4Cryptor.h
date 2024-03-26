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
@end

NS_ASSUME_NONNULL_END
