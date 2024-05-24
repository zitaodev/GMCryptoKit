//
//  GMUtilities.h
//  GMCryptoKit
//
//  Created by zitaodev's Laptop on 2024/4/15.
//  Copyright © 2024 zitaodev. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface GMUtilities : NSObject

/**
 十六进制编码的字符串转换为对应的二进制数据

 @return UTF-8编码二进制数据
 */
+ (NSData *_Nullable)hexStringToData:(NSString *)hexString;

/**
 二进制数据转换为对应的十六进制编码的字符串

 @return 十六进制编码的字符串
 */
+ (NSString *_Nullable)dataToHexString:(NSData *)data;

/**
 UTF-8编码字符串转换为对应的十六进制数据的字符串

 @return 十六进制数据的字符串
 */
+ (NSString *_Nullable)stringToHexString:(NSString *)string;

/**
 十六进制数据的字符串转换为对应的UTF-8编码字符串

 @return UTF-8编码字符串
 */
+ (NSString *_Nullable)hexStringToString:(NSString *)hexString;

/**
 UTF-8编码字符串转换为对应的二进制数据

 @return UTF-8编码二进制数据
 */
+ (NSData *_Nullable)stringToData:(NSString *)string;

/**
 二进制数据转换为对应的Base64编码的字符串

 @return Base64编码的字符串
 */
+ (NSString *_Nullable)dataToBase64String:(NSData *)data;

/**
 Base64编码字符串转换为对应的二进制数据

 @return UTF-8编码二进制数据
 */
+ (NSData *_Nullable)base64StringToData:(NSString *)base64String;
@end

NS_ASSUME_NONNULL_END
