//
//  GMUtilities.m
//  GMCryptoKit
//
//  Created by Joe's Laptop on 2024/4/15.
//  Copyright © 2024 zitaodev. All rights reserved.
//

#import "GMUtilities.h"

@implementation GMUtilities

+ (NSData *_Nullable)base64StringToData:(NSString *)base64String {
    if (![base64String isKindOfClass:[NSString class]] || base64String.length == 0) {
        return nil;
    }
    return [[NSData alloc] initWithBase64EncodedString:base64String options:0];;
}

+ (NSString *_Nullable)dataToBase64String:(NSData *)data {
    NSString *encodingString = nil;
    if ([data isKindOfClass:[NSData class]]) {
        NSData *base64Data = [data base64EncodedDataWithOptions:0];
        if (base64Data) {
            encodingString = [[NSString alloc] initWithData:base64Data encoding:NSUTF8StringEncoding];
        }
    }
    return encodingString;
}

+ (NSData *_Nullable)stringToData:(NSString *)string {
    NSString *hexString = [self stringToHexString:string];
    return [self hexStringToData:hexString];
}

+ (NSString *_Nullable)hexStringToString:(NSString *)hexString {
    if (!hexString || hexString.length == 0) {
        return nil;
    }
    
    char *myBuffer = (char *)malloc((int)hexString.length / 2 + 1);
    bzero(myBuffer, hexString.length / 2 + 1);
    for (int i = 0; i < [hexString length] - 1; i += 2) {
        unsigned int anInt;
        NSString * hexCharStr = [hexString substringWithRange:NSMakeRange(i, 2)];
        NSScanner * scanner = [[NSScanner alloc] initWithString:hexCharStr];
        [scanner scanHexInt:&anInt];
        myBuffer[i / 2] = (char)anInt;
    }
    NSString *unicodeString = [NSString stringWithCString:myBuffer encoding:NSUTF8StringEncoding];
    return unicodeString;
}

+ (NSString *_Nullable)stringToHexString:(NSString *)string {
    if (!string || string.length == 0) {
        return nil;
    }
    
    NSData *data = [string dataUsingEncoding:NSUTF8StringEncoding];
    Byte *bytes = (Byte *)[data bytes];
    NSString *hexString = @"";
    for(int i = 0; i < [data length]; i++) {
        NSString *newHexString = [NSString stringWithFormat:@"%x",bytes[i]&0xff];
        if([newHexString length] == 1) {
            hexString = [NSString stringWithFormat:@"%@0%@",hexString,newHexString];
        }else{
            hexString = [NSString stringWithFormat:@"%@%@",hexString,newHexString];
        }
    }
    return hexString;
}

+ (NSData *_Nullable)hexStringToData:(NSString *)hexString {
    if (!hexString || hexString.length == 0) {
        return nil;
    }
    const char *chars = [hexString UTF8String];
    NSInteger i = 0, len = hexString.length;
    
    NSMutableData *data = [NSMutableData dataWithCapacity:len / 2];
    char byteChars[3] = {'\0','\0','\0'};
    unsigned long wholeByte;
    
    while (i < len) {
        byteChars[0] = chars[i++];
        byteChars[1] = chars[i++];
        wholeByte = strtoul(byteChars, NULL, 16);
        [data appendBytes:&wholeByte length:1];
    }
    return data;
}

+ (NSString *_Nullable)dataToHexString:(NSData *)data {
    if (!data || data.length == 0) {
        return nil;
    }
    
    NSMutableString *hexString = [NSMutableString string];
    unsigned char *bytes = (unsigned char *)data.bytes;
    NSUInteger bytesLength = data.length;
    
    for (int i = 0; i < bytesLength; i += 1) {
        unsigned char byte = bytes[i];
        [hexString appendFormat:@"%02X", byte];
    }
    return [hexString copy];
}

@end
