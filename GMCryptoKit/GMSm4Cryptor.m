//
//  GMSm4Cryptor.m
//  GMCryptoKit
//
//  Created by zitaodev's Laptop on 2024/3/26.
//  Copyright © 2024 zitaodev. All rights reserved.
//

#import "GMSm4Cryptor.h"
#import "GMRandomGenerator.h"
#import <gmssl/sm4.h>
@implementation GMSm4Cryptor

+ (NSData *_Nullable)gm_createSm4Key {
    return [GMRandomGenerator gm_secRandomDataWithLength:SM4_KEY_SIZE];
}


@end
