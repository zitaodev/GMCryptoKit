//
//  GMSm2CryptorTests.m
//  GMCryptoKitTests
//
//  Created by zitaodev's Laptop on 2024/3/20.
//  Copyright © 2024 zitaodev. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "GMCryptoKit.h"

@interface GMSm2CryptorTests : XCTestCase

@property (nonatomic, copy) NSData *publicKeyData;  // 公钥
@property (nonatomic, copy) NSData *privateKeyData;  // 私钥
@property (nonatomic, copy) NSString *plaintext;   // 预置原文,UTF8编码

@end

@implementation GMSm2CryptorTests

- (void)setUp {
    NSDictionary<NSString *, NSData *> *keyPair = [GMSm2Cryptor gm_createSm2DataKeyPair];
    self.publicKeyData = keyPair[@"publicKey"];
    self.privateKeyData = keyPair[@"privateKey"];
    self.plaintext = @"Copyright © 2024 zitaodev. All rights reserved.";
}

- (void)tearDown {
    self.publicKeyData = nil;
    self.privateKeyData = nil;
    self.plaintext = nil;
}

- (void)testSm2CryptorVerify {
    NSString *signatureBase64Encoded = @"vGjT917K2USb7MgRqDofqtj6FoQ0WQNEeVjujp5Ewaixedcp5Z8/6Hq3X7seOordfh5eRp2TKIE54UPQtYGSIQ==";
    NSData *signatureData = [[NSData alloc] initWithBase64EncodedString:signatureBase64Encoded options:NSDataBase64DecodingIgnoreUnknownCharacters];
    assert(signatureData != nil);
    
    NSString *messageBase64Encoded = @"Q29weXJpZ2h0IMKpIDIwMjQgeml0YW9kZXYuIEFsbCByaWdodHMgcmVzZXJ2ZWQu";
    NSData *messageData = [[NSData alloc] initWithBase64EncodedString:messageBase64Encoded options:NSDataBase64DecodingIgnoreUnknownCharacters];
    assert(messageData != nil);
    
    NSString *publicKeyBase64Encoded = @"R4jRhNXfGj7Pdlic0Xx29gHyPDJZgaHUc7ti428eTV4Jba/u/cKJIqDo+/5wsMUrsao0qge86dhpwZGr3vBMlw==";
    NSData *publicKeyData = [[NSData alloc] initWithBase64EncodedString:publicKeyBase64Encoded options:NSDataBase64DecodingIgnoreUnknownCharacters];
    assert(publicKeyData != nil);
    
    NSInteger numberOfVerify = 10;
    NSInteger expectedNumberOfVerify = 0;
    for (NSInteger i = 0; i < numberOfVerify; i++) {
        BOOL verified = [GMSm2Cryptor gm_sm2VerifySignature:signatureData forData:messageData withPublicKey:publicKeyData];
        if (verified) {
            expectedNumberOfVerify += 1;
        }
    }
    XCTAssertEqual(expectedNumberOfVerify, numberOfVerify);
}

- (void)testSm2CryptorSign {
    NSString *messageBase64Encoded = @"Q29weXJpZ2h0IMKpIDIwMjQgeml0YW9kZXYuIEFsbCByaWdodHMgcmVzZXJ2ZWQu";
    NSData *messageData = [[NSData alloc] initWithBase64EncodedString:messageBase64Encoded options:NSDataBase64DecodingIgnoreUnknownCharacters];
    assert(messageData != nil);
    
    NSString *privateKeyBase64Encoded = @"LN1NxeDJkxTPWrMLjGKP4FUV8Jk7FnbI+6VAGEI0akE=";
    NSData *privateKeyData = [[NSData alloc] initWithBase64EncodedString:privateKeyBase64Encoded options:NSDataBase64DecodingIgnoreUnknownCharacters];
    assert(privateKeyData != nil);
    
    NSString *publicKeyBase64Encoded = @"R4jRhNXfGj7Pdlic0Xx29gHyPDJZgaHUc7ti428eTV4Jba/u/cKJIqDo+/5wsMUrsao0qge86dhpwZGr3vBMlw==";
    NSData *publicKeyData = [[NSData alloc] initWithBase64EncodedString:publicKeyBase64Encoded options:NSDataBase64DecodingIgnoreUnknownCharacters];
    assert(publicKeyData != nil);
    
    NSData *signatureData = [GMSm2Cryptor gm_sm2SignData:messageData withPrivateKey:privateKeyData];
    BOOL verified = [GMSm2Cryptor gm_sm2VerifySignature:signatureData forData:messageData withPublicKey:publicKeyData];
    XCTAssertNotNil(signatureData, @"数字签名不能为空");
    XCTAssertTrue(verified);
}

- (void)testSm2CryptorDecryption {
    NSString *ciphertextBase64Encoded = @"BNnruW8h3W/tVqCq2FHEk3ebJzDPJlyCmo8Rl29vBUFLIEze84byulYgYr0QiCbKHzhNKMQISS4RLkmc08KJI2lm8uPa1uCDwmdzTlUXlZE3RB8UFQZIGx9oeiyqAxc0/hsMnWxBbpfXlsYkuc1tmsnJnZSbgfGc3w89og4x4c2PgFI0BFnPyJOFXCSu+U8Phw==";
    NSData *ciphertextData = [[NSData alloc] initWithBase64EncodedString:ciphertextBase64Encoded options:NSDataBase64DecodingIgnoreUnknownCharacters];
    assert(ciphertextData != nil);
    
    NSString *expectedPlaintextBase64Encoded = @"Q29weXJpZ2h0IMKpIDIwMjQgeml0YW9kZXYuIEFsbCByaWdodHMgcmVzZXJ2ZWQu";
    NSData *expectedPlaintextData = [[NSData alloc] initWithBase64EncodedString:expectedPlaintextBase64Encoded options:NSDataBase64DecodingIgnoreUnknownCharacters];
    assert(expectedPlaintextData != nil);
    
    NSString *privateKeyBase64Encoded = @"B/Jzqosa4yP5XokYm8PGBv8dlytA8+U8J+bhYPAvphU=";
    NSData *privateKeyData = [[NSData alloc] initWithBase64EncodedString:privateKeyBase64Encoded options:NSDataBase64DecodingIgnoreUnknownCharacters];
    assert(privateKeyData != nil);
    
    NSData *decryptedData = [GMSm2Cryptor gm_sm2DecryptData:ciphertextData withPrivateKey:privateKeyData];
    XCTAssertNotNil(decryptedData, @"解密结果不能为空");
    XCTAssertEqualObjects(expectedPlaintextData, decryptedData);
}

- (void)testSm2CryptorEncryption {
    NSString *plaintextBase64Encoded = @"Q29weXJpZ2h0IMKpIDIwMjQgeml0YW9kZXYuIEFsbCByaWdodHMgcmVzZXJ2ZWQu";
    NSData *plaintextData = [[NSData alloc] initWithBase64EncodedString:plaintextBase64Encoded options:NSDataBase64DecodingIgnoreUnknownCharacters];
    assert(plaintextData != nil);
    
    NSString *publicKeyBase64Encoded = @"ASirRBCIT3J8xh54QzzVTSLnvWUBnYBu2unap+ppT8CybCkO/xqBdq6blrdTgjfGg+S2jZy51LwOkULLeY2KDw==";
    NSData *publicKeyData = [[NSData alloc] initWithBase64EncodedString:publicKeyBase64Encoded options:NSDataBase64DecodingIgnoreUnknownCharacters];
    assert(publicKeyData != nil);
    
    NSString *privateKeyBase64Encoded = @"B/Jzqosa4yP5XokYm8PGBv8dlytA8+U8J+bhYPAvphU=";
    NSData *privateKeyData = [[NSData alloc] initWithBase64EncodedString:privateKeyBase64Encoded options:NSDataBase64DecodingIgnoreUnknownCharacters];
    assert(privateKeyData != nil);
    
    NSData *ciphertextData = [GMSm2Cryptor gm_sm2EncryptData:plaintextData withPublicKey:publicKeyData];
    NSData *expectedPlaintextData = [GMSm2Cryptor gm_sm2DecryptData:ciphertextData withPrivateKey:privateKeyData];
    XCTAssertNotNil(ciphertextData, @"密文不能为空");
    XCTAssertEqualObjects(expectedPlaintextData, plaintextData);
}

- (void)testSm2CryptorCreateKeyPair {
    NSDictionary<NSString *, NSData *> *keyPair = [GMSm2Cryptor gm_createSm2DataKeyPair];
    NSData *publicKey = keyPair[@"publicKey"];
    NSData *privateKey = keyPair[@"privateKey"];
    XCTAssertNotNil(publicKey, @"生成公钥不能为空");
    XCTAssertNotNil(privateKey, @"生成私钥不能为空");
}

- (void)testSm2CryptorThrows {
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wnonnull"
    XCTAssertThrows((void) [GMSm2Cryptor gm_sm2VerifySignature:nil forData:[NSData data] withPublicKey:[NSData data]]);
    XCTAssertThrows((void) [GMSm2Cryptor gm_sm2VerifySignature:[NSData data] forData:nil withPublicKey:[NSData data]]);
    XCTAssertThrows((void) [GMSm2Cryptor gm_sm2VerifySignature:[NSData data] forData:[NSData data] withPublicKey:nil]);
    XCTAssertThrows((void) [GMSm2Cryptor gm_sm2SignData:nil withPrivateKey:[NSData data]]);
    XCTAssertThrows((void) [GMSm2Cryptor gm_sm2SignData:[NSData data] withPrivateKey:nil]);
    XCTAssertThrows((void) [GMSm2Cryptor gm_sm2DecryptData:nil withPrivateKey:[NSData data]]);
    XCTAssertThrows((void) [GMSm2Cryptor gm_sm2DecryptData:[NSData data] withPrivateKey:nil]);
    XCTAssertThrows((void) [GMSm2Cryptor gm_sm2EncryptData:nil withPublicKey:[NSData data]]);
    XCTAssertThrows((void) [GMSm2Cryptor gm_sm2EncryptData:[NSData data] withPublicKey:nil]);
    #pragma clang diagnostic pop
}

- (void)testPerformanceSm2Verify {
    NSData *plaintextData = [self.plaintext dataUsingEncoding:NSUTF8StringEncoding];
    NSData *signatureData = [GMSm2Cryptor gm_sm2SignData:plaintextData withPrivateKey:self.privateKeyData];
    [self measureBlock:^{
        BOOL isSignatureValid = [GMSm2Cryptor gm_sm2VerifySignature:signatureData forData:plaintextData withPublicKey:self.publicKeyData];
        XCTAssertTrue(isSignatureValid, @"签名验签需成功");
    }];
}

- (void)testPerformanceSm2Sign {
    NSData *plaintextData = [self.plaintext dataUsingEncoding:NSUTF8StringEncoding];
    [self measureBlock:^{
        NSData *signatureData = [GMSm2Cryptor gm_sm2SignData:plaintextData withPrivateKey:self.privateKeyData];
        XCTAssertNotNil(signatureData, @"数字签名不能为空");
    }];
}

- (void)testPerformanceSm2Decrypt {
    NSData *plaintextData = [self.plaintext dataUsingEncoding:NSUTF8StringEncoding];
    NSData *ciphertextData = [GMSm2Cryptor gm_sm2EncryptData:plaintextData withPublicKey:self.publicKeyData];
    
    [self measureBlock:^{
        NSData *decryptedData = [GMSm2Cryptor gm_sm2DecryptData:ciphertextData withPrivateKey:self.privateKeyData];
        XCTAssertNotNil(decryptedData, @"解密结果不能为空");
    }];
}

- (void)testPerformanceSm2Encrypt {
    NSData *plaintextData = [self.plaintext dataUsingEncoding:NSUTF8StringEncoding];
    [self measureBlock:^{
        NSData *ciphertextData = [GMSm2Cryptor gm_sm2EncryptData:plaintextData withPublicKey:self.publicKeyData];
        XCTAssertNotNil(ciphertextData, @"密文不能为空");
    }];
}

- (void)testPerformanceSm2KeyPairGenerate {
    [self measureBlock:^{
        NSDictionary<NSString *, NSData *> *keyPair = [GMSm2Cryptor gm_createSm2DataKeyPair];
        NSData *publicKeyData = keyPair[@"publicKey"];
        NSData *privateKeyData = keyPair[@"privateKey"];
        XCTAssertNotNil(publicKeyData, @"生成公钥不能为空");
        XCTAssertNotNil(privateKeyData, @"生成私钥不能为空");
    }];
}
@end
