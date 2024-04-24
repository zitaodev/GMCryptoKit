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
@property (nonatomic, copy) NSString *publicKeyHex;  // hex编码公钥
@property (nonatomic, copy) NSString *publicKeyBase64;  // Base64编码公钥
@property (nonatomic, copy) NSData *privateKeyData;  // 私钥
@property (nonatomic, copy) NSString *privateKeyHex;  // hex编码私钥
@property (nonatomic, copy) NSString *privateKeyBase64;  // Base64编码私钥
@property (nonatomic, copy) NSString *plaintext;   // 预置原文,UTF8编码

@end

@implementation GMSm2CryptorTests

- (void)setUp {
    NSDictionary<NSString *, NSData *> *keyPair = [GMSm2Cryptor createSm2DataKeyPair];
    NSDictionary *keyPairHex = [GMSm2Cryptor createSm2HexKeyPair];
    NSDictionary *keyPairBase64 = [GMSm2Cryptor createSm2Base64KeyPair];
    self.publicKeyData = keyPair[@"publicKey"];
    self.publicKeyHex = keyPairHex[@"publicKey"];
    self.publicKeyBase64 = keyPairBase64[@"publicKey"];
    self.privateKeyData = keyPair[@"privateKey"];
    self.privateKeyHex = keyPairHex[@"privateKey"];
    self.privateKeyBase64 = keyPairBase64[@"privateKey"];

    self.plaintext = @"Copyright © 2024 zitaodev. All rights reserved.";
}

- (void)tearDown {
    self.publicKeyBase64 = nil;
    self.publicKeyHex = nil;
    self.publicKeyData = nil;
    self.privateKeyBase64 = nil;
    self.privateKeyHex = nil;
    self.privateKeyData = nil;
    self.plaintext = nil;
}

- (void)testSm2CryptorVerifyTextSignature {
    NSString *message = self.plaintext;
    NSString *publicKeyBase64 = @"EUw3bhAs7CgwdDqsaxd8Uk/H1fv8nXVHPBsb34C59V4/FZ8UccFVYbTUMR2DkuItq1CbIraBXzC+h1D+ctGx+Q==";
    NSString *base64Signature = @"WAnzV4SYV9NNUnETXNliyJUUnrqXl6n4iTkTr1C4dLqkGRyDgWhpGFFrUaFmTplyyOLACYGlAmHS8IzEOh9SIQ==";
    BOOL verified = [GMSm2Cryptor sm2VerifySignature:base64Signature forMessage:message withBase64PublicKey:publicKeyBase64];
    XCTAssertTrue(verified);
}

- (void)testSm2CryptorVerifyHexSignature {
    NSString *hexMessage = @"436F7079726967687420C2A92032303234207A6974616F6465762E20416C6C207269676874732072657365727665642E";
    NSString *publicKeyHex = @"754E175A9AE8F78C59D815E72E154E7C801051248E6396CBE92BE6FD01E40178DE63029DAE984D704FB0BBB6D7D2F16DC3D405BDAF9C082606384F1B34AD5B94";
    NSString *hexSignature = @"9C016281E59E2974BCB22504F5A1A3178D446D86AFD88F88B4459EE305801BF6E0696CF93039F9BD94D33100EDCF5096D02B3976A242AA3DD4705082A66087D4";
    BOOL verified = [GMSm2Cryptor sm2VerifyHexSignature:hexSignature forHexMessage:hexMessage withHexPublicKey:publicKeyHex];
    XCTAssertTrue(verified);
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
    
    BOOL verified = [GMSm2Cryptor sm2VerifySignature:signatureData forData:messageData withPublicKey:publicKeyData];
    XCTAssertTrue(verified);
}

- (void)testSm2CryptorSignText {
    NSString *message = self.plaintext;
    NSString *privateKeyBase64 = @"DdCqRWlr/amjcbxy7E7FbFmBDugw/YG+zLc775mOsw0=";
    NSString *publicKeyBase64 = @"5Ku5d+wdmdX6QfoJAurTkbWN9FzzGKeMEXmprj8ZCFGk2ffFgI3l4w1hxYFMihkiH789LOtjiUMhWM289wpo8Q==";
    NSString *base64Signature = [GMSm2Cryptor sm2SignText:message withBase64PrivateKey:privateKeyBase64];
    BOOL verified = [GMSm2Cryptor sm2VerifySignature:base64Signature forMessage:message withBase64PublicKey:publicKeyBase64];
    XCTAssertNotNil(base64Signature, @"数字签名不能为空");
    XCTAssertTrue(verified);
}

- (void)testSm2CryptorSignHexText {
    NSString *hexMessage = @"436F7079726967687420C2A92032303234207A6974616F6465762E20416C6C207269676874732072657365727665642E";
    NSString *privateKeyHex = @"8E4F3E43CB35F3E716B1AE5770AB8D0790E4C1EE7066105FFAB58EF2CCF9BB2A";
    NSString *publicKeyHex = @"25B15674ED57984BD2A9479EEC054B1E9F7154D102EC732BEF1BA764DA2893134DC6A86B086E14808E1CB57B7484722F99D9C68795BB025BBEE6F23DFBA892DA";
    NSString *hexSignature = [GMSm2Cryptor sm2SignHexText:hexMessage withHexPrivateKey:privateKeyHex];
    BOOL verified = [GMSm2Cryptor sm2VerifyHexSignature:hexSignature forHexMessage:hexMessage withHexPublicKey:publicKeyHex];
    XCTAssertNotNil(hexSignature, @"数字签名不能为空");
    XCTAssertTrue(verified);
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
    
    NSData *signatureData = [GMSm2Cryptor sm2SignData:messageData withPrivateKey:privateKeyData];
    BOOL verified = [GMSm2Cryptor sm2VerifySignature:signatureData forData:messageData withPublicKey:publicKeyData];
    XCTAssertNotNil(signatureData, @"数字签名不能为空");
    XCTAssertTrue(verified);
}

- (void)testSm2CryptorDecryptText {
    NSString *ciphertextBase64Encoded = @"BHuI+J4OdnfXPbfxlabqhXr1pWrVL3f215q2nkhWAR3PI+jktF0VAhMSt/vfjzHCVvDwlJcbR2ok1r3RJCOr4/pk7lBo/Vpdr9jwR2K7hYryFYjpCVcBP02h7n4WkItSMFSqSLElw1mMhv1gpq2CII7S+TgzYlghokR69DOQ0djv9W9PYM8cbymQZ6LsCGq7IA==";
    NSString *expectedPlaintextBase64Encoded = self.plaintext;
    NSString *privateKeyBase64Encoded = @"fVj99dDlyiW4cmfGYu99BggF/THQg0HjSRwp5TpChHw=";
    NSString *decryptedtext = [GMSm2Cryptor sm2DecryptText:ciphertextBase64Encoded withBase64PrivateKey:privateKeyBase64Encoded];
    XCTAssertNotNil(decryptedtext, @"解密结果不能为空");
    XCTAssertEqualObjects(expectedPlaintextBase64Encoded, decryptedtext);
}

- (void)testSm2CryptorDecryptHexText {
    NSString *ciphertextHextext = @"045D4F71A18BEDF762CEF6B7D3FBE8656600C5FC5BE3F302B714379F95FDA00764FAF98D4CFBD56CFE6A51D590AEDBE897945469726C3549758D9C4D7500FC266AADFD08F762DBF507F4D6FC84DB0D2434D1501F710F1862B0F2C1569FB2643E69AD437DC46B6EE9F9C8BDE8EAE5F7BA6697B9CB9B2EAF96692840CF561952772A1A6D47C0FA54189A8F8628D92D32320D";
    NSString *expectedPlaintexthex = @"436F7079726967687420C2A92032303234207A6974616F6465762E20416C6C207269676874732072657365727665642E";
    NSString *privateKeyHex = @"78DD7DA3C55878F18B5B7C5D5543B7E488B0368526DD57F6B96128ED54B96FFB";
    NSString *decryptedHextext = [GMSm2Cryptor sm2DecryptHexText:ciphertextHextext withHexPrivateKey:privateKeyHex];
    XCTAssertNotNil(decryptedHextext, @"解密结果不能为空");
    XCTAssertEqualObjects(expectedPlaintexthex, decryptedHextext);
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
    
    NSData *decryptedData = [GMSm2Cryptor sm2DecryptData:ciphertextData withPrivateKey:privateKeyData];
    XCTAssertNotNil(decryptedData, @"解密结果不能为空");
    XCTAssertEqualObjects(expectedPlaintextData, decryptedData);
}

- (void)testSm2CryptorEncryptText {
    NSString *publicKeyBase64 = @"2XO7NzqPEmDulzWfT2yCiTcY9oRt6ms2sU0aJLk50jQwQ6OBd41d2yxq27z7KJ6ezDr34Qpd+xil2TrgBDz+yg==";
    NSString *privateKeyBase64 = @"flrgprTnt36O0LK/t+ZUDVBDnbPsn1jfjQaJ0iH+RSc=";
    NSString *base64Ciphertext = [GMSm2Cryptor sm2EncryptText:self.plaintext withBase64PublicKey:publicKeyBase64];
    NSString *decryptedtext = [GMSm2Cryptor sm2DecryptText:base64Ciphertext withBase64PrivateKey:privateKeyBase64];
    XCTAssertNotNil(base64Ciphertext, @"密文不能为空");
    XCTAssertEqualObjects(decryptedtext, self.plaintext);
}

- (void)testSm2CryptorEncryptHexText {
    NSString *hexPlaintext = [GMUtilities stringToHexString:self.plaintext];
    assert(hexPlaintext != nil);
    NSString *publicKeyHex = @"978eecac55e81474d0a203e9fd1e95ad1b5852eaf19338313b161825f2615dd958d20ec5173b5ebd5e5c581b0fc59ac13954b2c6017f691ad982464189d2ab10";
    NSString *privateKeyHex = @"2809e8a112dc6aba8430ac6ae3cbf0e3a509e15fb9e71c3d5adb7656ae5a29a3";
    NSString *hexCiphertext = [GMSm2Cryptor sm2EncryptHexText:hexPlaintext withHexPublicKey:publicKeyHex];
    NSString *decryptedHextext = [GMSm2Cryptor sm2DecryptHexText:hexCiphertext withHexPrivateKey:privateKeyHex];
    XCTAssertNotNil(hexCiphertext, @"密文不能为空");
    XCTAssertEqualObjects(decryptedHextext, hexPlaintext);
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
    
    NSData *ciphertextData = [GMSm2Cryptor sm2EncryptData:plaintextData withPublicKey:publicKeyData];
    NSData *expectedPlaintextData = [GMSm2Cryptor sm2DecryptData:ciphertextData withPrivateKey:privateKeyData];
    XCTAssertNotNil(ciphertextData, @"密文不能为空");
    XCTAssertEqualObjects(expectedPlaintextData, plaintextData);
}

- (void)testSm2CryptorCreateBase64KeyPair {
    NSDictionary<NSString *, NSString *> *keyPair = [GMSm2Cryptor createSm2Base64KeyPair];
    NSString *publicKey = keyPair[@"publicKey"];
    NSString *privateKey = keyPair[@"privateKey"];
    XCTAssertNotNil(publicKey, @"生成公钥不能为空");
    XCTAssertNotNil(privateKey, @"生成私钥不能为空");
}

- (void)testSm2CryptorCreateHexKeyPair {
    NSDictionary<NSString *, NSString *> *keyPair = [GMSm2Cryptor createSm2HexKeyPair];
    NSString *publicKey = keyPair[@"publicKey"];
    NSString *privateKey = keyPair[@"privateKey"];
    XCTAssertNotNil(publicKey, @"生成公钥不能为空");
    XCTAssertNotNil(privateKey, @"生成私钥不能为空");
}

- (void)testSm2CryptorCreateKeyPair {
    NSDictionary<NSString *, NSData *> *keyPair = [GMSm2Cryptor createSm2DataKeyPair];
    NSData *publicKey = keyPair[@"publicKey"];
    NSData *privateKey = keyPair[@"privateKey"];
    XCTAssertNotNil(publicKey, @"生成公钥不能为空");
    XCTAssertNotNil(privateKey, @"生成私钥不能为空");
}

- (void)testSm2CryptorThrows {
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wnonnull"
    
    XCTAssertThrows((void) [GMSm2Cryptor sm2VerifySignature:nil forMessage:@"" withBase64PublicKey:@""]);
    XCTAssertThrows((void) [GMSm2Cryptor sm2VerifySignature:@"" forMessage:nil withBase64PublicKey:@""]);
    XCTAssertThrows((void) [GMSm2Cryptor sm2VerifySignature:@"" forMessage:@"" withBase64PublicKey:nil]);
    XCTAssertThrows((void) [GMSm2Cryptor sm2VerifyHexSignature:nil forHexMessage:@"" withHexPublicKey:@""]);
    XCTAssertThrows((void) [GMSm2Cryptor sm2VerifyHexSignature:@"" forHexMessage:nil withHexPublicKey:@""]);
    XCTAssertThrows((void) [GMSm2Cryptor sm2VerifyHexSignature:@"" forHexMessage:@"" withHexPublicKey:nil]);
    XCTAssertThrows((void) [GMSm2Cryptor sm2VerifySignature:nil forData:[NSData data] withPublicKey:[NSData data]]);
    XCTAssertThrows((void) [GMSm2Cryptor sm2VerifySignature:[NSData data] forData:nil withPublicKey:[NSData data]]);
    XCTAssertThrows((void) [GMSm2Cryptor sm2VerifySignature:[NSData data] forData:[NSData data] withPublicKey:nil]);
    XCTAssertThrows((void) [GMSm2Cryptor sm2SignText:nil withBase64PrivateKey:@""]);
    XCTAssertThrows((void) [GMSm2Cryptor sm2SignText:@"" withBase64PrivateKey:nil]);
    XCTAssertThrows((void) [GMSm2Cryptor sm2SignHexText:nil withHexPrivateKey:@""]);
    XCTAssertThrows((void) [GMSm2Cryptor sm2SignHexText:@"" withHexPrivateKey:nil]);
    XCTAssertThrows((void) [GMSm2Cryptor sm2SignData:nil withPrivateKey:[NSData data]]);
    XCTAssertThrows((void) [GMSm2Cryptor sm2SignData:[NSData data] withPrivateKey:nil]);
    XCTAssertThrows((void) [GMSm2Cryptor sm2DecryptText:nil withBase64PrivateKey:@""]);
    XCTAssertThrows((void) [GMSm2Cryptor sm2DecryptText:@"" withBase64PrivateKey:nil]);
    XCTAssertThrows((void) [GMSm2Cryptor sm2DecryptHexText:nil withHexPrivateKey:@""]);
    XCTAssertThrows((void) [GMSm2Cryptor sm2DecryptHexText:@"" withHexPrivateKey:nil]);
    XCTAssertThrows((void) [GMSm2Cryptor sm2DecryptData:nil withPrivateKey:[NSData data]]);
    XCTAssertThrows((void) [GMSm2Cryptor sm2DecryptData:[NSData data] withPrivateKey:nil]);
    XCTAssertThrows((void) [GMSm2Cryptor sm2EncryptText:nil withBase64PublicKey:@""]);
    XCTAssertThrows((void) [GMSm2Cryptor sm2EncryptText:@"" withBase64PublicKey:nil]);
    XCTAssertThrows((void) [GMSm2Cryptor sm2EncryptHexText:nil withHexPublicKey:@""]);
    XCTAssertThrows((void) [GMSm2Cryptor sm2EncryptHexText:@"" withHexPublicKey:nil]);
    XCTAssertThrows((void) [GMSm2Cryptor sm2EncryptData:nil withPublicKey:[NSData data]]);
    XCTAssertThrows((void) [GMSm2Cryptor sm2EncryptData:[NSData data] withPublicKey:nil]);
    #pragma clang diagnostic pop
}

- (void)testPerformanceSm2VerifyText {
    NSString *base64Signature = [GMSm2Cryptor sm2SignText:self.plaintext withBase64PrivateKey:self.privateKeyBase64];
    [self measureBlock:^{
        BOOL isSignatureValid = [GMSm2Cryptor sm2VerifySignature:base64Signature forMessage:self.plaintext withBase64PublicKey:self.publicKeyBase64];
        XCTAssertTrue(isSignatureValid, @"签名验签需成功");
    }];
}

- (void)testPerformanceSm2VerifyHex {
    NSString *hexMessage = [GMUtilities stringToHexString:self.plaintext];
    NSString *hexSignature = [GMSm2Cryptor sm2SignHexText:hexMessage withHexPrivateKey:self.privateKeyHex];
    [self measureBlock:^{
        BOOL isSignatureValid = [GMSm2Cryptor sm2VerifyHexSignature:hexSignature forHexMessage:hexMessage withHexPublicKey:self.publicKeyHex];
        XCTAssertTrue(isSignatureValid, @"签名验签需成功");
    }];
}

- (void)testPerformanceSm2Verify {
    NSData *plaintextData = [self.plaintext dataUsingEncoding:NSUTF8StringEncoding];
    NSData *signatureData = [GMSm2Cryptor sm2SignData:plaintextData withPrivateKey:self.privateKeyData];
    [self measureBlock:^{
        BOOL isSignatureValid = [GMSm2Cryptor sm2VerifySignature:signatureData forData:plaintextData withPublicKey:self.publicKeyData];
        XCTAssertTrue(isSignatureValid, @"签名验签需成功");
    }];
}

- (void)testPerformanceSm2SignText {
    [self measureBlock:^{
        NSString *base64Signature = [GMSm2Cryptor sm2SignText:self.plaintext withBase64PrivateKey:self.privateKeyBase64];
        XCTAssertNotNil(base64Signature, @"数字签名不能为空");
    }];
}

- (void)testPerformanceSm2SignHexText {
    NSString *hexMessage = [GMUtilities stringToHexString:self.plaintext];
    [self measureBlock:^{
        NSString *hexSignature = [GMSm2Cryptor sm2SignHexText:hexMessage withHexPrivateKey:self.privateKeyHex];
        XCTAssertNotNil(hexSignature, @"数字签名不能为空");
    }];
}

- (void)testPerformanceSm2Sign {
    NSData *messageData = [self.plaintext dataUsingEncoding:NSUTF8StringEncoding];
    [self measureBlock:^{
        NSData *signatureData = [GMSm2Cryptor sm2SignData:messageData withPrivateKey:self.privateKeyData];
        XCTAssertNotNil(signatureData, @"数字签名不能为空");
    }];
}

- (void)testPerformanceSm2DecryptText {
    NSString *base64Ciphertext = [GMSm2Cryptor sm2EncryptText:self.plaintext withBase64PublicKey:self.publicKeyBase64];
    [self measureBlock:^{
        NSString *decryptedtext = [GMSm2Cryptor sm2DecryptText:base64Ciphertext withBase64PrivateKey:self.privateKeyBase64];
        XCTAssertNotNil(decryptedtext, @"解密结果不能为空");
    }];
}

- (void)testPerformanceSm2DecryptHexText {
    NSString *plaintextHex = [GMUtilities stringToHexString:self.plaintext];
    NSString *hexCiphertext = [GMSm2Cryptor sm2EncryptHexText:plaintextHex withHexPublicKey:self.publicKeyHex];
    [self measureBlock:^{
        NSString *decryptedHextext = [GMSm2Cryptor sm2DecryptHexText:hexCiphertext withHexPrivateKey:self.privateKeyHex];
        XCTAssertNotNil(decryptedHextext, @"解密结果不能为空");
    }];
}

- (void)testPerformanceSm2Decrypt {
    NSData *plaintextData = [self.plaintext dataUsingEncoding:NSUTF8StringEncoding];
    NSData *ciphertextData = [GMSm2Cryptor sm2EncryptData:plaintextData withPublicKey:self.publicKeyData];
    [self measureBlock:^{
        NSData *decryptedData = [GMSm2Cryptor sm2DecryptData:ciphertextData withPrivateKey:self.privateKeyData];
        XCTAssertNotNil(decryptedData, @"解密结果不能为空");
    }];
}

- (void)testPerformanceSm2EncryptText {
    [self measureBlock:^{
        NSString *ciphertextBase64 = [GMSm2Cryptor sm2EncryptText:self.plaintext withBase64PublicKey:self.publicKeyBase64];
        XCTAssertNotNil(ciphertextBase64, @"密文不能为空");
    }];
}

- (void)testPerformanceSm2EncryptHexText {
    NSString *plaintextHex = [GMUtilities stringToHexString:self.plaintext];
    [self measureBlock:^{
        NSString *ciphertextHex = [GMSm2Cryptor sm2EncryptHexText:plaintextHex
                                                    withHexPublicKey:self.publicKeyHex];
        XCTAssertNotNil(ciphertextHex, @"密文不能为空");
    }];
}

- (void)testPerformanceSm2Encrypt {
    NSData *plaintextData = [self.plaintext dataUsingEncoding:NSUTF8StringEncoding];
    [self measureBlock:^{
        NSData *ciphertextData = [GMSm2Cryptor sm2EncryptData:plaintextData 
                                                   withPublicKey:self.publicKeyData];
        XCTAssertNotNil(ciphertextData, @"密文不能为空");
    }];
}

- (void)testPerformanceSm2Base64KeyPairGenerate {
    [self measureBlock:^{
        NSDictionary<NSString *, NSString *> *keyPair = [GMSm2Cryptor createSm2Base64KeyPair];
        NSString *publicKeyBase64 = keyPair[@"publicKey"];
        NSString *privateKeyBase64 = keyPair[@"privateKey"];
        XCTAssertNotNil(publicKeyBase64, @"生成公钥不能为空");
        XCTAssertNotNil(privateKeyBase64, @"生成私钥不能为空");
    }];
}

- (void)testPerformanceSm2HexKeyPairGenerate {
    [self measureBlock:^{
        NSDictionary<NSString *, NSString *> *keyPair = [GMSm2Cryptor createSm2HexKeyPair];
        NSString *publicKeyHex = keyPair[@"publicKey"];
        NSString *privateKeyHex = keyPair[@"privateKey"];
        XCTAssertNotNil(publicKeyHex, @"生成公钥不能为空");
        XCTAssertNotNil(privateKeyHex, @"生成私钥不能为空");
    }];
}

- (void)testPerformanceSm2KeyPairGenerate {
    [self measureBlock:^{
        NSDictionary<NSString *, NSData *> *keyPair = [GMSm2Cryptor createSm2DataKeyPair];
        NSData *publicKeyData = keyPair[@"publicKey"];
        NSData *privateKeyData = keyPair[@"privateKey"];
        XCTAssertNotNil(publicKeyData, @"生成公钥不能为空");
        XCTAssertNotNil(privateKeyData, @"生成私钥不能为空");
    }];
}
@end
