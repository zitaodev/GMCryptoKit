//
//  ViewController.m
//  GMCryptoKit
//
//  Created by zitaodev's Laptop on 2024/3/14.
//

#import "ViewController.h"
#import <GMCryptoKit/GMCryptoKit.h>

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor whiteColor];
    
    NSMutableString *logStr = [NSMutableString stringWithString:@""];
    // ---------------------- 1、生成随机数 ----------------------
    NSData *randomData = [GMRandomGenerator secRandomDataWithLength:16];
    [logStr appendString:@"\n-------安全随机数-------"];
    [logStr appendFormat:@"\n随机数：%@", randomData];
    
    // ---------------------- 2、生成SM2密钥对 ----------------------
    NSDictionary *keyPairData = [GMSm2Cryptor createSm2DataKeyPair];
    NSDictionary *keyPairHex = [GMSm2Cryptor createSm2HexKeyPair];
    NSDictionary *keyPairBase64 = [GMSm2Cryptor createSm2Base64KeyPair];
    NSString     *publicKeyBase64 = keyPairBase64[@"publicKey"];
    NSString     *publicKeyHex = keyPairHex[@"publicKey"];
    NSData       *publicKey = keyPairData[@"publicKey"];
    NSString     *privateKeyBase64 = keyPairBase64[@"privateKey"];
    NSString     *privateKeyHex = keyPairHex[@"privateKey"];
    NSData       *privateKey = keyPairData[@"privateKey"];
    [logStr appendString:@"\n-------SM2密钥对-------"];
    [logStr appendFormat:@"\nBase64公钥：%@", publicKeyBase64];
    [logStr appendFormat:@"\nBase64私钥：%@", privateKeyBase64];
    [logStr appendFormat:@"\nHex公钥：%@", publicKeyHex];
    [logStr appendFormat:@"\nHex私钥：%@", privateKeyHex];
    [logStr appendFormat:@"\n公钥：%@", publicKey];
    [logStr appendFormat:@"\n私钥：%@", privateKey];
    
    // ---------------------- 3、SM2加密和解密 ----------------------
    NSString *plaintext = @"sm2 encrypt text: Copyright © 2024 zitaodev. All rights reserved.";
    NSString *hexPlaintext = [GMUtilities stringToHexString:plaintext];
    NSData   *plaintextData = [plaintext dataUsingEncoding:NSUTF8StringEncoding];
    
    NSString *base64Ciphertext = [GMSm2Cryptor sm2EncryptText:plaintext withPublicKey:publicKeyHex];
    NSString *hexCiphertext =    [GMSm2Cryptor sm2EncryptHexText:hexPlaintext withPublicKey:publicKeyHex];
    NSData   *ciphertextData =     [GMSm2Cryptor sm2EncryptData:plaintextData withPublicKey:publicKey];
    
    NSString *decryptedtext =    [GMSm2Cryptor sm2DecryptText:base64Ciphertext withPrivateKey:privateKeyHex];
    NSString *decryptedHextext = [GMSm2Cryptor sm2DecryptHexText:hexCiphertext withPrivateKey:privateKeyHex];
    NSData   *decryptedData =      [GMSm2Cryptor sm2DecryptData:ciphertextData withPrivateKey:privateKey];
    if ([plaintext isEqualToString:decryptedtext] && [hexPlaintext isEqualToString:decryptedHextext] && [plaintextData isEqualToData:decryptedData]) {
        NSLog(@"SM2加密和解密成功");
    }else {
        NSLog(@"SM2加密和解密失败");
    }
    [logStr appendString:@"\n-------SM2加密和解密-------"];
    [logStr appendFormat:@"\nSM2明文：%@", plaintext];
    [logStr appendFormat:@"\nSM2加密密文：%@", base64Ciphertext];
    [logStr appendFormat:@"\nSM2解密结果：%@", decryptedtext];
    
    // ---------------------- 4、SM2数字签名和验证 ----------------------
    NSString *message = @"sm2 sign text: Copyright © 2024 zitaodev. All rights reserved.";
    
    NSString *hexMessage = [GMUtilities stringToHexString:message];
    NSData   *messageData = [message dataUsingEncoding:NSUTF8StringEncoding];
    NSString *base64Signature = [GMSm2Cryptor sm2SignText:message withPrivateKey:privateKeyHex];
    NSString *hexSignature = [GMSm2Cryptor sm2SignHexText:hexMessage withPrivateKey:privateKeyHex];
    NSData   *signatureData = [GMSm2Cryptor sm2SignData:messageData withPrivateKey:privateKey];
    
    BOOL isBase64SignatureValid = [GMSm2Cryptor sm2VerifyText:base64Signature forMessage:message withPublicKey:publicKeyHex];
    BOOL isHexSignatureValid = [GMSm2Cryptor sm2VerifyHexText:hexSignature forMessageHex:hexMessage withPublicKey:publicKeyHex];
    BOOL isSignatureValid = [GMSm2Cryptor sm2VerifyData:signatureData forMessageData:messageData withPublicKey:publicKey];
    if (isBase64SignatureValid && isHexSignatureValid && isSignatureValid) {
        NSLog(@"SM2签名验签成功");
    }else {
        NSLog(@"SM2签名验签失败");
    }
    [logStr appendString:@"\n-------SM2数字签名和验证-------"];
    [logStr appendFormat:@"\nSM2签名消息：%@", messageData];
    [logStr appendFormat:@"\nSM2公钥：%@", publicKey];
    [logStr appendFormat:@"\nSM2私钥：%@", privateKey];
    [logStr appendFormat:@"\nSM2数字签名：%@", signatureData];
    [logStr appendFormat:@"\nSM2验签结果：%@", @(isSignatureValid)];
    
    
    // ---------------------- 5、SM3提取摘要 ----------------------
    NSString *sm3message = @"sm3 digest text: Copyright © 2024 zitaodev. All rights reserved.";
    [logStr appendString:@"\n-------SM3提取摘要-------"];
    [logStr appendFormat:@"\nSM3消息明文：%@", sm3message];
    // 5.1 UTF-8编码字符串的摘要提取
    NSString *sm3Digest = [GMSm3Digest sm3DigestWithText:sm3message];
    if (sm3Digest) {
        NSLog(@"Sm3 UTF-8编码字符串的摘要提取成功");
    }else {
        NSLog(@"Sm3 UTF-8编码字符串的摘要提取失败");
    }
    [logStr appendFormat:@"\nSM3摘要Base64提取结果：%@", sm3Digest];
    // 5.2 Hex编码字符串的摘要提取
    NSString *sm3messageHex = [GMUtilities stringToHexString:sm3message];
    sm3Digest = [GMSm3Digest sm3DigestWithHexText:sm3messageHex];
    if (sm3Digest) {
        NSLog(@"Sm3 Hex编码字符串的摘要提取成功");
    }else {
        NSLog(@"Sm3 Hex编码字符串的摘要提取失败");
    }
    [logStr appendFormat:@"\nSM3摘要Hex提取结果：%@", sm3Digest];
    // 7.3 二进制数据的摘要提取
    NSData *sm3messageData = [GMUtilities stringToData:sm3message];
    NSData *sm3DigestData = [GMSm3Digest sm3DigestWithData:sm3messageData];
    if (sm3DigestData) {
        NSLog(@"Sm3 二进制数据的摘要提取成功");
    }else {
        NSLog(@"Sm3 二进制数据的摘要提取失败");
    }
    [logStr appendFormat:@"\nSM3摘要二进制提取结果：%@", sm3DigestData];
    
    
    // ---------------------- 6、基于SM3计算HMAC ----------------------
    NSString *sm3HmacMessage = @"sm3 hmac text: Copyright © 2024 zitaodev. All rights reserved.";
    NSData *hmacKeyData = [GMRandomGenerator secRandomDataWithLength:32];
    NSString *hmacKey = [GMUtilities dataToHexString:hmacKeyData];
    [logStr appendString:@"\n-------基于SM3计算HMAC-------"];
    [logStr appendFormat:@"\nhmacSm3消息明文：%@", sm3HmacMessage];
    // 6.1 UTF-8编码字符串的HMAC计算
    NSString *sm3Hmac = [GMSm3Digest hmacSm3DigestWithText:sm3HmacMessage key:hmacKey];
    if (sm3Hmac) {
        NSLog(@"Sm3 UTF-8编码字符串的HMAC计算成功");
    }else {
        NSLog(@"Sm3 UTF-8编码字符串的HMAC计算失败");
    }
    [logStr appendFormat:@"\nSM3 HMAC计算Base64结果：%@", sm3Hmac];
    // 6.2 Hex编码字符串的HMAC计算
    NSString *sm3HmacMessageHex = [GMUtilities stringToHexString:sm3HmacMessage];
    sm3Hmac = [GMSm3Digest hmacSm3DigestWithText:sm3HmacMessageHex key:hmacKey];
    if (sm3Hmac) {
        NSLog(@"Sm3 Hex编码字符串的HMAC计算成功");
    }else {
        NSLog(@"Sm3 Hex编码字符串的HMAC计算失败");
    }
    [logStr appendFormat:@"\nSM3 HMAC计算Hex结果：%@", sm3Hmac];
    // 6.3 二进制数据的HMAC计算
    NSData *sm3HmacMessageData = [GMUtilities stringToData:sm3HmacMessage];
    NSData *hmacData = [GMSm3Digest hmacSm3DigestWithData:sm3HmacMessageData key:hmacKeyData];
    if (hmacData) {
        NSLog(@"Sm3 二进制数据的HMAC计算成功");
    }else {
        NSLog(@"Sm3 二进制数据的HMAC计算失败");
    }
    [logStr appendFormat:@"\nSM3 HMAC计算二进制结果：%@", hmacData];
    
    // ---------------------- 7、SM4加密和解密 ----------------------
    NSString *sm4plaintext = @"sm4 encrypt text: Copyright © 2024 zitaodev. All rights reserved.";
    NSString *sm4Key = [GMSm4Cryptor createSm4HexKey];
    NSString *sm4Iv = [GMSm4Cryptor createSm4HexKey];
    
    [logStr appendString:@"\n-------SM4加密和解密-------"];
    [logStr appendFormat:@"\nSM4明文：%@", sm4plaintext];
    [logStr appendFormat:@"\nSM4密钥：%@", sm4Key];
    [logStr appendFormat:@"\nSM4初始化向量：%@", sm4Iv];
    // 7.1 UTF-8编码字符串的加密和解密
    NSString *sm4Ciphertext = [GMSm4Cryptor sm4CbcPaddingEncryptText:sm4plaintext withKey:sm4Key withIv:sm4Iv];
    NSString *sm4Decryptedtext = [GMSm4Cryptor sm4CbcPaddingDecryptText:sm4Ciphertext withKey:sm4Key withIv:sm4Iv];
    if ([sm4Decryptedtext isEqualToString:sm4plaintext]) {
        NSLog(@"SM4 UTF-8编码字符串的加密和解密成功");
    } else {
        NSLog(@"SM4 UTF-8编码字符串的加密和解密失败");
    }
    [logStr appendFormat:@"\nSM4密文Base64编码：%@", sm4Ciphertext];
    [logStr appendFormat:@"\nSM4密文Base64解密结果：%@", sm4Decryptedtext];
    // 7.2 Hex编码字符串的加密和解密
    NSString *sm4plaintextHex = [GMUtilities stringToHexString:sm4plaintext];
    sm4Ciphertext = [GMSm4Cryptor sm4CbcPaddingEncryptHexText:sm4plaintextHex withKey:sm4Key withIv:sm4Iv];
    sm4Decryptedtext = [GMSm4Cryptor sm4CbcPaddingDecryptHexText:sm4Ciphertext withKey:sm4Key withIv:sm4Iv];
    if ([sm4Decryptedtext isEqualToString:sm4plaintextHex]) {
        NSLog(@"SM4 Hex编码字符串的加密和解密成功");
    } else {
        NSLog(@"SM4 Hex编码字符串的加密和解密失败");
    }
    [logStr appendFormat:@"\nSM4密文Hex编码：%@", sm4Ciphertext];
    [logStr appendFormat:@"\nSM4密文Hex解密结果：%@", sm4Decryptedtext];
    // 7.3 二进制数据的加密和解密
    NSData *sm4KeyData = [GMUtilities hexStringToData:sm4Key];
    NSData *sm4IvData = [GMUtilities hexStringToData:sm4Iv];
    NSData *sm4PlaintextData = [GMUtilities stringToData:sm4plaintext];
    NSData *sm4CiphertextData = [GMSm4Cryptor sm4CbcPaddingEncryptData:sm4PlaintextData withKey:sm4KeyData withIv:sm4IvData];
    NSData *sm4DecryptedData = [GMSm4Cryptor sm4CbcPaddingDecryptData:sm4CiphertextData withKey:sm4KeyData withIv:sm4IvData];
    if ([sm4DecryptedData isEqualToData:sm4PlaintextData]) {
        NSLog(@"SM4 二进制数据的加密和解密成功");
    } else {
        NSLog(@"SM4 二进制数据的加密和解密失败");
    }
    [logStr appendFormat:@"\nSM4密文二进制数据：%@", sm4CiphertextData];
    [logStr appendFormat:@"\nSM4密文二进制解密结果：%@", sm4DecryptedData];

    NSLog(@"%@", logStr);
}

@end
