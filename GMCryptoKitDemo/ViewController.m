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
    // 生成指定字节的加密安全随机数
    NSData *randomData = [GMRandomGenerator secRandomDataWithLength:16];
    [logStr appendString:@"\n-------安全随机数-------"];
    [logStr appendFormat:@"\n随机数：%@", randomData];
    
    // 生成SM2密钥对
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
    
    // SM2加密和解密
    NSString *plaintext = @"sm2 encrypt text: Copyright © 2024 zitaodev. All rights reserved.";
    NSString *hexPlaintext = [GMUtilities stringToHexString:plaintext];
    NSData   *plaintextData = [plaintext dataUsingEncoding:NSUTF8StringEncoding];
    
    NSString *base64Ciphertext = [GMSm2Cryptor sm2EncryptText:plaintext withBase64PublicKey:publicKeyBase64];
    NSString *hexCiphertext =    [GMSm2Cryptor sm2EncryptHexText:hexPlaintext withHexPublicKey:publicKeyHex];
    NSData   *ciphertextData =     [GMSm2Cryptor sm2EncryptData:plaintextData withPublicKey:publicKey];
    
    NSString *decryptedtext =    [GMSm2Cryptor sm2DecryptText:base64Ciphertext withBase64PrivateKey:privateKeyBase64];
    NSString *decryptedHextext = [GMSm2Cryptor sm2DecryptHexText:hexCiphertext withHexPrivateKey:privateKeyHex];
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
    
    // SM2数字签名和验证
    NSString *message = @"sm2 sign text: Copyright © 2024 zitaodev. All rights reserved.";
    NSString *hexMessage = [GMUtilities stringToHexString:message];
    NSData   *messageData = [message dataUsingEncoding:NSUTF8StringEncoding];
    NSString *base64Signature = [GMSm2Cryptor sm2SignText:message withBase64PrivateKey:privateKeyBase64];
    NSString *hexSignature = [GMSm2Cryptor sm2SignHexText:hexMessage withHexPrivateKey:privateKeyHex];
    NSData   *signatureData = [GMSm2Cryptor sm2SignData:messageData withPrivateKey:privateKey];
    
    BOOL isBase64SignatureValid = [GMSm2Cryptor sm2VerifySignature:base64Signature forMessage:message withBase64PublicKey:publicKeyBase64];
    BOOL isHexSignatureValid = [GMSm2Cryptor sm2VerifyHexSignature:hexSignature forHexMessage:hexMessage withHexPublicKey:publicKeyHex];
    BOOL isSignatureValid = [GMSm2Cryptor sm2VerifySignature:signatureData forData:messageData withPublicKey:publicKey];
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
    
    // SM3提取摘要
    NSString *sm3message = @"sm3 digest text: Copyright © 2024 zitaodev. All rights reserved.";
    NSString *hexSm3Message = [GMUtilities stringToHexString:sm3message];
    NSData   *sm3messageData = [sm3message dataUsingEncoding:NSUTF8StringEncoding];
    NSString *base64Digest = [GMSm3Digest sm3DigestWithText:sm3message];
    NSString *hexDigest = [GMSm3Digest sm3DigestWithHexText:hexSm3Message];
    NSData *digestData = [GMSm3Digest sm3DigestWithData:sm3messageData];
    if (base64Digest && hexDigest && digestData) {
        NSLog(@"SM3提取摘要成功");
    }else {
        NSLog(@"SM3提取摘要失败");
    }
    [logStr appendString:@"\n-------SM3提取摘要-------"];
    [logStr appendFormat:@"\nSM3消息明文：%@", sm3message];
    [logStr appendFormat:@"\nSM3摘要值：%@", base64Digest];
    
    // 基于SM3计算HMAC
    NSString *sm3HmacMessage = @"sm3 hmac text: Copyright © 2024 zitaodev. All rights reserved.";
    NSString *hexSm3HmacMessage = [GMUtilities stringToHexString:sm3HmacMessage];
    NSData   *sm3HmacMessageData = [sm3HmacMessage dataUsingEncoding:NSUTF8StringEncoding];
    NSData *keyData = [GMRandomGenerator secRandomDataWithLength:16];
    NSString *base64Key = [GMUtilities dataToBase64String:keyData];
    NSString *hexKey = [GMUtilities dataToHexString:keyData];
    NSString *base64Hmac = [GMSm3Digest hmacSm3DigestWithText:sm3HmacMessage base64Key:base64Key];
    NSString *hexHmac = [GMSm3Digest hmacSm3DigestWithHexText:hexSm3HmacMessage hexKey:hexKey];
    NSData *hmacData = [GMSm3Digest hmacSm3DigestWithData:sm3HmacMessageData keyData:keyData];
    if (base64Hmac && hexHmac && hmacData) {
        NSLog(@"基于SM3计算HMAC成功");
    }else {
        NSLog(@"基于SM3计算HMAC失败");
    }
    [logStr appendString:@"\n-------基于SM3计算HMAC-------"];
    [logStr appendFormat:@"\nhmacSm3消息明文：%@", sm3HmacMessage];
    [logStr appendFormat:@"\nhmacSm3密钥：%@", keyData];
    [logStr appendFormat:@"\nhmacSm3MAC值：%@", base64Hmac];
    
    // SM4加密和解密
    NSString *sm4plaintext = @"sm4 encrypt text: Copyright © 2024 zitaodev. All rights reserved.";
    NSString *sm4Key = [GMSm4Cryptor createSm4HexKey];
    NSString *sm4Iv = [GMSm4Cryptor createSm4HexKey];
    
    [logStr appendString:@"\n-------SM4加密和解密-------"];
    [logStr appendFormat:@"\nSM4明文：%@", sm4plaintext];
    [logStr appendFormat:@"\nSM4密钥：%@", sm4Key];
    [logStr appendFormat:@"\nSM4初始化向量：%@", sm4Iv];
    // 1.1 UTF-8编码字符串的加密和解密
    NSString *sm4Ciphertext = [GMSm4Cryptor sm4CbcPaddingEncryptText:sm4plaintext withKey:sm4Key withIv:sm4Iv];
    NSString *sm4Decryptedtext = [GMSm4Cryptor sm4CbcPaddingDecryptText:sm4Ciphertext withKey:sm4Key withIv:sm4Iv];
    if ([sm4Decryptedtext isEqualToString:sm4plaintext]) {
        NSLog(@"SM4 UTF-8编码字符串的加密和解密成功");
    } else {
        NSLog(@"SM4 UTF-8编码字符串的加密和解密失败");
    }
    [logStr appendFormat:@"\nSM4密文Base64编码：%@", sm4Ciphertext];
    [logStr appendFormat:@"\nSM4密文Base64解密结果：%@", sm4Decryptedtext];
    // 1.2 Hex编码字符串的加密和解密
    sm4plaintext = [GMUtilities stringToHexString:sm4plaintext];
    sm4Ciphertext = [GMSm4Cryptor sm4CbcPaddingEncryptHexText:sm4plaintext withKey:sm4Key withIv:sm4Iv];
    sm4Decryptedtext = [GMSm4Cryptor sm4CbcPaddingDecryptHexText:sm4Ciphertext withKey:sm4Key withIv:sm4Iv];
    if ([sm4Decryptedtext isEqualToString:sm4plaintext]) {
        NSLog(@"SM4 Hex编码字符串的加密和解密成功");
    } else {
        NSLog(@"SM4 Hex编码字符串的加密和解密失败");
    }
    [logStr appendFormat:@"\nSM4密文Hex编码：%@", sm4Ciphertext];
    [logStr appendFormat:@"\nSM4密文Hex解密结果：%@", sm4Decryptedtext];
    // 1.3 二进制数据的加密和解密
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
