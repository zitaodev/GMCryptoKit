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
    NSData *randomData = [GMRandomGenerator gm_secRandomDataWithLength:16];
    [logStr appendString:@"\n-------安全随机数-------"];
    [logStr appendFormat:@"\n随机数：%@", randomData];
    
    // 生成SM2密钥对
    NSDictionary *keyPairData = [GMSm2Cryptor gm_createSm2DataKeyPair];
    NSDictionary *keyPairHex = [GMSm2Cryptor gm_createSm2HexKeyPair];
    NSDictionary *keyPairBase64 = [GMSm2Cryptor gm_createSm2Base64KeyPair];
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
    
    NSString *base64Ciphertext = [GMSm2Cryptor gm_sm2EncryptText:plaintext withBase64PublicKey:publicKeyBase64];
    NSString *hexCiphertext =    [GMSm2Cryptor gm_sm2EncryptHexText:hexPlaintext withHexPublicKey:publicKeyHex];
    NSData   *ciphertextData =     [GMSm2Cryptor gm_sm2EncryptData:plaintextData withPublicKey:publicKey];
    
    NSString *decryptedtext =    [GMSm2Cryptor gm_sm2DecryptText:base64Ciphertext withBase64PrivateKey:privateKeyBase64];
    NSString *decryptedHextext = [GMSm2Cryptor gm_sm2DecryptHexText:hexCiphertext withHexPrivateKey:privateKeyHex];
    NSData   *decryptedData =      [GMSm2Cryptor gm_sm2DecryptData:ciphertextData withPrivateKey:privateKey];
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
    NSString *message = @"sm2 encrypt text: Copyright © 2024 zitaodev. All rights reserved.";
    NSString *hexMessage = [GMUtilities stringToHexString:message];
    NSData   *messageData = [message dataUsingEncoding:NSUTF8StringEncoding];
    NSString *base64Signature = [GMSm2Cryptor gm_sm2SignText:message withBase64PrivateKey:privateKeyBase64];
    NSString *hexSignature = [GMSm2Cryptor gm_sm2SignHexText:hexMessage withHexPrivateKey:privateKeyHex];
    NSData   *signatureData = [GMSm2Cryptor gm_sm2SignData:messageData withPrivateKey:privateKey];
    
    BOOL isBase64SignatureValid = [GMSm2Cryptor gm_sm2VerifySignature:base64Signature forMessage:message withBase64PublicKey:publicKeyBase64];
    BOOL isHexSignatureValid = [GMSm2Cryptor gm_sm2VerifyHexSignature:hexSignature forHexMessage:hexMessage withHexPublicKey:publicKeyHex];
    BOOL isSignatureValid = [GMSm2Cryptor gm_sm2VerifySignature:signatureData forData:messageData withPublicKey:publicKey];
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
    NSData *mesData = [@"hello world!" dataUsingEncoding:NSUTF8StringEncoding];
    NSData *digestData = [GMSm3Digest gm_sm3DigestWithData:mesData];
    [logStr appendString:@"\n-------SM3提取摘要-------"];
    [logStr appendFormat:@"\nSM3消息明文：%@", mesData];
    [logStr appendFormat:@"\nSM3摘要值：%@", digestData];
    
    // 基于SM3计算HMAC
    NSData *hmacMesData = [@"hello world!" dataUsingEncoding:NSUTF8StringEncoding];
    NSData *keyData = [GMRandomGenerator gm_secRandomDataWithLength:16];
    NSData *hmacData = [GMSm3Digest gm_hmacSm3DigestWithData:hmacMesData keyData:keyData];
    [logStr appendString:@"\n-------基于SM3计算HMAC-------"];
    [logStr appendFormat:@"\nhmacSm3消息明文：%@", hmacMesData];
    [logStr appendFormat:@"\nhmacSm3密钥：%@", keyData];
    [logStr appendFormat:@"\nhmacSm3MAC值：%@", hmacData];
    
    // SM4加密和解密
    NSData *sm4KeyData = [GMSm4Cryptor gm_createSm4Key];
    NSData *sm4IvData = [GMSm4Cryptor gm_createSm4Key];
    NSData *sm4CiphertextData = [GMSm4Cryptor gm_sm4CbcPaddingEncryptData:plaintextData withKey:sm4KeyData withIv:sm4IvData];
    NSData *sm4DecryptedData = [GMSm4Cryptor gm_sm4CbcPaddingDecryptData:sm4CiphertextData withKey:sm4KeyData withIv:sm4IvData];
    [logStr appendString:@"\n-------SM4加密和解密-------"];
    [logStr appendFormat:@"\nSM4明文：%@", plaintextData];
    [logStr appendFormat:@"\nSM4密钥：%@", sm4KeyData];
    [logStr appendFormat:@"\nSM2IV：%@", sm4IvData];
    [logStr appendFormat:@"\nSM4加密密文：%@", sm4CiphertextData];
    [logStr appendFormat:@"\nSM4解密结果：%@", sm4DecryptedData];
    
    NSLog(@"%@", logStr);
    
}

@end
