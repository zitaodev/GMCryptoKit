# GMCryptoKit

## 概述

GMCryptoKit是一个基于[GmSSL](https://github.com/guanzhi/GmSSL)开源库封装的Objective-C国密算法组件，旨在为 iOS 开发者提供国密算法的实现。该密码组建支持生成加密安全的随机数和国密算法（SM2/SM3/SM4/SM9），为 iOS 应用提供了密码学安全的功能支持。

## 项目状态 

目前项目正处于初始阶段，为即将到来的项目奠定基础。目前提供以下服务：

### 已完成功能：

- **生成加密安全的随机数：** 通过 GMCryptoKit 库，您可以轻松生成加密安全的随机数。
- **SM2 非对称加解密、数字签名和验证：** 实现了使用 SM2 算法进行非对称加解密、使用 SM2 算法实现数字签名、验签算法等功能。

### 待完成功能：

- **SM3 哈希算法：** 使用 SM3 哈希算法计算哈希值的功能。
- **SM4 对称加密算法：**使用 SM4 对称加密算法进行加解密的功能。
- **SM9 加密算法：**使用 SM9 加密算法进行加密和解密的功能。

## 功能特性

### 1. 随机数生成

通过GMCryptoKit，你可以轻松生成指定字节长度的加密安全的随机数，可用于密钥生成、初始化向量等场景。

#### 使用示例：

```objective-c
// 生成指定字节的加密安全随机数
NSData *randomData = [GMRandomGenerator gm_secRandomDataWithLength:16];
```

### 2. 非对称国密算法SM2

GMCryptoKit提供了对SM2算法的支持，包括密钥对生成、加密、解密、数字签名和验证等功能。

#### 使用示例：

```objective-c
// 生成SM2密钥对
NSDictionary *keyPair = [GMSm2Cryptor gm_createSm2KeyPair];
NSData *publicKey = keyPair[@"publicKey"];
NSData *privateKey = keyPair[@"privateKey"];

// 加密和解密
NSData *plaintextData = [GMRandomGenerator gm_secRandomDataWithLength:12];
NSData *ciphertextData = [GMSm2Cryptor gm_sm2EncryptData:plaintextData withPublicKey:publicKey];
NSData *decryptedData = [GMSm2Cryptor gm_sm2DecryptData:ciphertextData withPrivateKey:privateKey];

// 数字签名和验证
NSData *messageData = [GMRandomGenerator gm_secRandomDataWithLength:36]; // 待签名的数据
NSData *signatureData = [GMSm2Cryptor gm_sm2SignData:messageData withPrivateKey:privateKey];
BOOL isSignatureValid = [GMSm2Cryptor gm_sm2VerifySignature:signatureData forData:messageData withPublicKey:publicKey];
```

## 环境要求

- [GmSSL](https://github.com/guanzhi/GmSSL) 静态库v3.1.0+
- Xcode 14.3+
- iOS 8.0+

## 使用

- 从 [GitHub](https://github.com/zitaodev/GMCryptoKit) 获取源代码

- 将源代码中 GMCryptoKit 目录导入 App 项目，并选中 ***Copy items if needed***

- 从[GmSSL](https://github.com/guanzhi/GmSSL) 编译获取GmSSL 静态库：libgmssl 和对应的头文件，并添加到 App项目中

  > 注意：
  >
  > 1、[GmSSL](https://github.com/guanzhi/GmSSL) 版本需要编译v3.1.0或以上版本.
  >
  > 2、[GmSSL 静态库编译步骤](https://github.com/guanzhi/GmSSL/blob/v3.1.0/INSTALL.md)

## 运行示例应用程序

在示例应用中，你可以找到对应功能的用法和实例代码。请参考`GMCryptoKitDemo`目录下的示例应用。

## 运行单元测试

打开示例应用，选择单元测试对应的Scheme`GMCryptoKitTests`,然后按Command-u构建组件并运行单元测试。

## 联系我

如有任何问题或建议，欢迎联系我：

- 邮件：zitaodev@gmail.com
- GitHub：[https://github.com/zitaodev/GMCryptoKit](https://github.com/yourusername/GmSSLCryptoKit)

## 许可证

GmSSLCryptoKit基于MIT许可证开源，详见LICENSE文件。
