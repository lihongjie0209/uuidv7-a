# UUIDv7a - 可认证的UUID

[![CI/CD Pipeline](https://github.com/lihongjie0209/uuidv7-a/actions/workflows/ci.yml/badge.svg)](https://github.com/lihongjie0209/uuidv7-a/actions/workflows/ci.yml)
[![Java Version](https://img.shields.io/badge/Java-8%2B-orange.svg)](https://www.oracle.com/java/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

UUIDv7a是基于UUIDv7标准扩展的可认证UUID实现，在保持时间戳排序特性的同时，增加了HMAC认证标签，确保UUID的真实性和完整性。

## 特性

- **时间戳排序**: 继承UUIDv7的时间戳特性，支持按生成时间排序
- **认证能力**: 使用HMAC-SHA256提供认证标签，防止伪造和篡改
- **可配置安全级别**: 支持不同的认证标签位数配置
- **高性能**: 静态方法设计，无需实例化
- **标准兼容**: 128位UUID格式，兼容现有UUID系统

## 设计原理

UUIDv7a使用以下128位布局：
- `unix_ts_ms` (48位): Unix毫秒时间戳
- `ver` (4位): 版本号，设为 F (私有/实验性版本)
- `rand_a` (12位): 12位随机数，防止同毫秒冲突
- `var` (2位): 变体号，设为 10
- `rand_b` (n位): 剩余随机位
- `auth_tag` (m位): 认证标签 (其中 n + m = 62)

## 配置选项

### 预定义配置

- **高唯一性配置** (32位标签 + 42位随机): 每毫秒约4.4万亿个唯一ID，基础安全级别
- **均衡配置** (48位标签 + 26位随机): 每毫秒约6700万个唯一ID，较强安全级别 (默认)
- **高安全性配置** (62位标签 + 12位随机): 每毫秒4096个唯一ID，极强安全级别

## 使用方法

### 基本用法

```java
// 生成随机密钥
byte[] secretKey = UUIDv7a.generateRandomKey();

// 生成UUID字符串
String uuidString = UUIDv7a.generateString(secretKey);

// 验证UUID
boolean isValid = UUIDv7a.verifyString(uuidString, secretKey);
```

### 使用密码

```java
// 使用密码生成UUID
String uuid = UUIDv7a.generateString("myPassword123");

// 验证需要使用相同密码派生的密钥
byte[] key = UUIDv7a.deriveKeyFromPassword("myPassword123");
boolean isValid = UUIDv7a.verifyString(uuid, key);
```

### 不同安全配置

```java
// 高唯一性配置 (适合高并发场景)
String uuid1 = UUIDv7a.generateString(secretKey, UUIDv7a.Config.HIGH_UNIQUENESS_TAG_BITS);

// 均衡配置 (默认，适合大多数场景)
String uuid2 = UUIDv7a.generateString(secretKey, UUIDv7a.Config.BALANCED_TAG_BITS);

// 高安全性配置 (适合安全敏感场景)
String uuid3 = UUIDv7a.generateString(secretKey, UUIDv7a.Config.HIGH_SECURITY_TAG_BITS);
```

### 时间戳提取

```java
UUID uuid = UUIDv7a.generateUUID(secretKey);
long timestamp = UUIDv7a.extractTimestamp(uuid);
System.out.println("生成时间: " + new Date(timestamp));
```

### 字节数组操作

```java
// 生成字节数组
byte[] uuidBytes = UUIDv7a.generateBytes(secretKey);

// 验证字节数组
boolean isValid = UUIDv7a.verifyBytes(uuidBytes, secretKey);
```

## API参考

### 生成方法

- `generateString(byte[] secretKey)` - 使用默认配置生成UUID字符串
- `generateString(byte[] secretKey, int authTagBits)` - 使用指定配置生成UUID字符串
- `generateString(String password)` - 使用密码生成UUID字符串
- `generateBytes(byte[] secretKey)` - 生成UUID字节数组
- `generateUUID(byte[] secretKey)` - 生成UUID对象

### 验证方法

- `verifyString(String uuid, byte[] secretKey)` - 验证UUID字符串
- `verifyBytes(byte[] uuidBytes, byte[] secretKey)` - 验证UUID字节数组
- `verifyUUID(UUID uuid, byte[] secretKey)` - 验证UUID对象

### 工具方法

- `generateRandomKey()` - 生成32字节随机密钥
- `deriveKeyFromPassword(String password)` - 从密码派生密钥
- `extractTimestamp(UUID uuid)` - 提取时间戳
- `getConfigDescription(int authTagBits)` - 获取配置描述
- `getMaxIdsPerMillisecond(int authTagBits)` - 获取每毫秒最大ID数量

## 安全注意事项

1. **密钥管理**: 妥善保管密钥，不要在代码中硬编码
2. **配置选择**: 根据业务需求选择合适的安全配置
3. **时间同步**: 确保系统时间准确，避免时间戳异常
4. **验证检查**: 始终验证接收到的UUID的真实性

## 性能

基于JUnit测试结果，UUIDv7a具有良好的性能表现：
- 生成速度: 适合高频UUID生成场景
- 验证速度: 快速验证，适合实时验证需求
- 内存效率: 静态方法设计，无内存泄漏风险

## 兼容性

- Java 8+
- 标准UUID格式，与现有UUID系统兼容
- 可与数据库UUID字段类型无缝集成

## 许可证

本项目采用MIT许可证。
