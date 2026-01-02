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

### 二进制布局

UUIDv7a 使用标准的 128 位 UUID 格式，但在内部结构上进行了精心设计，以融合时间戳排序和认证能力。

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      unix_ts_ms (48位)                         |
|                        高32位                                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   unix_ts_ms  | ver |      rand_a (12位)      |var|           |
|     低16位    | (4) |  防止同毫秒冲突          |(2)|           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                                 |
|              rand_b (n位) + auth_tag (m位)                     |
|                   (n + m = 62)                                 |
|                                                                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

#### 字段说明

| 字段 | 位数 | 位置 | 说明 |
|------|------|------|------|
| `unix_ts_ms` | 48 | 0-47 | Unix 毫秒时间戳，从 1970-01-01 00:00:00 UTC 开始计数 |
| `ver` | 4 | 48-51 | 版本号，固定为 `F` (1111)，表示私有/实验性版本 |
| `rand_a` | 12 | 52-63 | 随机数的高位部分，用于防止同一毫秒内的ID冲突 |
| `var` | 2 | 64-65 | 变体号，固定为 `10` (二进制)，符合 RFC 4122 标准 |
| `rand_b` + `auth_tag` | 62 | 66-127 | 随机数低位 (n位) + HMAC 认证标签 (m位)，其中 n + m = 62 |

#### 可配置的随机位和标签位

UUIDv7a 的核心创新在于允许在 **唯一性** 和 **安全性** 之间进行权衡配置：

**约束条件**: `rand_b位数 + auth_tag位数 = 62`

不同配置方案的特点：

| 配置方案 | rand_b位数 | auth_tag位数 | 每毫秒唯一ID数 | 安全强度 |
|---------|-----------|-------------|---------------|---------|
| 高唯一性 | 42 | 32 | ~4.4万亿 (2^42) | 基础 (2^32) |
| 均衡配置 (默认) | 26 | 48 | ~6700万 (2^26) | 较强 (2^48) |
| 高安全性 | 0 | 62 | ~4096 (2^12) | 极强 (2^62) |

### 认证机制

UUIDv7a 使用 HMAC-SHA256 算法提供认证能力：

1. **预认证数据 (Pre-image)**：将时间戳、版本号、随机数和变体号拼接成一个 66 位的数据块
2. **计算 HMAC**：对预认证数据使用密钥计算 HMAC-SHA256，生成 256 位的标签
3. **截断标签**：从完整标签中提取前 m 位（根据配置），嵌入到 UUID 的末尾
4. **验证**：接收方重新计算 HMAC 并比较标签，通过恒定时间比较防止时序攻击

这种设计确保了：
- ✅ **真实性 (Authenticity)**：只有持有密钥的一方才能生成有效的 UUID
- ✅ **完整性 (Integrity)**：UUID 的任何部分被篡改都会导致验证失败
- ✅ **时间排序 (Temporal Ordering)**：UUID 可以按生成时间自然排序

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

## 测试

项目包含两种类型的测试：

### 单元测试 (JUnit)
使用 JUnit 4 进行传统的单元测试，覆盖所有 API 方法和边界条件：

```bash
mvn test -Dtest=UUIDv7aTest
```

### 属性测试 (jqwik)
使用 jqwik 框架进行基于属性的测试，通过生成大量随机测试用例来验证系统属性：

```bash
mvn test -Dtest=UUIDv7aPropertyTest
```

属性测试验证的关键属性包括：
- ✅ **可验证性**: 所有生成的 UUID 都能通过验证
- ✅ **格式正确性**: UUID 符合标准格式 (8-4-4-4-12)
- ✅ **密钥安全**: 使用错误密钥无法验证通过
- ✅ **防篡改**: 修改 UUID 任何位都会导致验证失败
- ✅ **时间排序**: UUID 按时间戳单调递增
- ✅ **版本和变体**: 符合 UUID 标准规范
- ✅ **表示一致性**: 字符串、字节数组和对象表示保持一致

运行所有测试：

```bash
mvn test
```

## 兼容性

- Java 8+
- 标准UUID格式，与现有UUID系统兼容
- 可与数据库UUID字段类型无缝集成

## 许可证

本项目采用MIT许可证。
