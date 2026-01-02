package cn.lihongjie.uuid;

import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/**
 * UUIDv7a - 可认证的UUID工具类
 * 基于UUIDv7的时间戳排序特性，增加了HMAC认证标签
 * 
 * 设计布局 (128位):
 * - unix_ts_ms (48位): Unix毫秒时间戳
 * - ver (4位): 版本号，设为 F (私有/实验性版本)
 * - rand_a (12位): 12位随机数，防止同毫秒冲突
 * - var (2位): 变体号，设为 10
 * - rand_b (n位): 剩余随机位
 * - auth_tag (m位): 认证标签 (其中 n + m = 62)
 * 
 * 使用方式：
 * 1. 实例模式（推荐）：
 *    UUIDv7a generator = new UUIDv7a(secretKey);
 *    String uuid = generator.generateString();
 *    boolean valid = generator.verifyString(uuid);
 * 
 * 2. 静态方法模式：
 *    String uuid = UUIDv7a.generateString(secretKey);
 *    boolean valid = UUIDv7a.verifyString(uuid, secretKey);
 * 
 * @author lihongjie
 */
public class UUIDv7a {
    
    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final String KDF_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int VERSION = 0xF; // 版本号 F (私有版本)
    private static final int VARIANT = 0x2; // 变体号 10 (二进制)
    
    // 默认配置：26位随机 + 48位标签 (均衡配置)
    private static final int DEFAULT_AUTH_TAG_BITS = 48;
    private static final int TOTAL_RANDOM_AND_TAG_BITS = 62;
    
    // PBKDF2 配置
    private static final int PBKDF2_ITERATIONS = 100000; // OWASP 推荐最低值
    private static final int KEY_LENGTH = 256; // 32字节密钥
    
    // 密钥派生缓存（LRU缓存，最多保存1000个条目）
    private static final int CACHE_MAX_SIZE = 1000;
    private static final Map<CacheKey, byte[]> KEY_DERIVATION_CACHE = 
        java.util.Collections.synchronizedMap(new LinkedHashMap<CacheKey, byte[]>(16, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<CacheKey, byte[]> eldest) {
                return size() > CACHE_MAX_SIZE;
            }
        });
    
    private static final SecureRandom RANDOM = new SecureRandom();
    
    // ========== 实例字段 ==========
    
    private final byte[] secretKey;
    private final int authTagBits;
    
    // ========== 构造函数 ==========
    
    /**
     * 使用密钥创建 UUIDv7a 生成器（使用默认配置）
     * @param secretKey 密钥
     */
    public UUIDv7a(byte[] secretKey) {
        this(secretKey, DEFAULT_AUTH_TAG_BITS);
    }
    
    /**
     * 使用密钥和配置创建 UUIDv7a 生成器
     * @param secretKey 密钥
     * @param authTagBits 认证标签位数
     */
    public UUIDv7a(byte[] secretKey, int authTagBits) {
        validateInputs(secretKey, authTagBits);
        this.secretKey = secretKey.clone(); // 防御性复制
        this.authTagBits = authTagBits;
    }
    
    /**
     * 使用密码字符串创建 UUIDv7a 生成器（使用默认配置）
     * @param password 密码字符串
     */
    public UUIDv7a(String password) {
        this(deriveKeyFromPassword(password), DEFAULT_AUTH_TAG_BITS);
    }
    
    /**
     * 使用密码字符串和配置创建 UUIDv7a 生成器
     * @param password 密码字符串
     * @param authTagBits 认证标签位数
     */
    public UUIDv7a(String password, int authTagBits) {
        this(deriveKeyFromPassword(password), authTagBits);
    }
    
    // ========== 实例方法 ==========
    
    /**
     * 生成 UUIDv7a 字符串
     * @return UUID 字符串格式
     */
    public String generateString() {
        return generateUUID(this.secretKey, this.authTagBits).toString();
    }
    
    /**
     * 生成 UUIDv7a 字节数组
     * @return 128位字节数组
     */
    public byte[] generateBytes() {
        return uuidToBytes(generateUUID(this.secretKey, this.authTagBits));
    }
    
    /**
     * 生成 UUIDv7a UUID对象
     * @return UUID对象
     */
    public UUID generate() {
        return generateUUID(this.secretKey, this.authTagBits);
    }
    
    /**
     * 验证 UUIDv7a 字符串
     * @param uuidString UUID字符串
     * @return 验证结果
     */
    public boolean verifyString(String uuidString) {
        return verifyString(uuidString, this.secretKey, this.authTagBits);
    }
    
    /**
     * 验证 UUIDv7a 字节数组
     * @param uuidBytes 128位字节数组
     * @return 验证结果
     */
    public boolean verifyBytes(byte[] uuidBytes) {
        return verifyBytes(uuidBytes, this.secretKey, this.authTagBits);
    }
    
    /**
     * 验证 UUIDv7a UUID对象
     * @param uuid UUID对象
     * @return 验证结果
     */
    public boolean verify(UUID uuid) {
        return verifyUUID(uuid, this.secretKey, this.authTagBits);
    }
    
    /**
     * 获取当前配置描述
     * @return 配置描述
     */
    public String getConfigDescription() {
        return getConfigDescription(this.authTagBits);
    }
    
    /**
     * 获取当前配置每毫秒的最大ID数量
     * @return 每毫秒最大ID数量
     */
    public long getMaxIdsPerMillisecond() {
        return getMaxIdsPerMillisecond(this.authTagBits);
    }
    
    /**
     * 配置常量
     */
    public static final class Config {
        /**
         * 高唯一性配置: 42位随机 + 32位标签
         */
        public static final int HIGH_UNIQUENESS_TAG_BITS = 32;
        
        /**
         * 均衡配置: 26位随机 + 48位标签 (默认)
         */
        public static final int BALANCED_TAG_BITS = 48;
        
        /**
         * 高安全性配置: 12位随机 + 62位标签
         */
        public static final int HIGH_SECURITY_TAG_BITS = 62;
    }
    
    // ========== 生成方法 ==========
    
    /**
     * 使用默认配置生成UUIDv7a字符串
     * @param secretKey 密钥
     * @return UUID字符串格式
     */
    public static String generateString(byte[] secretKey) {
        return generateString(secretKey, DEFAULT_AUTH_TAG_BITS);
    }
    
    /**
     * 使用指定配置生成UUIDv7a字符串
     * @param secretKey 密钥
     * @param authTagBits 认证标签位数
     * @return UUID字符串格式
     */
    public static String generateString(byte[] secretKey, int authTagBits) {
        return generateUUID(secretKey, authTagBits).toString();
    }
    
    /**
     * 使用密码字符串生成UUIDv7a字符串
     * @param password 密码字符串
     * @return UUID字符串格式
     */
    public static String generateString(String password) {
        return generateString(deriveKeyFromPassword(password), DEFAULT_AUTH_TAG_BITS);
    }
    
    /**
     * 使用密码字符串和指定配置生成UUIDv7a字符串
     * @param password 密码字符串
     * @param authTagBits 认证标签位数
     * @return UUID字符串格式
     */
    public static String generateString(String password, int authTagBits) {
        return generateString(deriveKeyFromPassword(password), authTagBits);
    }
    
    /**
     * 使用默认配置生成UUIDv7a字节数组
     * @param secretKey 密钥
     * @return 128位字节数组
     */
    public static byte[] generateBytes(byte[] secretKey) {
        return generateBytes(secretKey, DEFAULT_AUTH_TAG_BITS);
    }
    
    /**
     * 使用指定配置生成UUIDv7a字节数组
     * @param secretKey 密钥
     * @param authTagBits 认证标签位数
     * @return 128位字节数组
     */
    public static byte[] generateBytes(byte[] secretKey, int authTagBits) {
        return uuidToBytes(generateUUID(secretKey, authTagBits));
    }
    
    /**
     * 使用默认配置生成UUIDv7a UUID对象
     * @param secretKey 密钥
     * @return UUID对象
     */
    public static UUID generateUUID(byte[] secretKey) {
        return generateUUID(secretKey, DEFAULT_AUTH_TAG_BITS);
    }
    
    /**
     * 使用指定配置生成UUIDv7a UUID对象
     * @param secretKey 密钥
     * @param authTagBits 认证标签位数
     * @return UUID对象
     */
    public static UUID generateUUID(byte[] secretKey, int authTagBits) {
        validateInputs(secretKey, authTagBits);
        
        int randomBits = TOTAL_RANDOM_AND_TAG_BITS - authTagBits;
        
        // 1. 获取当前时间戳 (48位)
        long timestamp = System.currentTimeMillis();
        
        // 2. 生成随机数
        int randA = RANDOM.nextInt(1 << 12); // 12位随机数
        long randB = randomBits > 0 ? (RANDOM.nextLong() & ((1L << randomBits) - 1)) : 0;
        
        // 3. 构造预认证部分（包含randB）
        byte[] preImage = buildPreImage(timestamp, randA, randB, authTagBits);
        
        // 4. 计算HMAC并截断
        long authTag = calculateAuthTag(preImage, secretKey, authTagBits);
        
        // 5. 组装UUID
        return assembleUUID(timestamp, randA, randB, authTag, authTagBits);
    }
    
    // ========== 验证方法 ==========
    
    /**
     * 验证UUIDv7a字符串
     * @param uuidString UUID字符串
     * @param secretKey 密钥
     * @return 验证结果
     */
    public static boolean verifyString(String uuidString, byte[] secretKey) {
        return verifyString(uuidString, secretKey, DEFAULT_AUTH_TAG_BITS);
    }
    
    /**
     * 验证UUIDv7a字符串
     * @param uuidString UUID字符串
     * @param secretKey 密钥
     * @param authTagBits 认证标签位数
     * @return 验证结果
     */
    public static boolean verifyString(String uuidString, byte[] secretKey, int authTagBits) {
        if (uuidString == null || uuidString.isEmpty()) {
            return false;
        }
        try {
            return verifyUUID(UUID.fromString(uuidString), secretKey, authTagBits);
        } catch (IllegalArgumentException e) {
            return false;
        }
    }
    
    /**
     * 验证UUIDv7a字节数组
     * @param uuidBytes 128位字节数组
     * @param secretKey 密钥
     * @return 验证结果
     */
    public static boolean verifyBytes(byte[] uuidBytes, byte[] secretKey) {
        return verifyBytes(uuidBytes, secretKey, DEFAULT_AUTH_TAG_BITS);
    }
    
    /**
     * 验证UUIDv7a字节数组
     * @param uuidBytes 128位字节数组
     * @param secretKey 密钥
     * @param authTagBits 认证标签位数
     * @return 验证结果
     */
    public static boolean verifyBytes(byte[] uuidBytes, byte[] secretKey, int authTagBits) {
        if (uuidBytes == null || uuidBytes.length != 16) {
            return false;
        }
        return verifyUUID(bytesToUUID(uuidBytes), secretKey, authTagBits);
    }
    
    /**
     * 验证UUIDv7a UUID对象
     * @param uuid UUID对象
     * @param secretKey 密钥
     * @return 验证结果
     */
    public static boolean verifyUUID(UUID uuid, byte[] secretKey) {
        return verifyUUID(uuid, secretKey, DEFAULT_AUTH_TAG_BITS);
    }
    
    /**
     * 验证UUIDv7a UUID对象
     * @param uuid UUID对象
     * @param secretKey 密钥
     * @param authTagBits 认证标签位数
     * @return 验证结果
     */
    public static boolean verifyUUID(UUID uuid, byte[] secretKey, int authTagBits) {
        try {
            validateInputs(secretKey, authTagBits);
            
            // 1. 解析UUID结构
            UUIDStructure structure = parseUUID(uuid, authTagBits);
            
            // 2. 检查版本和变体
            if (structure.version != VERSION || structure.variant != VARIANT) {
                return false;
            }
            
            // 3. 重建预认证部分（包含randB）
            byte[] preImage = buildPreImage(structure.timestamp, structure.randA, structure.randB, authTagBits);
            
            // 4. 重新计算认证标签
            long expectedAuthTag = calculateAuthTag(preImage, secretKey, authTagBits);
            
            // 5. 恒定时间比较
            return constantTimeEquals(structure.authTag, expectedAuthTag);
            
        } catch (Exception e) {
            return false;
        }
    }
    
    // ========== 工具方法 ==========
    
    /**
     * 从UUID中提取时间戳
     * @param uuid UUID对象
     * @return 时间戳毫秒数
     */
    public static long extractTimestamp(UUID uuid) {
        return parseUUID(uuid, DEFAULT_AUTH_TAG_BITS).timestamp;
    }
    
    /**
     * 生成随机密钥
     * @return 32字节随机密钥
     */
    public static byte[] generateRandomKey() {
        byte[] key = new byte[32];
        RANDOM.nextBytes(key);
        return key;
    }
    
    /**
     * 从密码字符串派生密钥（使用固定盐值）
     * 注意：为了安全性，建议使用 deriveKeyFromPassword(password, salt) 提供随机盐值
     * @param password 密码字符串
     * @return 派生的32字节密钥
     */
    public static byte[] deriveKeyFromPassword(String password) {
        // 使用固定盐值以保持向后兼容性（不推荐用于生产环境）
        byte[] salt = "UUIDv7a-Default-Salt".getBytes(StandardCharsets.UTF_8);
        return deriveKeyFromPassword(password, salt);
    }
    
    /**
     * 从密码字符串和盐值派生密钥（推荐使用）
     * 使用 PBKDF2WithHmacSHA256 算法，迭代 100,000 次
     * 结果会被缓存以提高性能
     * @param password 密码字符串
     * @param salt 盐值（建议至少16字节的随机值）
     * @return 派生的32字节密钥
     */
    public static byte[] deriveKeyFromPassword(String password, byte[] salt) {
        if (password == null || password.isEmpty()) {
            throw new IllegalArgumentException("Password cannot be null or empty");
        }
        if (salt == null || salt.length < 8) {
            throw new IllegalArgumentException("Salt must be at least 8 bytes");
        }
        
        // 检查缓存
        CacheKey cacheKey = new CacheKey(password, salt);
        byte[] cachedKey = KEY_DERIVATION_CACHE.get(cacheKey);
        if (cachedKey != null) {
            return cachedKey.clone(); // 返回副本以防止修改
        }
        
        // 计算密钥
        try {
            PBEKeySpec spec = new PBEKeySpec(
                password.toCharArray(),
                salt,
                PBKDF2_ITERATIONS,
                KEY_LENGTH
            );
            
            SecretKeyFactory factory = SecretKeyFactory.getInstance(KDF_ALGORITHM);
            byte[] derivedKey = factory.generateSecret(spec).getEncoded();
            
            // 存入缓存
            KEY_DERIVATION_CACHE.put(cacheKey, derivedKey.clone());
            
            return derivedKey;
            
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException("Failed to derive key from password", e);
        }
    }
    
    /**
     * 生成随机盐值
     * @return 32字节随机盐值
     */
    public static byte[] generateRandomSalt() {
        byte[] salt = new byte[32];
        RANDOM.nextBytes(salt);
        return salt;
    }
    
    /**
     * 清除密钥派生缓存
     * 可用于安全考虑或内存管理
     */
    public static void clearKeyDerivationCache() {
        KEY_DERIVATION_CACHE.clear();
    }
    
    /**
     * 获取当前缓存大小
     * @return 缓存中的条目数量
     */
    public static int getKeyDerivationCacheSize() {
        return KEY_DERIVATION_CACHE.size();
    }
    
    /**
     * 获取配置描述
     * @param authTagBits 认证标签位数
     * @return 配置描述
     */
    public static String getConfigDescription(int authTagBits) {
        switch (authTagBits) {
            case Config.HIGH_UNIQUENESS_TAG_BITS:
                return "高唯一性配置 (42位随机 + 32位标签)";
            case Config.BALANCED_TAG_BITS:
                return "均衡配置 (26位随机 + 48位标签)";
            case Config.HIGH_SECURITY_TAG_BITS:
                return "高安全性配置 (12位随机 + 62位标签)";
            default:
                int randomBits = TOTAL_RANDOM_AND_TAG_BITS - authTagBits;
                return String.format("自定义配置 (%d位随机 + %d位标签)", randomBits, authTagBits);
        }
    }
    
    /**
     * 获取指定配置每毫秒的最大ID数量
     * @param authTagBits 认证标签位数
     * @return 每毫秒最大ID数量
     */
    public static long getMaxIdsPerMillisecond(int authTagBits) {
        int randomBits = TOTAL_RANDOM_AND_TAG_BITS - authTagBits;
        return 1L << Math.min(randomBits + 12, 62); // randA(12) + randB
    }
    
    // ========== 私有方法 ==========
    
    private static void validateInputs(byte[] secretKey, int authTagBits) {
        if (secretKey == null || secretKey.length == 0) {
            throw new IllegalArgumentException("Secret key cannot be null or empty");
        }
        if (authTagBits < 8 || authTagBits > TOTAL_RANDOM_AND_TAG_BITS) {
            throw new IllegalArgumentException("Auth tag bits must be between 8 and " + TOTAL_RANDOM_AND_TAG_BITS);
        }
    }
    
    private static byte[] buildPreImage(long timestamp, int randA, long randB, int authTagBits) {
        // 构建预认证数据：包含除authTag之外的所有数据
        // timestamp (48位) + version (4位) + randA (12位) + variant (2位) + randB (n位)
        int randomBits = TOTAL_RANDOM_AND_TAG_BITS - authTagBits;
        int totalBits = 48 + 4 + 12 + 2 + randomBits; // 66 + randomBits
        int byteCount = (totalBits + 7) / 8; // 向上取整
        
        byte[] preImage = new byte[byteCount];
        
        // 按位构建数据
        long bitBuffer = 0;
        int bitsInBuffer = 0;
        int byteIndex = 0;
        
        // 写入timestamp (48位)
        for (int i = 47; i >= 0; i--) {
            bitBuffer = (bitBuffer << 1) | ((timestamp >>> i) & 1);
            bitsInBuffer++;
            if (bitsInBuffer == 8) {
                preImage[byteIndex++] = (byte) bitBuffer;
                bitBuffer = 0;
                bitsInBuffer = 0;
            }
        }
        
        // 写入version (4位)
        for (int i = 3; i >= 0; i--) {
            bitBuffer = (bitBuffer << 1) | ((VERSION >>> i) & 1);
            bitsInBuffer++;
            if (bitsInBuffer == 8) {
                preImage[byteIndex++] = (byte) bitBuffer;
                bitBuffer = 0;
                bitsInBuffer = 0;
            }
        }
        
        // 写入randA (12位)
        for (int i = 11; i >= 0; i--) {
            bitBuffer = (bitBuffer << 1) | ((randA >>> i) & 1);
            bitsInBuffer++;
            if (bitsInBuffer == 8) {
                preImage[byteIndex++] = (byte) bitBuffer;
                bitBuffer = 0;
                bitsInBuffer = 0;
            }
        }
        
        // 写入variant (2位)
        for (int i = 1; i >= 0; i--) {
            bitBuffer = (bitBuffer << 1) | ((VARIANT >>> i) & 1);
            bitsInBuffer++;
            if (bitsInBuffer == 8) {
                preImage[byteIndex++] = (byte) bitBuffer;
                bitBuffer = 0;
                bitsInBuffer = 0;
            }
        }
        
        // 写入randB (randomBits位)
        if (randomBits > 0) {
            for (int i = randomBits - 1; i >= 0; i--) {
                bitBuffer = (bitBuffer << 1) | ((randB >>> i) & 1);
                bitsInBuffer++;
                if (bitsInBuffer == 8) {
                    preImage[byteIndex++] = (byte) bitBuffer;
                    bitBuffer = 0;
                    bitsInBuffer = 0;
                }
            }
        }
        
        // 写入剩余位（如果有）
        if (bitsInBuffer > 0) {
            preImage[byteIndex] = (byte) (bitBuffer << (8 - bitsInBuffer));
        }
        
        return preImage;
    }
    
    private static long calculateAuthTag(byte[] preImage, byte[] secretKey, int authTagBits) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            SecretKeySpec keySpec = new SecretKeySpec(secretKey, HMAC_ALGORITHM);
            mac.init(keySpec);
            
            byte[] fullTag = mac.doFinal(preImage);
            
            // 从256位HMAC结果中提取指定位数的标签
            return extractBits(fullTag, authTagBits);
            
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException("Failed to calculate HMAC", e);
        }
    }
    
    private static long extractBits(byte[] data, int bitCount) {
        long result = 0;
        int bitsExtracted = 0;
        
        for (int i = 0; i < data.length && bitsExtracted < bitCount; i++) {
            int bitsFromThisByte = Math.min(8, bitCount - bitsExtracted);
            int mask = (1 << bitsFromThisByte) - 1;
            int shift = 8 - bitsFromThisByte;
            
            result = (result << bitsFromThisByte) | ((data[i] >>> shift) & mask);
            bitsExtracted += bitsFromThisByte;
        }
        
        return result;
    }
    
    private static UUID assembleUUID(long timestamp, int randA, long randB, long authTag, int authTagBits) {
        int randomBits = TOTAL_RANDOM_AND_TAG_BITS - authTagBits;
        
        // 构造最高64位 (MSB)
        long msb = (timestamp << 16) | // 48位时间戳
                   ((long) VERSION << 12) | // 4位版本
                   (randA & 0xFFF); // 12位随机数A
        
        // 构造最低64位 (LSB)
        long lsb = ((long) VARIANT << 62); // 2位变体
        
        if (randomBits > 0) {
            lsb |= (randB << authTagBits); // 随机数B
        }
        lsb |= (authTag & ((1L << authTagBits) - 1)); // 认证标签
        
        return new UUID(msb, lsb);
    }
    
    private static UUIDStructure parseUUID(UUID uuid, int authTagBits) {
        long msb = uuid.getMostSignificantBits();
        long lsb = uuid.getLeastSignificantBits();
        
        UUIDStructure structure = new UUIDStructure();
        
        // 解析MSB
        structure.timestamp = msb >>> 16; // 高48位
        structure.version = (int) ((msb >>> 12) & 0xF); // 4位版本
        structure.randA = (int) (msb & 0xFFF); // 12位随机数A
        
        // 解析LSB
        structure.variant = (int) (lsb >>> 62); // 高2位
        
        int randomBits = TOTAL_RANDOM_AND_TAG_BITS - authTagBits;
        
        // 提取认证标签（最低位）
        structure.authTag = lsb & ((1L << authTagBits) - 1);
        
        // 提取randB（在variant之后，authTag之前）
        if (randomBits > 0) {
            structure.randB = (lsb >>> authTagBits) & ((1L << randomBits) - 1);
        } else {
            structure.randB = 0;
        }
        
        return structure;
    }
    
    private static boolean constantTimeEquals(long a, long b) {
        return ((a ^ b) == 0);
    }
    
    private static byte[] uuidToBytes(UUID uuid) {
        byte[] bytes = new byte[16];
        long msb = uuid.getMostSignificantBits();
        long lsb = uuid.getLeastSignificantBits();
        
        for (int i = 0; i < 8; i++) {
            bytes[i] = (byte) (msb >>> (8 * (7 - i)));
            bytes[8 + i] = (byte) (lsb >>> (8 * (7 - i)));
        }
        
        return bytes;
    }
    
    private static UUID bytesToUUID(byte[] bytes) {
        long msb = 0;
        long lsb = 0;
        
        for (int i = 0; i < 8; i++) {
            msb = (msb << 8) | (bytes[i] & 0xFF);
            lsb = (lsb << 8) | (bytes[8 + i] & 0xFF);
        }
        
        return new UUID(msb, lsb);
    }
    
    // 内部结构类
    private static class UUIDStructure {
        long timestamp;
        int version;
        int randA;
        int variant;
        long randB;  // 随机数B部分
        long authTag;
    }
    
    // 缓存键类
    private static class CacheKey {
        private final String password;
        private final byte[] salt;
        private final int hashCode;
        
        CacheKey(String password, byte[] salt) {
            this.password = password;
            this.salt = salt.clone();
            this.hashCode = computeHashCode();
        }
        
        private int computeHashCode() {
            int result = password.hashCode();
            result = 31 * result + Arrays.hashCode(salt);
            return result;
        }
        
        @Override
        public boolean equals(Object obj) {
            if (this == obj) return true;
            if (!(obj instanceof CacheKey)) return false;
            CacheKey other = (CacheKey) obj;
            return password.equals(other.password) && 
                   Arrays.equals(salt, other.salt);
        }
        
        @Override
        public int hashCode() {
            return hashCode;
        }
    }
}
