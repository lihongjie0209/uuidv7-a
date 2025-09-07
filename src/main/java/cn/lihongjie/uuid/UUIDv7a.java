package cn.lihongjie.uuid;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.UUID;

/**
 * UUIDv7a - 可认证的UUID静态工具类
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
 * @author lihongjie
 */
public final class UUIDv7a {
    
    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final int VERSION = 0xF; // 版本号 F (私有版本)
    private static final int VARIANT = 0x2; // 变体号 10 (二进制)
    
    // 默认配置：26位随机 + 48位标签 (均衡配置)
    private static final int DEFAULT_AUTH_TAG_BITS = 48;
    private static final int TOTAL_RANDOM_AND_TAG_BITS = 62;
    
    private static final SecureRandom RANDOM = new SecureRandom();
    
    // 私有构造函数，防止实例化
    private UUIDv7a() {
        throw new UnsupportedOperationException("This is a utility class and cannot be instantiated");
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
        
        // 3. 构造预认证部分 (66位: 48 + 4 + 12 + 2)
        byte[] preImage = buildPreImage(timestamp, randA);
        
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
            
            // 3. 重建预认证部分
            byte[] preImage = buildPreImage(structure.timestamp, structure.randA);
            
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
     * 从密码字符串派生密钥
     * @param password 密码字符串
     * @return 派生的密钥
     */
    public static byte[] deriveKeyFromPassword(String password) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(password.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not available", e);
        }
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
    
    private static byte[] buildPreImage(long timestamp, int randA) {
        // 构造66位的预认证数据
        // 格式: timestamp(48) + version(4) + randA(12) + variant(2)
        byte[] preImage = new byte[9]; // 66位需要9字节 (72位，有6位填充)
        
        // 写入时间戳 (48位)
        for (int i = 0; i < 6; i++) {
            preImage[i] = (byte) (timestamp >>> (40 - i * 8));
        }
        
        // 写入版本 + randA的高4位 (8位)
        preImage[6] = (byte) ((VERSION << 4) | (randA >>> 8));
        
        // 写入randA的低8位 (8位)
        preImage[7] = (byte) (randA & 0xFF);
        
        // 写入变体 (2位，左对齐到字节)
        preImage[8] = (byte) (VARIANT << 6);
        
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
        
        structure.authTag = lsb & ((1L << authTagBits) - 1);
        
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
        long authTag;
    }
}
