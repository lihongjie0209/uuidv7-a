package cn.lihongjie.uuid;

import net.jqwik.api.*;
import net.jqwik.api.constraints.IntRange;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * UUIDv7a 属性测试
 * 使用 jqwik 框架进行基于属性的测试，验证系统的通用性质
 * 
 * @author lihongjie
 */
class UUIDv7aPropertyTest {
    
    /**
     * 属性：所有生成的 UUID 都应该能够通过验证
     */
    @Property
    @Label("生成的 UUID 必须能够被验证")
    void generatedUUIDsShouldBeVerifiable(@ForAll("validSecretKeys") byte[] secretKey,
                                          @ForAll("authTagBits") int authTagBits) {
        UUID uuid = UUIDv7a.generateUUID(secretKey, authTagBits);
        boolean isValid = UUIDv7a.verifyUUID(uuid, secretKey, authTagBits);
        
        assertTrue(isValid, 
            "生成的 UUID 应该能够通过验证 (authTagBits=" + authTagBits + ")");
    }
    
    /**
     * 属性：生成的 UUID 字符串格式应该正确
     */
    @Property
    @Label("UUID 字符串格式必须正确")
    void uuidStringShouldHaveCorrectFormat(@ForAll("validSecretKeys") byte[] secretKey) {
        String uuidString = UUIDv7a.generateString(secretKey);
        
        // UUID 字符串长度应为 36 个字符
        assertEquals(36, uuidString.length(), 
            "UUID 字符串长度应为 36");
        
        // UUID 格式：8-4-4-4-12
        assertTrue(
            uuidString.matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),
            "UUID 应符合标准格式"
        );
    }
    
    /**
     * 属性：生成的 UUID 字节数组长度应为 16
     */
    @Property
    @Label("UUID 字节数组长度必须为 16")
    void uuidBytesShouldBe16BytesLong(@ForAll("validSecretKeys") byte[] secretKey,
                                      @ForAll("authTagBits") int authTagBits) {
        byte[] uuidBytes = UUIDv7a.generateBytes(secretKey, authTagBits);
        
        assertEquals(16, uuidBytes.length, 
            "UUID 字节数组长度应为 16");
    }
    
    /**
     * 属性：使用错误的密钥应该无法验证通过
     */
    @Property
    @Label("使用错误的密钥必须验证失败")
    void wrongKeyShouldFailVerification(@ForAll("validSecretKeys") byte[] correctKey,
                                        @ForAll("validSecretKeys") byte[] wrongKey,
                                        @ForAll("authTagBits") int authTagBits) {
        Assume.that(!Arrays.equals(correctKey, wrongKey));
        
        UUID uuid = UUIDv7a.generateUUID(correctKey, authTagBits);
        boolean isValid = UUIDv7a.verifyUUID(uuid, wrongKey, authTagBits);
        
        assertFalse(isValid, 
            "使用错误的密钥应该验证失败");
    }
    
    /**
     * 属性：使用错误的 authTagBits 配置应该无法验证通过
     */
    @Property
    @Label("使用错误的配置必须验证失败")
    void wrongConfigShouldFailVerification(@ForAll("validSecretKeys") byte[] secretKey,
                                           @ForAll("authTagBits") int correctBits,
                                           @ForAll("authTagBits") int wrongBits) {
        Assume.that(correctBits != wrongBits);
        
        UUID uuid = UUIDv7a.generateUUID(secretKey, correctBits);
        boolean isValid = UUIDv7a.verifyUUID(uuid, secretKey, wrongBits);
        
        assertFalse(isValid, 
            "使用错误的配置应该验证失败");
    }
    
    /**
     * 属性：提取的时间戳应该在合理范围内
     */
    @Property
    @Label("提取的时间戳必须在合理范围内")
    void extractedTimestampShouldBeReasonable(@ForAll("validSecretKeys") byte[] secretKey) {
        long beforeGeneration = System.currentTimeMillis();
        UUID uuid = UUIDv7a.generateUUID(secretKey);
        long afterGeneration = System.currentTimeMillis();
        
        long timestamp = UUIDv7a.extractTimestamp(uuid);
        
        assertTrue(timestamp >= beforeGeneration - 10, 
            "时间戳应该不早于生成前");
        assertTrue(timestamp <= afterGeneration + 10, 
            "时间戳应该不晚于生成后");
    }
    
    /**
     * 属性：UUID 应该按时间顺序排列
     */
    @Property(tries = 100)
    @Label("UUID 必须按时间顺序排列")
    void uuidsShouldBeOrderedByTime(@ForAll("validSecretKeys") byte[] secretKey) {
        List<UUID> uuids = new ArrayList<>();
        List<Long> timestamps = new ArrayList<>();
        
        // 生成多个 UUID
        for (int i = 0; i < 10; i++) {
            UUID uuid = UUIDv7a.generateUUID(secretKey);
            uuids.add(uuid);
            timestamps.add(UUIDv7a.extractTimestamp(uuid));
            
            try {
                Thread.sleep(1); // 确保时间戳不同
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        
        // 验证 UUID 顺序与时间戳顺序一致
        for (int i = 1; i < uuids.size(); i++) {
            long ts1 = timestamps.get(i - 1);
            long ts2 = timestamps.get(i);
            
            // 时间戳应该是非递减的
            assertTrue(ts2 >= ts1, 
                "时间戳应该递增");
            
            // 如果时间戳增加了，UUID 的字典序也应该增加
            if (ts2 > ts1) {
                assertTrue(uuids.get(i).compareTo(uuids.get(i - 1)) > 0,
                    "UUID 应该按时间戳排序");
            }
        }
    }
    
    /**
     * 属性：UUID 的版本位应该是 F (0xF)
     */
    @Property
    @Label("UUID 版本位必须为 F")
    void uuidVersionShouldBeF(@ForAll("validSecretKeys") byte[] secretKey,
                              @ForAll("authTagBits") int authTagBits) {
        UUID uuid = UUIDv7a.generateUUID(secretKey, authTagBits);
        
        long msb = uuid.getMostSignificantBits();
        int version = (int) ((msb >>> 12) & 0xF);
        
        assertEquals(0xF, version, 
            "UUID 版本号应该是 F (私有/实验性版本)");
    }
    
    /**
     * 属性：UUID 的变体位应该是 10 (二进制)
     */
    @Property
    @Label("UUID 变体位必须为 10")
    void uuidVariantShouldBe10(@ForAll("validSecretKeys") byte[] secretKey,
                               @ForAll("authTagBits") int authTagBits) {
        UUID uuid = UUIDv7a.generateUUID(secretKey, authTagBits);
        
        long lsb = uuid.getLeastSignificantBits();
        int variant = (int) (lsb >>> 62);
        
        assertEquals(0x2, variant, 
            "UUID 变体号应该是 10 (二进制)，即 2");
    }
    
    /**
     * 属性：篡改 UUID 的任何位都应该导致验证失败
     */
    @Property(tries = 50)
    @Label("篡改 UUID 必须导致验证失败")
    void tamperingUUIDShouldFailVerification(@ForAll("validSecretKeys") byte[] secretKey,
                                             @ForAll("authTagBits") int authTagBits,
                                             @ForAll @IntRange(min = 0, max = 127) int bitToFlip) {
        byte[] originalBytes = UUIDv7a.generateBytes(secretKey, authTagBits);
        byte[] tamperedBytes = Arrays.copyOf(originalBytes, originalBytes.length);
        
        // 翻转某一位
        int byteIndex = bitToFlip / 8;
        int bitIndex = bitToFlip % 8;
        tamperedBytes[byteIndex] ^= (1 << bitIndex);
        
        boolean isValid = UUIDv7a.verifyBytes(tamperedBytes, secretKey, authTagBits);
        
        assertFalse(isValid, 
            "篡改第 " + bitToFlip + " 位后应该验证失败");
    }
    
    /**
     * 属性：相同密码应该派生出相同的密钥
     */
    @Property(tries = 100)  // 减少测试次数以提升 Java 8 性能（PBKDF2 计算密集）
    @Label("相同密码必须派生相同密钥")
    void samePasswordShouldDeriveIdenticalKeys(@ForAll("passwords") String password) {
        byte[] key1 = UUIDv7a.deriveKeyFromPassword(password);
        byte[] key2 = UUIDv7a.deriveKeyFromPassword(password);
        
        assertArrayEquals(key1, key2, 
            "相同密码应该派生出相同的密钥");
    }
    
    /**
     * 属性：不同密码应该派生出不同的密钥
     */
    @Property(tries = 100)  // 减少测试次数以提升 Java 8 性能（PBKDF2 计算密集）
    @Label("不同密码必须派生不同密钥")
    void differentPasswordsShouldDeriveDifferentKeys(@ForAll("passwords") String password1,
                                                     @ForAll("passwords") String password2) {
        Assume.that(!password1.equals(password2));
        
        byte[] key1 = UUIDv7a.deriveKeyFromPassword(password1);
        byte[] key2 = UUIDv7a.deriveKeyFromPassword(password2);
        
        assertFalse(Arrays.equals(key1, key2), 
            "不同密码应该派生出不同的密钥");
    }
    
    /**
     * 属性：派生的密钥长度应该是 32 字节
     */
    @Property(tries = 100)  // 减少测试次数以提升 Java 8 性能（PBKDF2 计算密集）
    @Label("派生的密钥长度必须为 32 字节")
    void derivedKeyShouldBe32Bytes(@ForAll("passwords") String password) {
        byte[] key = UUIDv7a.deriveKeyFromPassword(password);
        
        assertEquals(32, key.length, 
            "派生的密钥应该是 32 字节");
    }
    
    /**
     * 属性：生成的随机密钥应该都不相同
     */
    @Property(tries = 100)
    @Label("生成的随机密钥必须不同")
    void randomKeysShouldBeDifferent() {
        Set<String> keys = new HashSet<>();
        
        for (int i = 0; i < 50; i++) {
            byte[] key = UUIDv7a.generateRandomKey();
            keys.add(Arrays.toString(key));
        }
        
        assertEquals(50, keys.size(), 
            "生成的 50 个随机密钥应该都不相同");
    }
    
    /**
     * 属性：字符串、字节数组和 UUID 对象之间应该可以相互转换并保持一致
     */
    @Property
    @Label("不同表示形式必须保持一致")
    void differentRepresentationsShouldBeConsistent(@ForAll("validSecretKeys") byte[] secretKey,
                                                    @ForAll("authTagBits") int authTagBits) {
        // 生成 UUID 对象
        UUID uuid = UUIDv7a.generateUUID(secretKey, authTagBits);
        
        // 转换为字符串
        String uuidString = uuid.toString();
        
        // 转换为字节数组
        byte[] uuidBytes = toBytes(uuid);
        
        // 从字节数组重建 UUID
        UUID reconstructedFromBytes = fromBytes(uuidBytes);
        
        // 从字符串重建 UUID
        UUID reconstructedFromString = UUID.fromString(uuidString);
        
        // 验证一致性
        assertEquals(uuid, reconstructedFromBytes, 
            "从字节数组重建的 UUID 应该与原始 UUID 相同");
        assertEquals(uuid, reconstructedFromString, 
            "从字符串重建的 UUID 应该与原始 UUID 相同");
        
        // 验证所有形式都能通过验证
        assertTrue(UUIDv7a.verifyUUID(uuid, secretKey, authTagBits));
        assertTrue(UUIDv7a.verifyString(uuidString, secretKey, authTagBits));
        assertTrue(UUIDv7a.verifyBytes(uuidBytes, secretKey, authTagBits));
    }
    
    // ========== Arbitraries（生成器）==========
    
    /**
     * 生成有效的密钥（16-64 字节）
     */
    @Provide
    Arbitrary<byte[]> validSecretKeys() {
        return Arbitraries.bytes()
            .array(byte[].class)
            .ofMinSize(16)
            .ofMaxSize(64);
    }
    
    /**
     * 生成有效的 authTagBits（16-56，且为 8 的倍数）
     * 避免使用8位（碰撞概率太高）
     */
    @Provide
    Arbitrary<Integer> authTagBits() {
        return Arbitraries.integers()
            .between(2, 7)
            .map(i -> i * 8); // 16, 24, 32, 40, 48, 56
    }
    
    /**
     * 生成测试用的密码字符串
     */
    @Provide
    Arbitrary<String> passwords() {
        return Arbitraries.strings()
            .withCharRange('a', 'z')
            .numeric()
            .withChars("!@#$%^&*")
            .ofMinLength(6)
            .ofMaxLength(32);
    }
    
    // ========== 辅助方法 ==========
    
    private static byte[] toBytes(UUID uuid) {
        byte[] bytes = new byte[16];
        long msb = uuid.getMostSignificantBits();
        long lsb = uuid.getLeastSignificantBits();
        
        for (int i = 0; i < 8; i++) {
            bytes[i] = (byte) (msb >>> (8 * (7 - i)));
            bytes[i + 8] = (byte) (lsb >>> (8 * (7 - i)));
        }
        
        return bytes;
    }
    
    private static UUID fromBytes(byte[] bytes) {
        if (bytes == null || bytes.length != 16) {
            throw new IllegalArgumentException("UUID 字节数组必须是 16 字节");
        }
        
        long msb = 0;
        long lsb = 0;
        
        for (int i = 0; i < 8; i++) {
            msb = (msb << 8) | (bytes[i] & 0xFF);
            lsb = (lsb << 8) | (bytes[i + 8] & 0xFF);
        }
        
        return new UUID(msb, lsb);
    }
}
