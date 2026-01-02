package cn.lihongjie.uuid;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import static org.junit.jupiter.api.Assertions.*;
import java.util.UUID;
import java.util.Arrays;

/**
 * UUIDv7a 单元测试
 * 
 * @author lihongjie
 */
class UUIDv7aTest {
    
    private byte[] secretKey;
    
    @BeforeEach
    void setUp() {
        secretKey = new byte[32];
        Arrays.fill(secretKey, (byte) 0x42); // 固定密钥用于测试
    }
    
    @Test
    public void testGenerateString() {
        String uuid = UUIDv7a.generateString(secretKey);
        assertNotNull(uuid);
        assertEquals(36, uuid.length());
        assertTrue(uuid.matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"));
    }
    
    @Test
    public void testGenerateStringWithAuthTagBits() {
        String uuid = UUIDv7a.generateString(secretKey, 32);
        assertNotNull(uuid);
        assertEquals(36, uuid.length());
    }
    
    @Test
    public void testGenerateStringWithPassword() {
        String uuid = UUIDv7a.generateString("password123");
        assertNotNull(uuid);
        assertEquals(36, uuid.length());
    }
    
    @Test
    public void testGenerateBytes() {
        byte[] uuidBytes = UUIDv7a.generateBytes(secretKey);
        assertNotNull(uuidBytes);
        assertEquals(16, uuidBytes.length);
    }
    
    @Test
    public void testGenerateBytesWithAuthTagBits() {
        byte[] uuidBytes = UUIDv7a.generateBytes(secretKey, 48);
        assertNotNull(uuidBytes);
        assertEquals(16, uuidBytes.length);
    }
    
    @Test
    public void testGenerateUUID() {
        UUID uuid = UUIDv7a.generateUUID(secretKey);
        assertNotNull(uuid);
    }
    
    @Test
    public void testGenerateUUIDWithAuthTagBits() {
        UUID uuid = UUIDv7a.generateUUID(secretKey, 62);
        assertNotNull(uuid);
    }
    
    @Test
    public void testVerifyString() {
        String uuid = UUIDv7a.generateString(secretKey);
        assertTrue(UUIDv7a.verifyString(uuid, secretKey));
    }
    
    @Test
    public void testVerifyStringWithAuthTagBits() {
        String uuid = UUIDv7a.generateString(secretKey, 32);
        assertTrue(UUIDv7a.verifyString(uuid, secretKey, 32));
    }
    
    @Test
    public void testVerifyBytes() {
        byte[] uuidBytes = UUIDv7a.generateBytes(secretKey);
        assertTrue(UUIDv7a.verifyBytes(uuidBytes, secretKey));
    }
    
    @Test
    public void testVerifyBytesWithAuthTagBits() {
        byte[] uuidBytes = UUIDv7a.generateBytes(secretKey, 48);
        assertTrue(UUIDv7a.verifyBytes(uuidBytes, secretKey, 48));
    }
    
    @Test
    public void testVerifyUUID() {
        UUID uuid = UUIDv7a.generateUUID(secretKey);
        assertTrue(UUIDv7a.verifyUUID(uuid, secretKey));
    }
    
    @Test
    public void testVerifyUUIDWithAuthTagBits() {
        UUID uuid = UUIDv7a.generateUUID(secretKey, 62);
        assertTrue(UUIDv7a.verifyUUID(uuid, secretKey, 62));
    }
    
    @Test
    public void testExtractTimestamp() {
        long beforeGeneration = System.currentTimeMillis();
        UUID uuid = UUIDv7a.generateUUID(secretKey);
        long afterGeneration = System.currentTimeMillis();
        
        long timestamp = UUIDv7a.extractTimestamp(uuid);
        assertTrue(timestamp >= beforeGeneration);
        assertTrue(timestamp <= afterGeneration);
    }
    
    @Test
    public void testGenerateRandomKey() {
        byte[] key1 = UUIDv7a.generateRandomKey();
        byte[] key2 = UUIDv7a.generateRandomKey();
        
        assertNotNull(key1);
        assertNotNull(key2);
        assertEquals(32, key1.length);
        assertEquals(32, key2.length);
        assertFalse(Arrays.equals(key1, key2));
    }
    
    @Test
    public void testDeriveKeyFromPassword() {
        byte[] key1 = UUIDv7a.deriveKeyFromPassword("test123");
        byte[] key2 = UUIDv7a.deriveKeyFromPassword("test123");
        byte[] key3 = UUIDv7a.deriveKeyFromPassword("test456");
        
        assertNotNull(key1);
        assertEquals(32, key1.length);
        assertArrayEquals(key1, key2);
        assertFalse(Arrays.equals(key1, key3));
    }
    
    @Test
    public void testGetConfigDescription() {
        String desc1 = UUIDv7a.getConfigDescription(UUIDv7a.Config.HIGH_UNIQUENESS_TAG_BITS);
        String desc2 = UUIDv7a.getConfigDescription(UUIDv7a.Config.BALANCED_TAG_BITS);
        String desc3 = UUIDv7a.getConfigDescription(UUIDv7a.Config.HIGH_SECURITY_TAG_BITS);
        String desc4 = UUIDv7a.getConfigDescription(40);
        
        assertNotNull(desc1);
        assertNotNull(desc2);
        assertNotNull(desc3);
        assertNotNull(desc4);
        assertTrue(desc1.contains("高唯一性"));
        assertTrue(desc2.contains("均衡"));
        assertTrue(desc3.contains("高安全性"));
        assertTrue(desc4.contains("自定义"));
    }
    
    @Test
    public void testGetMaxIdsPerMillisecond() {
        long max1 = UUIDv7a.getMaxIdsPerMillisecond(32);
        long max2 = UUIDv7a.getMaxIdsPerMillisecond(48);
        long max3 = UUIDv7a.getMaxIdsPerMillisecond(62);
        
        assertTrue(max1 > 0);
        assertTrue(max2 > 0);
        assertTrue(max3 > 0);
        assertTrue(max1 > max2);
        assertTrue(max2 > max3);
    }
    
    @Test
    void testGenerateStringWithNullKey() {
        assertThrows(IllegalArgumentException.class, () -> {
            UUIDv7a.generateString((byte[]) null);
        });
    }
    
    @Test
    void testGenerateStringWithEmptyKey() {
        assertThrows(IllegalArgumentException.class, () -> {
            UUIDv7a.generateString(new byte[0]);
        });
    }
    
    @Test
    void testGenerateStringWithInvalidAuthTagBits() {
        assertThrows(IllegalArgumentException.class, () -> {
            UUIDv7a.generateString(secretKey, 7);
        });
    }
    
    @Test
    void testGenerateStringWithTooLargeAuthTagBits() {
        assertThrows(IllegalArgumentException.class, () -> {
            UUIDv7a.generateString(secretKey, 63);
        });
    }
    
    @Test
    public void testVerifyWithWrongKey() {
        String uuid = UUIDv7a.generateString(secretKey);
        byte[] wrongKey = UUIDv7a.generateRandomKey();
        
        assertFalse(UUIDv7a.verifyString(uuid, wrongKey));
    }
    
    @Test
    public void testVerifyWithWrongAuthTagBits() {
        String uuid = UUIDv7a.generateString(secretKey, 32);
        
        assertFalse(UUIDv7a.verifyString(uuid, secretKey, 48));
    }
    
    @Test
    public void testVerifyInvalidUUIDString() {
        assertFalse(UUIDv7a.verifyString("invalid-uuid", secretKey));
        assertFalse(UUIDv7a.verifyString(null, secretKey));
        assertFalse(UUIDv7a.verifyString("", secretKey));
    }
    
    @Test
    public void testVerifyInvalidUUIDBytes() {
        assertFalse(UUIDv7a.verifyBytes(null, secretKey));
        assertFalse(UUIDv7a.verifyBytes(new byte[15], secretKey));
        assertFalse(UUIDv7a.verifyBytes(new byte[17], secretKey));
    }
    
    @Test
    public void testTimeOrdering() throws InterruptedException {
        UUID uuid1 = UUIDv7a.generateUUID(secretKey);
        Thread.sleep(1);
        UUID uuid2 = UUIDv7a.generateUUID(secretKey);
        
        long ts1 = UUIDv7a.extractTimestamp(uuid1);
        long ts2 = UUIDv7a.extractTimestamp(uuid2);
        
        assertTrue(ts2 >= ts1);
        assertTrue(uuid1.compareTo(uuid2) <= 0);
    }
    
    @Test
    public void testDifferentConfigurations() {
        int[] configs = {
            UUIDv7a.Config.HIGH_UNIQUENESS_TAG_BITS,
            UUIDv7a.Config.BALANCED_TAG_BITS,
            UUIDv7a.Config.HIGH_SECURITY_TAG_BITS
        };
        
        for (int authTagBits : configs) {
            UUID uuid = UUIDv7a.generateUUID(secretKey, authTagBits);
            assertTrue(UUIDv7a.verifyUUID(uuid, secretKey, authTagBits));
            
            // 验证版本号应为 F
            long msb = uuid.getMostSignificantBits();
            int version = (int) ((msb >>> 12) & 0xF);
            assertEquals(0xF, version);
            
            // 验证变体号应为 10 (二进制)
            long lsb = uuid.getLeastSignificantBits();
            int variant = (int) (lsb >>> 62);
            assertEquals(0x2, variant);
        }
    }
    
    @Test
    public void testTamperingDetection() {
        // 生成多个 UUID 并测试，确保测试的健壮性
        for (int i = 0; i < 10; i++) {
            String uuid = UUIDv7a.generateString(secretKey);
            
            // 篡改最后一个字符（LSB部分，包含认证标签）
            char lastChar = uuid.charAt(uuid.length() - 1);
            char tamperedChar = lastChar == '0' ? 'f' : '0';
            String tampered1 = uuid.substring(0, uuid.length() - 1) + tamperedChar;
            assertFalse(UUIDv7a.verifyString(tampered1, secretKey), 
                "Tampered UUID should fail verification: " + uuid + " -> " + tampered1);
            
            // 篡改中间部分（非连字符位置）
            char[] chars = uuid.toCharArray();
            // 找到第一个非连字符位置并篡改
            for (int j = 0; j < chars.length; j++) {
                if (chars[j] != '-') {
                    char original = chars[j];
                    chars[j] = original == '0' ? 'f' : '0';
                    String tampered2 = new String(chars);
                    assertFalse(UUIDv7a.verifyString(tampered2, secretKey),
                        "Tampered UUID should fail verification at position " + j + ": " + uuid + " -> " + tampered2);
                    break;
                }
            }
        }
    }
    
    // ========== 实例方法测试 ==========
    
    @Test
    public void testInstanceCreationWithSecretKey() {
        UUIDv7a generator = new UUIDv7a(secretKey);
        assertNotNull(generator);
    }
    
    @Test
    public void testInstanceCreationWithSecretKeyAndAuthTagBits() {
        UUIDv7a generator = new UUIDv7a(secretKey, 32);
        assertNotNull(generator);
    }
    
    @Test
    public void testInstanceCreationWithPassword() {
        UUIDv7a generator = new UUIDv7a("password123");
        assertNotNull(generator);
    }
    
    @Test
    public void testInstanceCreationWithPasswordAndAuthTagBits() {
        UUIDv7a generator = new UUIDv7a("password123", 56);
        assertNotNull(generator);
    }
    
    @Test
    public void testInstanceGenerateString() {
        UUIDv7a generator = new UUIDv7a(secretKey);
        String uuid = generator.generateString();
        
        assertNotNull(uuid);
        assertEquals(36, uuid.length());
        assertTrue(uuid.matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"));
    }
    
    @Test
    public void testInstanceGenerateBytes() {
        UUIDv7a generator = new UUIDv7a(secretKey);
        byte[] uuidBytes = generator.generateBytes();
        
        assertNotNull(uuidBytes);
        assertEquals(16, uuidBytes.length);
    }
    
    @Test
    public void testInstanceGenerate() {
        UUIDv7a generator = new UUIDv7a(secretKey);
        UUID uuid = generator.generate();
        
        assertNotNull(uuid);
    }
    
    @Test
    public void testInstanceVerifyString() {
        UUIDv7a generator = new UUIDv7a(secretKey);
        String uuid = generator.generateString();
        
        assertTrue(generator.verifyString(uuid));
    }
    
    @Test
    public void testInstanceVerifyBytes() {
        UUIDv7a generator = new UUIDv7a(secretKey);
        byte[] uuidBytes = generator.generateBytes();
        
        assertTrue(generator.verifyBytes(uuidBytes));
    }
    
    @Test
    public void testInstanceVerify() {
        UUIDv7a generator = new UUIDv7a(secretKey);
        UUID uuid = generator.generate();
        
        assertTrue(generator.verify(uuid));
    }
    
    @Test
    public void testInstanceVerifyFailsWithWrongKey() {
        UUIDv7a generator1 = new UUIDv7a(secretKey);
        String uuid = generator1.generateString();
        
        byte[] differentKey = new byte[32];
        Arrays.fill(differentKey, (byte) 0x99);
        UUIDv7a generator2 = new UUIDv7a(differentKey);
        
        assertFalse(generator2.verifyString(uuid));
    }
    
    @Test
    public void testInstanceGetConfigDescription() {
        UUIDv7a generator1 = new UUIDv7a(secretKey, UUIDv7a.Config.HIGH_UNIQUENESS_TAG_BITS);
        assertEquals("高唯一性配置 (42位随机 + 32位标签)", generator1.getConfigDescription());
        
        UUIDv7a generator2 = new UUIDv7a(secretKey, UUIDv7a.Config.BALANCED_TAG_BITS);
        assertEquals("均衡配置 (26位随机 + 48位标签)", generator2.getConfigDescription());
        
        UUIDv7a generator3 = new UUIDv7a(secretKey, UUIDv7a.Config.HIGH_SECURITY_TAG_BITS);
        assertEquals("高安全性配置 (12位随机 + 62位标签)", generator3.getConfigDescription());
    }
    
    @Test
    public void testInstanceGetMaxIdsPerMillisecond() {
        UUIDv7a generator = new UUIDv7a(secretKey, 48);
        long maxIds = generator.getMaxIdsPerMillisecond();
        assertTrue(maxIds > 0);
    }
    
    @Test
    public void testInstanceMultipleGenerations() {
        UUIDv7a generator = new UUIDv7a(secretKey);
        
        String uuid1 = generator.generateString();
        String uuid2 = generator.generateString();
        String uuid3 = generator.generateString();
        
        assertNotEquals(uuid1, uuid2);
        assertNotEquals(uuid2, uuid3);
        assertNotEquals(uuid1, uuid3);
        
        assertTrue(generator.verifyString(uuid1));
        assertTrue(generator.verifyString(uuid2));
        assertTrue(generator.verifyString(uuid3));
    }
    
    @Test
    public void testInstanceWithDifferentConfigs() {
        UUIDv7a gen32 = new UUIDv7a(secretKey, 32);
        UUIDv7a gen48 = new UUIDv7a(secretKey, 48);
        UUIDv7a gen62 = new UUIDv7a(secretKey, 62);
        
        String uuid32 = gen32.generateString();
        String uuid48 = gen48.generateString();
        String uuid62 = gen62.generateString();
        
        assertTrue(gen32.verifyString(uuid32));
        assertTrue(gen48.verifyString(uuid48));
        assertTrue(gen62.verifyString(uuid62));
        
        // 使用错误的配置验证应失败
        assertFalse(gen32.verifyString(uuid48));
        assertFalse(gen48.verifyString(uuid62));
        assertFalse(gen62.verifyString(uuid32));
    }
    
    @Test
    public void testInstancePasswordBasedGeneration() {
        UUIDv7a generator = new UUIDv7a("mySecurePassword");
        
        String uuid = generator.generateString();
        assertTrue(generator.verifyString(uuid));
        
        // 相同密码应该能验证
        UUIDv7a generator2 = new UUIDv7a("mySecurePassword");
        assertTrue(generator2.verifyString(uuid));
        
        // 不同密码应该失败
        UUIDv7a generator3 = new UUIDv7a("differentPassword");
        assertFalse(generator3.verifyString(uuid));
    }
    
    @Test
    public void testInstanceSecretKeyDefensiveCopy() {
        byte[] key = new byte[32];
        Arrays.fill(key, (byte) 0x42);
        
        UUIDv7a generator = new UUIDv7a(key);
        String uuid1 = generator.generateString();
        
        // 修改原始密钥不应影响生成器
        Arrays.fill(key, (byte) 0x00);
        String uuid2 = generator.generateString();
        
        assertTrue(generator.verifyString(uuid1));
        assertTrue(generator.verifyString(uuid2));
    }
}
