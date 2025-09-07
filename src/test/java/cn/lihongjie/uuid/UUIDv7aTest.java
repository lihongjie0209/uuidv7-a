package cn.lihongjie.uuid;

import org.junit.Test;
import org.junit.Before;
import org.junit.Assert;
import java.util.UUID;
import java.util.Arrays;

/**
 * UUIDv7a 单元测试
 * 
 * @author lihongjie
 */
public class UUIDv7aTest {
    
    private byte[] secretKey;
    
    @Before
    public void setUp() {
        secretKey = new byte[32];
        Arrays.fill(secretKey, (byte) 0x42); // 固定密钥用于测试
    }
    
    @Test
    public void testGenerateString() {
        String uuid = UUIDv7a.generateString(secretKey);
        Assert.assertNotNull(uuid);
        Assert.assertEquals(36, uuid.length());
        Assert.assertTrue(uuid.matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"));
    }
    
    @Test
    public void testGenerateStringWithAuthTagBits() {
        String uuid = UUIDv7a.generateString(secretKey, 32);
        Assert.assertNotNull(uuid);
        Assert.assertEquals(36, uuid.length());
    }
    
    @Test
    public void testGenerateStringWithPassword() {
        String uuid = UUIDv7a.generateString("password123");
        Assert.assertNotNull(uuid);
        Assert.assertEquals(36, uuid.length());
    }
    
    @Test
    public void testGenerateBytes() {
        byte[] uuidBytes = UUIDv7a.generateBytes(secretKey);
        Assert.assertNotNull(uuidBytes);
        Assert.assertEquals(16, uuidBytes.length);
    }
    
    @Test
    public void testGenerateBytesWithAuthTagBits() {
        byte[] uuidBytes = UUIDv7a.generateBytes(secretKey, 48);
        Assert.assertNotNull(uuidBytes);
        Assert.assertEquals(16, uuidBytes.length);
    }
    
    @Test
    public void testGenerateUUID() {
        UUID uuid = UUIDv7a.generateUUID(secretKey);
        Assert.assertNotNull(uuid);
    }
    
    @Test
    public void testGenerateUUIDWithAuthTagBits() {
        UUID uuid = UUIDv7a.generateUUID(secretKey, 62);
        Assert.assertNotNull(uuid);
    }
    
    @Test
    public void testVerifyString() {
        String uuid = UUIDv7a.generateString(secretKey);
        Assert.assertTrue(UUIDv7a.verifyString(uuid, secretKey));
    }
    
    @Test
    public void testVerifyStringWithAuthTagBits() {
        String uuid = UUIDv7a.generateString(secretKey, 32);
        Assert.assertTrue(UUIDv7a.verifyString(uuid, secretKey, 32));
    }
    
    @Test
    public void testVerifyBytes() {
        byte[] uuidBytes = UUIDv7a.generateBytes(secretKey);
        Assert.assertTrue(UUIDv7a.verifyBytes(uuidBytes, secretKey));
    }
    
    @Test
    public void testVerifyBytesWithAuthTagBits() {
        byte[] uuidBytes = UUIDv7a.generateBytes(secretKey, 48);
        Assert.assertTrue(UUIDv7a.verifyBytes(uuidBytes, secretKey, 48));
    }
    
    @Test
    public void testVerifyUUID() {
        UUID uuid = UUIDv7a.generateUUID(secretKey);
        Assert.assertTrue(UUIDv7a.verifyUUID(uuid, secretKey));
    }
    
    @Test
    public void testVerifyUUIDWithAuthTagBits() {
        UUID uuid = UUIDv7a.generateUUID(secretKey, 62);
        Assert.assertTrue(UUIDv7a.verifyUUID(uuid, secretKey, 62));
    }
    
    @Test
    public void testExtractTimestamp() {
        long beforeGeneration = System.currentTimeMillis();
        UUID uuid = UUIDv7a.generateUUID(secretKey);
        long afterGeneration = System.currentTimeMillis();
        
        long timestamp = UUIDv7a.extractTimestamp(uuid);
        Assert.assertTrue(timestamp >= beforeGeneration);
        Assert.assertTrue(timestamp <= afterGeneration);
    }
    
    @Test
    public void testGenerateRandomKey() {
        byte[] key1 = UUIDv7a.generateRandomKey();
        byte[] key2 = UUIDv7a.generateRandomKey();
        
        Assert.assertNotNull(key1);
        Assert.assertNotNull(key2);
        Assert.assertEquals(32, key1.length);
        Assert.assertEquals(32, key2.length);
        Assert.assertFalse(Arrays.equals(key1, key2));
    }
    
    @Test
    public void testDeriveKeyFromPassword() {
        byte[] key1 = UUIDv7a.deriveKeyFromPassword("test123");
        byte[] key2 = UUIDv7a.deriveKeyFromPassword("test123");
        byte[] key3 = UUIDv7a.deriveKeyFromPassword("test456");
        
        Assert.assertNotNull(key1);
        Assert.assertEquals(32, key1.length);
        Assert.assertArrayEquals(key1, key2);
        Assert.assertFalse(Arrays.equals(key1, key3));
    }
    
    @Test
    public void testGetConfigDescription() {
        String desc1 = UUIDv7a.getConfigDescription(UUIDv7a.Config.HIGH_UNIQUENESS_TAG_BITS);
        String desc2 = UUIDv7a.getConfigDescription(UUIDv7a.Config.BALANCED_TAG_BITS);
        String desc3 = UUIDv7a.getConfigDescription(UUIDv7a.Config.HIGH_SECURITY_TAG_BITS);
        String desc4 = UUIDv7a.getConfigDescription(40);
        
        Assert.assertNotNull(desc1);
        Assert.assertNotNull(desc2);
        Assert.assertNotNull(desc3);
        Assert.assertNotNull(desc4);
        Assert.assertTrue(desc1.contains("高唯一性"));
        Assert.assertTrue(desc2.contains("均衡"));
        Assert.assertTrue(desc3.contains("高安全性"));
        Assert.assertTrue(desc4.contains("自定义"));
    }
    
    @Test
    public void testGetMaxIdsPerMillisecond() {
        long max1 = UUIDv7a.getMaxIdsPerMillisecond(32);
        long max2 = UUIDv7a.getMaxIdsPerMillisecond(48);
        long max3 = UUIDv7a.getMaxIdsPerMillisecond(62);
        
        Assert.assertTrue(max1 > 0);
        Assert.assertTrue(max2 > 0);
        Assert.assertTrue(max3 > 0);
        Assert.assertTrue(max1 > max2);
        Assert.assertTrue(max2 > max3);
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void testGenerateStringWithNullKey() {
        UUIDv7a.generateString((byte[]) null);
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void testGenerateStringWithEmptyKey() {
        UUIDv7a.generateString(new byte[0]);
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void testGenerateStringWithInvalidAuthTagBits() {
        UUIDv7a.generateString(secretKey, 7);
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void testGenerateStringWithTooLargeAuthTagBits() {
        UUIDv7a.generateString(secretKey, 63);
    }
    
    @Test
    public void testVerifyWithWrongKey() {
        String uuid = UUIDv7a.generateString(secretKey);
        byte[] wrongKey = UUIDv7a.generateRandomKey();
        
        Assert.assertFalse(UUIDv7a.verifyString(uuid, wrongKey));
    }
    
    @Test
    public void testVerifyWithWrongAuthTagBits() {
        String uuid = UUIDv7a.generateString(secretKey, 32);
        
        Assert.assertFalse(UUIDv7a.verifyString(uuid, secretKey, 48));
    }
    
    @Test
    public void testVerifyInvalidUUIDString() {
        Assert.assertFalse(UUIDv7a.verifyString("invalid-uuid", secretKey));
        Assert.assertFalse(UUIDv7a.verifyString(null, secretKey));
        Assert.assertFalse(UUIDv7a.verifyString("", secretKey));
    }
    
    @Test
    public void testVerifyInvalidUUIDBytes() {
        Assert.assertFalse(UUIDv7a.verifyBytes(null, secretKey));
        Assert.assertFalse(UUIDv7a.verifyBytes(new byte[15], secretKey));
        Assert.assertFalse(UUIDv7a.verifyBytes(new byte[17], secretKey));
    }
    
    @Test
    public void testTimeOrdering() throws InterruptedException {
        UUID uuid1 = UUIDv7a.generateUUID(secretKey);
        Thread.sleep(1);
        UUID uuid2 = UUIDv7a.generateUUID(secretKey);
        
        long ts1 = UUIDv7a.extractTimestamp(uuid1);
        long ts2 = UUIDv7a.extractTimestamp(uuid2);
        
        Assert.assertTrue(ts2 >= ts1);
        Assert.assertTrue(uuid1.compareTo(uuid2) <= 0);
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
            Assert.assertTrue(UUIDv7a.verifyUUID(uuid, secretKey, authTagBits));
            
            // 验证版本号应为 F
            long msb = uuid.getMostSignificantBits();
            int version = (int) ((msb >>> 12) & 0xF);
            Assert.assertEquals(0xF, version);
            
            // 验证变体号应为 10 (二进制)
            long lsb = uuid.getLeastSignificantBits();
            int variant = (int) (lsb >>> 62);
            Assert.assertEquals(0x2, variant);
        }
    }
    
    @Test
    public void testTamperingDetection() {
        String uuid = UUIDv7a.generateString(secretKey);
        
        // 篡改最后一个字符
        String tampered1 = uuid.substring(0, uuid.length() - 1) + "0";
        Assert.assertFalse(UUIDv7a.verifyString(tampered1, secretKey));
        
        // 篡改中间字符
        char[] chars = uuid.toCharArray();
        chars[10] = chars[10] == '0' ? '1' : '0';
        String tampered2 = new String(chars);
        Assert.assertFalse(UUIDv7a.verifyString(tampered2, secretKey));
    }
}
