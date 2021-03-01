package org.example.jwtdemo;

import org.apache.commons.codec.binary.Base64;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.keys.AesKey;
import org.jose4j.lang.JoseException;
import org.junit.Before;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;

public class JwtVerifiedAndDecodeTest {
    protected String signingSecretKey = "jofnuCF7ZtQEg9vc4-jzlSM3s9QmgFb618h2ijcuCU-OnWXuMCgd-6epfAR62Qvn43Uyn1TPwwcVrvft6YJGgw";
    protected String secret = "IbRBuezjJ65uuLBQ-eaMvVty8nd4nxZzIoIF-yLQEQc";


    protected Key signingKey = null;
    protected Key secretKeyEncryptionKey = null;

    @Before
    public void setUp() throws Exception {
        signingKey = new AesKey(signingSecretKey.getBytes(StandardCharsets.UTF_8));
        HashMap keys = new HashMap<String, Object>(2);
        keys.put("kty", "oct");
        keys.put("k", secret);
        secretKeyEncryptionKey = JsonWebKey.Factory.newJwk(keys).getKey();
    }

    /**
     * 验签
     * @param value 待验证字符串
     * @param signingKey 签名key
     * @return
     * @throws JoseException
     */
    public static boolean verifySignature(String value,Key signingKey) throws JoseException {
        JsonWebSignature jws = new JsonWebSignature();
        jws.setCompactSerialization(value);
        jws.setKey(signingKey);
        return jws.verifySignature();
    }


    public static String getEncodedPayload(String value) throws JoseException {
        JsonWebSignature jws = new JsonWebSignature();
        jws.setCompactSerialization(value);
        return jws.getEncodedPayload();
    }

    @Test
    public void decode() throws Exception{
        String token = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.ZXlKNmFYQWlPaUpFUlVZaUxDSmhiR2NpT2lKa2FYSWlMQ0psYm1NaU9pSkJNVEk0UTBKRExVaFRNalUySWl3aVkzUjVJam9pU2xkVUlpd2lkSGx3SWpvaVNsZFVJbjAuLko2WEhTRGs2d0R1V0d6MXE3a1pBbkEuN3laU0ZueDVYTEpsSmpOV3RiR2RiUEhvRXNMOFlwbU9uVmRTWko3VXp1VHJaVVZzZFZvSWlsam9WRGpKUThBVFJIUVpSYTVUc2RnS3lqNGgyeVZiOGtFWE1hWFpQQ0psdjZCUDN4bW44aUFlNzZvS05qa09SZVBienYtbUVwX3AydU5VT0lzc1J4TWFYZkVlRkh1dEE4WlRhclIwRmZWUC1vczB6LUF5dlpOdWpac0FPUEFqcjV0VDlKNDAzSzRRckJwU3BRaFd5TkI3QUp0U3lVcUE1NkhtZUdDOUdBREtRMzl1WTNTVHVZLUU0Sm1uQXd6MVMwdExEWlpVX3JXTURCUVpqSlQ4V2swSUY1ejdRTXVPMncuNDZYOEJZWGt6elQ4NThyZGp4UGtXdw.nsgqDb8xJdQ5QUs4oFJ1jX2tuQuZpAfTDkbIKLw8fOHDmEOHtLC4mx9jik03KGQb0AjjmPOL816F7tzNAvtazQ";
        boolean verified = verifySignature(token,signingKey);
        if (verified) {
            String payload = getEncodedPayload(token);
            byte[] encoded = Base64.decodeBase64(payload);
            if (encoded != null && encoded.length > 0){
                String encodedObj = new String(encoded, StandardCharsets.UTF_8);
                JsonWebEncryption jwe = new JsonWebEncryption();
                jwe.setKey(secretKeyEncryptionKey);
                jwe.setCompactSerialization(encodedObj);
                System.out.println(jwe.getPayload());
            }
        }
    }

    @Test
    public void encode() throws JoseException {
        String value = "{\"sub\":\"casuser\",\"roles\":[],\"iss\":\"https:\\/\\/cas.example.org:8443\\/cas\",\"nonce\":\"\",\"client_id\":\"clientid\",\"aud\":\"clientid\",\"grant_type\":\"PASSWORD\",\"permissions\":[],\"scope\":[],\"claims\":[],\"scopes\":[],\"state\":\"\",\"exp\":1614354640,\"iat\":1614325840,\"jti\":\"AT-1-U3I-bSR3WaNuBQAiKd4u2PPSp1dM9s5b\"}";
        String encryptionMethodHeaderParameter = "A128CBC-HS256";
        JsonWebEncryption jwe = new JsonWebEncryption();
        jwe.setPayload(value);
        jwe.enableDefaultCompression();
        jwe.setAlgorithmHeaderValue("dir");
        jwe.setEncryptionMethodHeaderParameter(encryptionMethodHeaderParameter);
        jwe.setKey(secretKeyEncryptionKey);
        jwe.setContentTypeHeaderValue("JWT");
        jwe.setHeader("typ", "JWT");

        Map<String, Object> customHeaders = null;
        if (false) {
            customHeaders.forEach((k, v) -> jwe.setHeader(k, v.toString()));
        }

        if (false) {
            String keyIdHeaderValue = "";
            jwe.setKeyIdHeaderValue(keyIdHeaderValue);
        }

        String encoded = jwe.getCompactSerialization();
        System.out.println("encodedValue="+encoded);


        // sign
        JsonWebSignature jws = new JsonWebSignature();
        String algHeaderValue = "HS512"; //簽名
        byte[] bytes = encoded.getBytes(StandardCharsets.UTF_8);
        String base64 = Base64.encodeBase64URLSafeString(bytes);
        jws.setEncodedPayload(base64);
        jws.setAlgorithmHeaderValue(algHeaderValue);
        jws.setKey(signingKey);
        jws.setHeader("typ", "JWT");
        if (false) {
            customHeaders.forEach((k, v) -> jws.setHeader(k, v.toString()));
        }
        bytes = jws.getCompactSerialization().getBytes(StandardCharsets.UTF_8);
        String signValue = new String(bytes, StandardCharsets.UTF_8);
        System.out.println("signValue="+signValue);

    }

}
