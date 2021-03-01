package org.example.jwtdemo;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.lang.JoseException;
import org.junit.Before;
import org.junit.Test;
import org.springframework.core.io.ClassPathResource;


import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Map;

import static org.springframework.util.ResourceUtils.CLASSPATH_URL_PREFIX;

public class JwtRSAVerifiedAndDecodeTest {

    protected Key signingKey = null;
    protected Key secretKeyEncryptionKey = null;

    @Before
    public void configureKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        ClassPathResource privateResource = new ClassPathResource("classpath:/private.key".substring(CLASSPATH_URL_PREFIX.length()));
        Reader in = new InputStreamReader(privateResource.getInputStream(), StandardCharsets.UTF_8);
        BufferedReader br = new BufferedReader(in);
        PEMParser pemParser = new PEMParser(br);
        PEMKeyPair pemKeyPair = (PEMKeyPair) pemParser.readObject();
        PrivateKey privateKey = new JcaPEMKeyConverter().getKeyPair(pemKeyPair).getPrivate();
        System.out.println(privateKey);

        ClassPathResource publicResource = new ClassPathResource("classpath:/public.key".substring(CLASSPATH_URL_PREFIX.length()));
        // read pem
//        PemReader reader = new PemReader(new InputStreamReader(publicResource.getInputStream(), StandardCharsets.UTF_8));
//        PemObject pemObject = reader.readPemObject();
//        byte[] content = pemObject.getContent();
//        X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(content);
//        KeyFactory rsa = KeyFactory.getInstance("RSA");
//        PublicKey publicKey = rsa.generatePublic(pubSpec);
//        System.out.println(publicKey);

        //read der
        InputStream publicKey = publicResource.getInputStream();
        byte[] bytes = new byte[(int) publicResource.contentLength()];
        publicKey.read(bytes);
        X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(bytes);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        PublicKey publicKey1 = factory.generatePublic(pubSpec);
        System.out.println(publicKey1);

        signingKey = privateKey;
        secretKeyEncryptionKey = publicKey1;
    }


    @Test
    public void encode() throws JoseException {
        String value = "{\"sub\":\"casuser\",\"roles\":[],\"iss\":\"https:\\/\\/cas.example.org:8443\\/cas\",\"nonce\":\"\",\"client_id\":\"clientid\",\"aud\":\"clientid\",\"grant_type\":\"PASSWORD\",\"permissions\":[],\"scope\":[],\"claims\":[],\"scopes\":[],\"state\":\"\",\"exp\":1614364566,\"iat\":1614335766,\"jti\":\"AT-1-XxIR609Bfx1evOCwxAzIf9P3GTV1Vm9R\"}";
        String encryptionMethodHeaderParameter = "A128CBC-HS256";
        JsonWebEncryption jwe = new JsonWebEncryption();
        jwe.setPayload(value);
        jwe.enableDefaultCompression();
        jwe.setAlgorithmHeaderValue("RSA-OAEP-256");
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
        byte[] bytes = encoded.getBytes(StandardCharsets.UTF_8);
        String base64 = Base64.encodeBase64URLSafeString(bytes);
        JsonWebSignature jws = new JsonWebSignature();
        String algHeaderValue = "RS512"; //簽名

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

    @Test
    public void decode() throws JoseException, NoSuchAlgorithmException, InvalidKeySpecException {
        String value = "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.ZXlKNmFYQWlPaUpFUlVZaUxDSmhiR2NpT2lKU1UwRXRUMEZGVUMweU5UWWlMQ0psYm1NaU9pSkJNVEk0UTBKRExVaFRNalUySWl3aVkzUjVJam9pU2xkVUlpd2lkSGx3SWpvaVNsZFVJbjAuckg2YUE0d20xX1gxRC1QSHljWkJRdkNpTVZVd3JVcFFJUVF1RWlpS3FTYXhBMmQ4ZEJrNjFFcUJoWE5fek5QX0ViX244TDV1Mzg3NVAxVFN4Qk9aNUwyVzBkVmpQNTFEeU9NNEtRY2RHbXVieDl6LWR6bkdGdXE1c1RlTGZWMklNc0tSaVJaTkNpZzlNY29CdUE2UnIxSFFrVE5fOHM0WU9uNEJPaUJyV0NXem9TWWYwYkxYV2Nqd0ltQlZKUWhrSGlydFYyTjc4azlhYVloUjBYTE1SY3JkM0JTdGRCNW92S2Ryc1JYWkJjeXItRlVmSnJuR0ZPc1IzVTZwZ25kOGV5SjlHMlpRWUU2d05pTXRCM1JVZkpXRzBWX3ZqYWxVSmxpT2RVZ1RVd1MyVkNhLXFuZEIxdm5JbGNoLVEwelppZ1pMbXU2dXh4N25NRnQtV1F1U1ZnLjllTlpLb0thQjRCU2NRYjUwak84cncudWN3V2dnVEdLcmRyeWJwR2pDWlYwTWJzRjF0X05kUEp1T1lFQ3hjN1QtZV8zSFVGamVYS2pEdnNjRjIwSTd2MWM1WDNHY1Z5emNpTEJBZU9xQ2tsR21WUG1pMmlEY1otN2k3UmdoeHBQVmkyN2JNTzR2eHpTem15Qm9PTHI1azJ3am9EVGtzcHRGRGZBVndpUURVTlVETHBWWXJGVnBBM0VuNUZiR2JKZ0czUmVIaGFJZXdWSHV4S0dGa3ZCaUxkMDUzWS1DMlk3MUs0YzNiQWg1WlEzcEJjTGcwVGU4T3ppU29QelI3TjJLTzlsZ2ZpR2RhOU1zWnBzUEFiZjBsRUhMZHJaRHFzSk9EejdnU2Q2cnpEVWcua05FdWtqRUlqT1hQU3RfQlZtQ1ZCQQ.zkQnvz9dxBsh2zj3JOAJqPL2rZerxTtiMk4rR8mZYCy5hRJpBDSNxGP6myjlLRkV4j16Kx9lSwzBX2qrnE53l0DxFdtlDTWcJ3NNre6VSXTtchAcs-bJvtHgLWIDbgZNJsw-tSp-XM3MCH0T2epP6GInsvCROISJL3FbH4SG72hVACoSFYh5oCj1fM640c8CUq1LJ0HnCz7Bdu4fFoVUg1TVAuBBzQM8JZ4UoVAz4tAA2ugbhQGBeVdG7mSXwC3cuAQHGi0rjhWF9CMuNjSwkvgK7KlRa1l7TixPXJbi6y0dR1Sbow9qdcoWk0gJeddl3HS7XSc1w0rgnRu8IXSDTA";
        RSAPrivateKey privKey = RSAPrivateKey.class.cast(this.signingKey);
        RSAPublicKeySpec keySpec = new RSAPublicKeySpec(privKey.getModulus(), BigInteger.valueOf(65537));
        PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(keySpec);

        JsonWebSignature jws = new JsonWebSignature();
        jws.setCompactSerialization(new String(value.getBytes(StandardCharsets.UTF_8),StandardCharsets.UTF_8));
        jws.setKey(publicKey);
        boolean b = jws.verifySignature();
        if (b){
            String encodedPayload = jws.getEncodedPayload();
            System.out.println(encodedPayload);
            JsonWebEncryption jwe = new JsonWebEncryption();
            jwe.setKey(signingKey);
            jwe.setCompactSerialization(new String(Base64.decodeBase64(encodedPayload), StandardCharsets.UTF_8));
            String payload = jwe.getPayload();
            System.out.println(payload);
        }
    }
}
