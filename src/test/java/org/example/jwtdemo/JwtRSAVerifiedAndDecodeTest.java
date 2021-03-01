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
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
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
    public void decode() throws JoseException {
        String encryptionMethodHeaderParameter = "A128CBC-HS256";
        String value = "eyJ6aXAiOiJERUYiLCJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiY3R5IjoiSldUIiwidHlwIjoiSldUIn0.G1u6ogp2EuhXrSXaH_7ReqQL-XILIL2wanfEtbchyjdH_AwxZYT7WfZUeLWrnHS_sCxUiODOikHIsOKuvZpfb_7cl1wfibq2pyfn6BbDya7IAqjNfmi3EP0Rj1CsI7hAE4XUkX0gkbp3IMTUsiPj3nQTr8DtcZ3oVGk3lxAnsPofAHMCQupaD9mNy55KfRW6dBawvP1O_jyj910EGnV6I8kw4kygPxChtKI8dVwtKKvXQ4IqjYAgG_5e93q8wCQ73oQgfcKoqn7UNvZtzr2Zyv9cPq3OQOsLYGiRnlm7O8G6o1liuhHZa-yvgsUHnEZ-5DzBeXrpFof6yylGwi2TbQ.HZBp4Q22j5f2lyZApaf6TA.iL5Nzj2HOK4a07IDT2kniAP0G3BAEhhs0oRb2nLrWiusAIo8cglBSiKz1P90HwfMtd77RcemCeLm1A1aLI4e7QWbJCIn2EtBRxHBGVkB9XxCYmPsb4KjBClsQnEei6e34_K51PwdqAWH6oZFNSmX-vmkclB8Csm7RZQQ1Gngwa5BWN8FDKaqLZpERSZ006TmnHJ7UPVSy3Rm0D35quW7vhFJ28kFwJ_Qs1rfvReoROtukFBuzhIkEw1Y0PQ5_kBcbhiE1a5o-UkijnO_SFC68w.Njw3xWZV8MuZQB7YLNu8yA";
        JsonWebEncryption jwe = new JsonWebEncryption();
        jwe.setPayload(value);
        jwe.enableDefaultCompression();
        jwe.setAlgorithmHeaderValue("RSA-OAEP-256");
        jwe.setEncryptionMethodHeaderParameter(encryptionMethodHeaderParameter);
        jwe.setKey(signingKey);
        jwe.setContentTypeHeaderValue("JWT");
        jwe.setHeader("typ", "JWT");
        String encoded = jwe.getCompactSerialization();
        System.out.println("encodedValue="+encoded);
    }
}
