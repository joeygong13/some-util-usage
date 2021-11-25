
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.springframework.core.io.ClassPathResource;

import javax.crypto.Cipher;
import java.io.FileReader;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/*
 * 使用了
 *         <dependency>
 *           <groupId>org.bouncycastle</groupId>
 *           <artifactId>bcprov-jdk16</artifactId>
 *           <version>1.46</version>
 *       </dependency>
 *
 * 如果不使用第三方工具读取的话，可以使用
 * //        byte[] bytes = Files.readAllBytes(file.getFile().toPath());
 * //        String key = new String(bytes, StandardCharsets.UTF_8);
 * //        String privateKeyPEM = key.replace("-----BEGIN OPENSSH PRIVATE KEY-----", "")
 * //                .replaceAll(System.lineSeparator(), "")
 * //                .replace("-----END OPENSSH PRIVATE KEY-----", "");
 * //        byte[] keyBytes = Base64.decodeBase64(privateKeyPEM);
 *
 */
public class MsgCrypt {

    private final PrivateKey privateKey;

    private final PublicKey publicKey;

    public MsgCrypt() {
        Security.addProvider(new BouncyCastleProvider());
        KeyFactory keyFactory = null;
        try {
            keyFactory = KeyFactory.getInstance("RSA");
        }catch (Exception e) {
            throw new RuntimeException("Get KeyFactory with RSA error", e);
        }

        ClassPathResource privateFile = new ClassPathResource("rsa/msg_private.pem");
        try(FileReader keyReader = new FileReader(privateFile.getFile())) {
            PemReader pemReader = new PemReader(keyReader);
            byte[] content = pemReader.readPemObject().getContent();

            KeySpec keySpec = new PKCS8EncodedKeySpec(content);
            privateKey = keyFactory.generatePrivate(keySpec);
        }catch (Exception e) {
            throw new RuntimeException("Read private key failed", e);
        }


        ClassPathResource publicFile = new ClassPathResource("rsa/msg_public.pem");

        try (FileReader keyReader = new FileReader(publicFile.getFile());
             PemReader pemReader = new PemReader(keyReader)) {

            PemObject pemObject = pemReader.readPemObject();
            byte[] content = pemObject.getContent();
            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(content);
            publicKey = keyFactory.generatePublic(pubKeySpec);
        }catch (Exception e) {
            throw new RuntimeException("Read public key failed", e);
        }
    }

    public String encrypt(byte[] bytes) throws Exception{
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, this.publicKey);
        byte[] ret = cipher.doFinal(bytes);
        byte[] base64 = Base64.encodeBase64(ret);
        return new String(base64);
    }

    public String decrypt(byte[] bytes) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, this.privateKey);
        byte[] ret = cipher.doFinal(bytes);
        return new String(ret);
    }
}
