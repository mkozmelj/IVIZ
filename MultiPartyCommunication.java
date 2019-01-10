package isp.handson;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.*;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

/**
 * This example demonstrates a multi-party communication, that is a communication between
 * more than two agents.
 */
public class MultiPartyCommunication {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        Environment env = new Environment();

        env.add(new Agent("alice") {
            public void task() throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {
                KeyPairGenerator aliceKG = KeyPairGenerator.getInstance("DH");
                aliceKG.initialize(2048);
                KeyPair aliceKeyPair = aliceKG.generateKeyPair();

                //kreira javni ključ in ga pošlje bobu
                final byte[] alicePubKey = aliceKeyPair.getPublic().getEncoded();
                send("bob", alicePubKey);

                final byte[] charliePubKeyE = receive("charlie");
                KeyFactory charlieKeyFac = KeyFactory.getInstance("DH");
                X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(charliePubKeyE);

                PublicKey charliePubKey = charlieKeyFac.generatePublic(x509KeySpec);

                KeyAgreement aliceKeyAgree = KeyAgreement.getInstance("DH");
                aliceKeyAgree.init(aliceKeyPair.getPrivate());
                Key ac = aliceKeyAgree.doPhase(charliePubKey, false);
                send("bob", ac.getEncoded());

                final byte[] bcE = receive("charlie");
                x509KeySpec = new X509EncodedKeySpec((bcE));
                PublicKey bobPubKey = charlieKeyFac.generatePublic(x509KeySpec);

                aliceKeyAgree.doPhase(bobPubKey, true);

                byte[] aliceSharedSecret = aliceKeyAgree.generateSecret();
                //print(Agent.hex(aliceSharedSecret));

                SecretKeySpec aesKey = new SecretKeySpec(aliceSharedSecret, 0, 16, "AES");
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(Cipher.ENCRYPT_MODE, aesKey);
                byte[] iv = cipher.getIV();
                byte[] ct = cipher.doFinal("Živjo Bob, Alice tu!".getBytes(StandardCharsets.UTF_8));
                send("bob", ct);
                send("bob", iv);

                cipher.init(Cipher.ENCRYPT_MODE, aesKey);
                iv = cipher.getIV();
                ct = cipher.doFinal("Živjo Charlie, Alice tu!".getBytes(StandardCharsets.UTF_8));
                send("charlie", ct);
                send("charlie", iv);

            }
        });
        env.add(new Agent("bob") {
            public void task() throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {
                final byte[] alicePubKeyE = receive("alice");
                KeyFactory bobKeyFac = KeyFactory.getInstance("DH");
                X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(alicePubKeyE);

                PublicKey alicePubKey = bobKeyFac.generatePublic(x509KeySpec);
                DHParameterSpec dhParamSpec = ((DHPublicKey) alicePubKey).getParams();

                KeyPairGenerator bobKpairGen = KeyPairGenerator.getInstance("DH");
                bobKpairGen.initialize(dhParamSpec);
                KeyPair bobKpair = bobKpairGen.generateKeyPair();

                final byte[] bobPubKey = bobKpair.getPublic().getEncoded();
                send("charlie", bobPubKey);

                KeyAgreement bobKeyAgree = KeyAgreement.getInstance("DH");
                bobKeyAgree.init(bobKpair.getPrivate());
                Key ab = bobKeyAgree.doPhase(alicePubKey, false);
                send("charlie", ab.getEncoded());

                byte[] acE = receive("alice");
                x509KeySpec = new X509EncodedKeySpec((acE));
                PublicKey charliePubKey = bobKeyFac.generatePublic(x509KeySpec);

                bobKeyAgree.doPhase(charliePubKey, true);

                byte[] bobSharedSecret = bobKeyAgree.generateSecret();

                SecretKeySpec aesKey = new SecretKeySpec(bobSharedSecret, 0, 16, "AES");

                //print(Agent.hex(bobSharedSecret));
                final byte[] ctFromAlice = receive("alice");
                final byte[] ivFromAlice = receive("alice");

                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                final GCMParameterSpec specs = new GCMParameterSpec(128, ivFromAlice);

                cipher.init(Cipher.DECRYPT_MODE, aesKey, specs);

                byte[] pt = cipher.doFinal(ctFromAlice);
                print(new String(pt));

            }
        });
        env.add(new Agent("charlie") {
            public void task() throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {
                final byte[] bobPubKeyE = receive("bob");
                KeyFactory charlieKeyFac = KeyFactory.getInstance("DH");
                X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(bobPubKeyE);

                PublicKey bobPubKey = charlieKeyFac.generatePublic(x509KeySpec);
                DHParameterSpec dhParamSpec = ((DHPublicKey) bobPubKey).getParams();

                KeyPairGenerator charlieKpairGen = KeyPairGenerator.getInstance("DH");
                charlieKpairGen.initialize(dhParamSpec);
                KeyPair charlieKpair = charlieKpairGen.generateKeyPair();

                final byte[] charliePubKey = charlieKpair.getPublic().getEncoded();
                send("alice", charliePubKey);

                KeyAgreement charlieKeyAgree = KeyAgreement.getInstance("DH");
                charlieKeyAgree.init(charlieKpair.getPrivate());
                Key bc = charlieKeyAgree.doPhase(bobPubKey, false);
                send("alice", bc.getEncoded());

                final byte[] abE = receive("bob");
                x509KeySpec = new X509EncodedKeySpec((abE));
                PublicKey alicePubKey = charlieKeyFac.generatePublic(x509KeySpec);
                charlieKeyAgree.doPhase(alicePubKey, true);

                byte[] charlieSharedSecret = charlieKeyAgree.generateSecret();
                //print(Agent.hex(charlieSharedSecret));

                SecretKeySpec aesKey = new SecretKeySpec(charlieSharedSecret, 0, 16, "AES");

                //print(Agent.hex(bobSharedSecret));
                final byte[] ctFromAlice = receive("alice");
                final byte[] ivFromAlice = receive("alice");

                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                final GCMParameterSpec specs = new GCMParameterSpec(128, ivFromAlice);

                cipher.init(Cipher.DECRYPT_MODE, aesKey, specs);

                byte[] pt = cipher.doFinal(ctFromAlice);
                print(new String(pt));
            }
        });

        env.connect("alice", "bob");
        env.connect("alice", "charlie");
        env.connect("charlie", "bob");
        env.start();
    }
}
