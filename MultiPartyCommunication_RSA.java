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
public class MultiPartyCommunication_RSA {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        Environment env = new Environment();

        // Alice's key
        final KeyPair aliceKP = KeyPairGenerator.getInstance("RSA").generateKeyPair();

        // Bob's key
        final KeyPair bobKP = KeyPairGenerator.getInstance("RSA").generateKeyPair();

        // Charlie's key
        final KeyPair charlieKP = KeyPairGenerator.getInstance("RSA").generateKeyPair();


        env.add(new Agent("alice") {
            public void task() throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {
                /*
                KeyAgreement keyAgree = KeyAgreement.getInstance("RSA");
                keyAgree.init(aliceKP.getPrivate());
                keyAgree.doPhase(bobKP.getPublic(), false);
                keyAgree.doPhase(charlieKP.getPublic(), true);

                byte[] sharedSecret = keyAgree.generateSecret();
                print(Agent.hex(sharedSecret));
                */
                SecretKey key = KeyGenerator.getInstance("AES").generateKey();
                byte[] keyArray = key.getEncoded();
                print(Agent.hex(keyArray));

                final Cipher encriptionForBob = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");
                encriptionForBob.init(Cipher.ENCRYPT_MODE, bobKP.getPublic());

                final byte[] ctForBob = encriptionForBob.doFinal(keyArray);
                send("bob", ctForBob);

                final Cipher encriptionForCharlie = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");
                encriptionForCharlie.init(Cipher.ENCRYPT_MODE, charlieKP.getPublic());
                final byte[] ctForCharlie = encriptionForCharlie.doFinal(keyArray);
                send("charlie", ctForCharlie);
            }
        });
        env.add(new Agent("bob") {
            public void task() throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException {
                final byte[] ctFromAlice = receive("alice");

                final Cipher decription = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");
                decription.init(Cipher.DECRYPT_MODE, bobKP.getPrivate());

                final byte[] sharedSecret = decription.doFinal(ctFromAlice);
                print(Agent.hex(sharedSecret));
            }
        });
        env.add(new Agent("charlie") {
            public void task() throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException {
                final byte[] ct = receive("alice");

                final Cipher decription = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");
                decription.init(Cipher.DECRYPT_MODE, charlieKP.getPrivate());

                final byte[] sharedSecret = decription.doFinal(ct);
                print(Agent.hex(sharedSecret));
            }
        });

        env.connect("alice", "bob");
        env.connect("alice", "charlie");
        env.connect("charlie", "bob");
        env.start();
    }
}
