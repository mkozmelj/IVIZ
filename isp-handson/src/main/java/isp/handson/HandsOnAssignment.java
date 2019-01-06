package isp.handson;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.*;

public class HandsOnAssignment {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        final Environment env = new Environment();

        final Key key = KeyGenerator.getInstance("AES").generateKey();
        String encryptionAlgorithm = "AES/GCM/NoPadding";
        String encryptionAlgorithm2 = "AES/CTR/NoPadding";

        final String signingAlgorithm =
                "SHA256withRSA";
        final String keyAlgorithm =
                "RSA";

        final KeyPair signkey = KeyPairGenerator.getInstance(keyAlgorithm).generateKeyPair();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                final byte[] dataForBob = "The package is in room 102.".getBytes(StandardCharsets.UTF_8);

                final Cipher encryption = Cipher.getInstance(encryptionAlgorithm);
                encryption.init(Cipher.ENCRYPT_MODE, key);
                final byte[] cipherText = encryption.doFinal(dataForBob);
                final byte[] iv = encryption.getIV();
                send("bob", cipherText);
                send("bob", iv);

                final byte[] ctFromBob = receive("bob");
                final byte[] ivFromBob = receive("bob");
                final byte[] signature = receive("bob");

                final Signature verifier = Signature.getInstance(signingAlgorithm);
                verifier.initVerify(signkey.getPublic());
                verifier.update(ctFromBob);
                verifier.update(ivFromBob);

                if (verifier.verify(signature)) {
                    final Cipher decription = Cipher.getInstance(encryptionAlgorithm2);
                    final IvParameterSpec specs = new IvParameterSpec(ivFromBob);

                    decription.init(Cipher.DECRYPT_MODE, key, specs);
                    final byte[] ct = decription.doFinal(ctFromBob);

                    print(new String(ct));
                }
                else print("Neveljaven podpis.");
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                final byte[] dataFromAlice = receive("alice");
                final Cipher decription = Cipher.getInstance(encryptionAlgorithm);
                final byte[] iv = receive("alice");
                final GCMParameterSpec specs = new GCMParameterSpec(128, iv);
                decription.init(Cipher.DECRYPT_MODE, key, specs);
                final byte[] ct = decription.doFinal(dataFromAlice);
                print(new String(ct));

                final byte[] dataFromBob = "Acknowledged.".getBytes(StandardCharsets.UTF_8);
                final Cipher encryption = Cipher.getInstance(encryptionAlgorithm2);
                encryption.init(Cipher.ENCRYPT_MODE, key);
                final byte[] cipherText = encryption.doFinal(dataFromBob);
                final byte[] iv2 = encryption.getIV();

                final Signature signer = Signature.getInstance(signingAlgorithm);
                signer.initSign(signkey.getPrivate());
                signer.update(cipherText);
                signer.update(iv2);
                final byte[] signature = signer.sign();

                send("alice", cipherText);
                send("alice", iv2);
                send("alice", signature);
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
