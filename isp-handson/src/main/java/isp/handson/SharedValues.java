package isp.handson;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

/**
 * Values that are shared between agents can be declared inside the main method.
 * This way they become global and accessible to both agents. See example for sharedSecret.
 * <p>
 * You can do the same for public-secret key pairs but make sure that the secret part of the
 * keypair is used by only the appropriate agents.
 */
public class SharedValues {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        final Environment env = new Environment();

        // shared secrete between Alice and Bob
        final SecretKey sharedSecret = KeyGenerator.getInstance("AES").generateKey();

        // Alice's key
        final KeyPair aliceKP = KeyPairGenerator.getInstance("RSA").generateKeyPair();

        // Bob's key
        final KeyPair bobKP = KeyPairGenerator.getInstance("RSA").generateKeyPair();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                print("Can use shared secret: %s", hex(sharedSecret.getEncoded()));
                print("Can use Alice's PK: %s", hex(aliceKP.getPublic().getEncoded()));
                print("Can use Alice's SK: %s", hex(aliceKP.getPrivate().getEncoded()));
                print("Can use Bob's PK: %s", hex(bobKP.getPublic().getEncoded()));
                print("Although possible, Alice should NOT use Bob's SK: %s",
                        hex(bobKP.getPrivate().getEncoded()));
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                print("Can use shared secret: %s", hex(sharedSecret.getEncoded()));
                print("Can use Bob's PK: %s", hex(bobKP.getPublic().getEncoded()));
                print("Can use Bob's SK: %s", hex(bobKP.getPrivate().getEncoded()));
                print("Can use Alice's PK: %s", hex(aliceKP.getPublic().getEncoded()));
                print("Although possible, Bob should NOT use Alices's SK: %s",
                        hex(aliceKP.getPrivate().getEncoded()));
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
