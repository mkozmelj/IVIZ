package isp.integrity;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Arrays;

/*
 * Message Authenticity and Integrity are provided using Hash algorithm and Shared Secret Key.
 * http://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html#Mac
 */
public class AgentCommunicationHMAC {
    public static void main(String[] args) throws Exception {
        /*
         * STEP 1: Alice and Bob share a secret session key that will be
         * used for hash based message authentication code.
         */
        final Key key = KeyGenerator.getInstance("HmacSHA256").generateKey();

        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                /*
                 * STEP 3.
                 * Alice
                 * - creates a message;
                 * - computes the tag using the HMAC-SHA-256 algorithm and the shared key;
                 * - sends a message that is comprised of:
                 *   - message,
                 *   - tag.
                 */
                final String text = "I hope you get this message intact. Kisses, Alice.";
                final byte[] pt = text.getBytes(StandardCharsets.UTF_8);

                Mac al = Mac.getInstance("HmacSHA256");
                al.init(key);
                final byte[] tag = al.doFinal(pt);
                final byte[] secret = new byte[tag.length + pt.length];
                System.arraycopy(tag, 0, secret, 0, tag.length);
                System.arraycopy(pt, 0, secret, tag.length, pt.length);

                send("bob", secret);


            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                /*
                 * Bob:
                 * - receives the message that is comprised of:
                 *   - message, and
                 *   - tag;
                 * - uses shared secret session key to verify the message
                 */
                byte[] secret = receive("alice");
                byte[] tag = Arrays.copyOfRange(secret,0, 32);
                byte[] pt = Arrays.copyOfRange(secret, 32, secret.length);

                Mac b = Mac.getInstance("HmacSHA256");
                b.init(key);
                final byte[] tag2 = b.doFinal(pt);

                if(Arrays.equals(tag, tag2)) {
                    print(new String(pt));
                }
                else print("Nope");


            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
