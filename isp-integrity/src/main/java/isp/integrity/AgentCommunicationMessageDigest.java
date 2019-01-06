package isp.integrity;

import fri.isp.Agent;
import fri.isp.Environment;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;

/**
 * An MITM example showing how merely using a collision-resistant hash
 * function is insufficient to protect against tampering
 */
public class AgentCommunicationMessageDigest {

    public static void main(String[] args) {
        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                /*
                 * Alice:
                 * - sends a message that consists of:
                 *   - a message
                 *   - and a message Digest
                 */
                final byte[] message = "I hope you get this message intact. Kisses, Alice.".getBytes(StandardCharsets.UTF_8);

                // TODO: Create the digest and send the (message, digest) pair
                final MessageDigest digestAlgorithm = MessageDigest.getInstance("SHA-256");
                final byte[] hashed = digestAlgorithm.digest(message);

                send("bob", hashed);
                send("bob", message);
            }
        });

        env.add(new Agent("mallory") {
            @Override
            public void task() throws Exception {
                // Intercept the message from Alice
                byte[] message = receive("alice");
                final byte[] tag = receive("alice");

                // TODO: Modify the message
                //message = "Neki drugega".getBytes(StandardCharsets.UTF_8);

                // Forward the modified message
                send("bob", message);
                send("bob", tag);
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                /*
                 * Bob
                 * - receives the message that is comprised of:
                 *   - message
                 *   - message digest
                 * - checks if received and calculated message digest checksum match.
                 */
                final byte[] tag = receive("alice");
                final byte[] message = receive("alice");

                // TODO: Check if the received (message, digest) pair is valid
                final MessageDigest digestAlgorithm = MessageDigest.getInstance("SHA-256");
                final byte[] hashed = digestAlgorithm.digest(message);

                if (Arrays.equals(hashed, tag)) {
                    print(new String(message));
                }
                else print("Neveljaven tag");
            }
        });

        env.mitm("alice", "bob", "mallory");
        env.start();
    }
}
