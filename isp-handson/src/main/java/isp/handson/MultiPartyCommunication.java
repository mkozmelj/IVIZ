package isp.handson;

import fri.isp.Agent;
import fri.isp.Environment;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;

/**
 * This example demonstrates a multi-party communication, that is a communication between
 * more than two agents.
 */
public class MultiPartyCommunication {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        Environment env = new Environment();
        env.add(new Agent("alice") {
            public void task() {
                send("bob", "from Alice".getBytes());
                send("charlie", "from Alice".getBytes());
                print("Got '%s'", new String(this.receive("bob"), StandardCharsets.UTF_8));
                print("Got '%s'", new String(this.receive("charlie"), StandardCharsets.UTF_8));
            }
        });
        env.add(new Agent("bob") {
            public void task() {
                send("alice", "from Bob".getBytes());
                send("charlie", "from Bob".getBytes());
                print("Got '%s'", new String(this.receive("alice"), StandardCharsets.UTF_8));
                print("Got '%s'", new String(this.receive("charlie"), StandardCharsets.UTF_8));
            }
        });
        env.add(new Agent("charlie") {
            public void task() {
                send("bob", "from Charlie".getBytes());
                send("alice", "from Charlie".getBytes());
                print("Got '%s'", new String(this.receive("alice"), StandardCharsets.UTF_8));
                print("Got '%s'", new String(this.receive("bob"), StandardCharsets.UTF_8));
            }
        });

        env.connect("alice", "bob");
        env.connect("alice", "charlie");
        env.connect("charlie", "bob");
        env.start();
    }
}
