package isp.secrecy;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.ChaCha20ParameterSpec;
import java.lang.annotation.IncompleteAnnotationException;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.SecureRandom;

/**
 * TASK:
 * Assuming Alice and Bob know a shared secret key in advance, secure the channel using
 * ChaCha20 stream cipher. Then exchange ten messages between Alice and Bob.
 * <p>
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */
public class A3ChaCha20 {
    public static void main(String[] args) throws Exception {
        // STEP 1: Alice and Bob beforehand agree upon a cipher algorithm and a shared secret key
        // This key may be accessed as a global variable by both agents
        final Key key = KeyGenerator.getInstance("ChaCha20").generateKey();

        // STEP 2: Setup communication
        final Environment env = new Environment();

        final int counter = 0;
        final int numberOfRepetitions = 10;

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                final String message = "I love you Bob. Kisses, Alice.";
                /* TODO STEP 3:
                 * Alice creates, encrypts and sends a message to Bob. Bob replies to the message.
                 * Such exchange repeats 10 times.
                 *
                 * Recall, ChaCha2 requires that you specify the nonce and the counter explicitly.
                 */

                for (int i = 1; i <= numberOfRepetitions; i++) {
                    final byte[] plaintext = message.getBytes();

                    final Cipher encrypt = Cipher.getInstance("ChaCha20");
                    final byte[] nonce = new byte[12];
                    new SecureRandom().nextBytes(nonce);

                    encrypt.init(Cipher.ENCRYPT_MODE, key, new ChaCha20ParameterSpec(nonce, counter));
                    final byte[] ciphertext = encrypt.doFinal(plaintext);

                    send("bob", ciphertext);
                    send("bob", nonce);

                    // Wait for Bob's response
                    final byte[] receivedCiphertext = receive("bob");
                    final byte[] receivedNonce = receive("bob");

                    final Cipher decrypt = Cipher.getInstance("ChaCha20");
                    decrypt.init(Cipher.DECRYPT_MODE, key, new ChaCha20ParameterSpec(receivedNonce, counter));

                    final byte[] decryptedResponse = decrypt.doFinal(receivedCiphertext);
                    print("[%d/%d] Bob's response: '%s'", i, numberOfRepetitions, new String(decryptedResponse));
                }

            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                // TODO
                final String response = "I love you too, Alice. Kisses. Bob";

                for (int i = 1; i <= numberOfRepetitions; i++) {
                    final byte[] receivedCiphertext = receive("alice");
                    final byte[] receivedNonce = receive("alice");

                    final Cipher decrypt = Cipher.getInstance("ChaCha20");
                    decrypt.init(Cipher.DECRYPT_MODE, key, new ChaCha20ParameterSpec(receivedNonce, counter));
                    final byte[] decryptedMessage = decrypt.doFinal(receivedCiphertext);

                    print("[%d/%d] Alice's' message: '%s'", i, numberOfRepetitions, new String(decryptedMessage));

                    // Send response
                    final Cipher encrypt = Cipher.getInstance("ChaCha20");
                    final byte[] nonce = new byte[12];
                    new SecureRandom().nextBytes(nonce);
                    encrypt.init(Cipher.ENCRYPT_MODE, key, new ChaCha20ParameterSpec(nonce, counter));
                    final byte[] encryptedResponse = encrypt.doFinal(response.getBytes());

                    send("alice", encryptedResponse);
                    send("alice", nonce);
                }
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
