package isp.secrecy;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;

/**
 * TASK:
 * Assuming Alice and Bob know a shared secret key in advance, secure the channel using
 * AES in CBC mode. Then exchange ten messages between Alice and Bob.
 * <p>
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */
public class A1AESInCBCMode {
    public static void main(String[] args) throws Exception {
        // STEP 1: Alice and Bob beforehand agree upon a cipher algorithm and a shared secret key
        // This key may be accessed as a global variable by both agents
        final Key key = KeyGenerator.getInstance("AES").generateKey();

        // STEP 2: Setup communication
        final Environment env = new Environment();

        final int numberOfRepetitions = 10;

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                final String message = "I love you Bob. Kisses, Alice.";
                /* TODO STEP 3:
                 * Alice creates, encrypts and sends a message to Bob. Bob replies to the message.
                 * Such exchange repeats 10 times.
                 *
                 * Do not forget: In CBC (and CTR mode), you have to also
                 * send the IV. The IV can be accessed via the
                 * cipher.getIV() call
                 */


                for (int i = 1; i <= numberOfRepetitions; i++) {
                    // Serialize the message
                    final byte[] plaintext = message.getBytes();

                    // Get the cipher instance and initialize it with the key.
                    final Cipher encrypt = Cipher.getInstance("AES/CBC/PKCS5PADDING");
                    encrypt.init(Cipher.ENCRYPT_MODE, key);

                    // Encrypt the message
                    final byte[] ciphertext = encrypt.doFinal(plaintext);

                    // Get initialization vector used in encryption process.
                    final byte[] initializationVector = encrypt.getIV();

                    // Send the ciphertext and the initialisation vector
                    send("bob", initializationVector);
                    send("bob", ciphertext);

                    // Wait for Bob's response
                    final byte[] bobsIV = receive("bob");
                    final byte[] encryptedResponse = receive("bob");

                    final Cipher decrypt = Cipher.getInstance("AES/CBC/PKCS5PADDING");
                    decrypt.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(bobsIV));

                    final byte[] decryptedResponse = decrypt.doFinal(encryptedResponse);

                    print("[%d/%d]  Bob's response: '%s'", i, numberOfRepetitions, new String(decryptedResponse));
                }
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                /* TODO STEP 4
                 * Bob receives, decrypts and displays a message.
                 * Once you obtain the byte[] representation of cipher parameters,
                 * you can load them with:
                 *
                 *   IvParameterSpec ivSpec = new IvParameterSpec(iv);
                 *   aes.init(Cipher.DECRYPT_MODE, my_key, ivSpec);
                 *
                 * You then pass this object to the cipher init() method call.*
                 */

                final String response = "I love you too, Alice. Kisses. Bob";

                for (int i = 1; i <= numberOfRepetitions; i++) {
                    // Receive initialization vector
                    final byte[] initializationVector = receive("alice");

                    // Receive ciphertext vector
                    final byte[] ciphertext = receive("alice");

                    // Get the cipher instance and initialize it with the key and initialization vector.
                    final Cipher decrypt = Cipher.getInstance("AES/CBC/PKCS5PADDING");
                    decrypt.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(initializationVector));

                    final byte[] decryptedPlaintext = decrypt.doFinal(ciphertext);
                    print("[%d/%d] Alice's message: '%s'", i, numberOfRepetitions, new String(decryptedPlaintext));

                    // Respond to Alice
                    final Cipher encrypt = Cipher.getInstance("AES/CBC/PKCS5PADDING");
                    encrypt.init(Cipher.ENCRYPT_MODE, key);

                    final byte[] encryptedResponse = encrypt.doFinal(response.getBytes());
                    final byte[] iv = encrypt.getIV();

                    send("alice", iv);
                    send("alice", encryptedResponse);
                }

            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
