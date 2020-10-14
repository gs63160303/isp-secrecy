package isp.secrecy;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;

/**
 * Implement a brute force key search (exhaustive key search) if you know that the
 * message is:
 * "I would like to keep this text confidential Bob. Kind regards, Alice."
 * <p>
 * Assume the message was encrypted with "DES/ECB/PKCS5Padding".
 * Also assume that the key was poorly chosen. In particular, as an attacker,
 * you are certain that all bytes in the key, with the exception of the last three bytes,
 * have been set to 0.
 * <p>
 * The length of DES key is 8 bytes.
 * <p>
 * To manually specify a key, use the class {@link javax.crypto.spec.SecretKeySpec})
 */
public class A4ExhaustiveSearch {
    public static void main(String[] args) throws Exception {
        final String message = "I would like to keep this text confidential Bob. Kind regards, Alice.";
        System.out.println("[MESSAGE] " + message);

        /**
         * TODO
         * Encrypt the message using poorly choosen key and "DES/ECB/PKCS5Padding"
         */

        final byte[] plaintext = message.getBytes();

        byte[] keyByteArray = new byte[] {0, 0, 0, 0, 0, 6, 7, 8};
        final SecretKeySpec key = new SecretKeySpec(keyByteArray, "DES");

        final Cipher encrypt = Cipher.getInstance("DES/ECB/PKCS5PADDING");
        encrypt.init(Cipher.ENCRYPT_MODE, key);
        final byte[] ciphertext = encrypt.doFinal(plaintext);

        System.out.printf("Message encrypted: '%s'\n", hex(ciphertext));

        final byte[] foundKey = bruteForceKey(ciphertext, message);

        if (foundKey != null) {
            System.out.printf("Encryption key found: '%s'\n", hex(foundKey));

            // Try to encrypt original message with found key and compare ciphertexts
            final Key newKey = new SecretKeySpec(foundKey, "DES");
            encrypt.init(Cipher.ENCRYPT_MODE, key);
            final byte[] newCiphertext = encrypt.doFinal(plaintext);

            System.out.printf("OLD [key='%s']: '%s'\nNEW [key='%s']: '%s'", hex(keyByteArray), hex(ciphertext), hex(foundKey), hex(newCiphertext));
        } else {
            System.out.printf("Encryption key not found\n");
        }
    }

    private static final char[] hexArray = "0123456789ABCDEF".toCharArray();

    public static String hex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];

        for(int j = 0; j < bytes.length; ++j) {
            int v = bytes[j] & 255;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 15];
        }

        return new String(hexChars);
    }

    public static boolean nextKey(byte[] key, int index) {
        if (index >= key.length) {
            return false;
        }

        if (key[index] >= hexArray.length) {
            key[index] = 0;
            return nextKey(key, index + 1);
        } else {
            key[index] += 1;
            return true;
        }
    }

    public static byte[] bruteForceKey(byte[] ciphertext, String message) throws Exception {
        // TODO
        System.out.printf("Brute force of DES encryption, ciphertext: '%s'\n", hex(ciphertext));
        byte[] possibleKey = new byte[8];
        do {
            final Key key = new SecretKeySpec(possibleKey, "DES");
            final Cipher decrypt = Cipher.getInstance("DES/ECB/PKCS5PADDING");
            decrypt.init(Cipher.DECRYPT_MODE, key);
            try {
                final byte[] decrypted = decrypt.doFinal(ciphertext);
                if (new String(decrypted).equals(message)) {
                    return possibleKey;
                }
            } catch (BadPaddingException e) {
                continue;
            }
        } while (nextKey(possibleKey, 5));

        return null;
    }
}
