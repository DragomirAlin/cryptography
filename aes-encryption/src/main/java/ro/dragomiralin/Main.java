package ro.dragomiralin;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.io.IOException;
import java.io.Serializable;
import java.security.*;
import java.util.Base64;

public class Main {
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, IOException, BadPaddingException, InvalidKeyException, ClassNotFoundException {
        simpleEncryption();
        objectEncryption();
        prepareKeyToStore();
    }

    private static void prepareKeyToStore() throws NoSuchAlgorithmException {
        SecretKey key = generateKey(128);
        String output = Base64.getEncoder().withoutPadding().encodeToString(key.getEncoded());

        System.out.println("Key: " + output);

        byte[] encoded = Base64.getDecoder().decode(output);
        SecretKey aesKey = new SecretKeySpec(encoded, "AES");
        System.out.println(key.equals(aesKey));
    }

    private static void objectEncryption() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, IOException, InvalidKeyException, BadPaddingException, ClassNotFoundException {
        SecuredData securedData = new SecuredData("Dragomir", "Alin");
        SecretKey key = generateKey(128);
        IvParameterSpec ivParameterSpec = generateIv();
        String algorithm = "AES/CBC/PKCS5Padding";
        SealedObject sealedObject = encryptObject(
                algorithm, securedData, key, ivParameterSpec);
        System.out.println("Encrypted object: " + sealedObject);
        SecuredData object = (SecuredData) decryptObject(
                algorithm, sealedObject, key, ivParameterSpec);
        System.out.println("Decrypted object: " + object);
    }

    private static void simpleEncryption() throws NoSuchAlgorithmException {
        SecretKey key = generateKey(256);
        IvParameterSpec iv = generateIv();

        String algorithm = "AES/CBC/PKCS5Padding";
        String plainText = "Hello World AES CBC";

        try {
            String cipherText = encrypt(algorithm, plainText, key, iv);
            System.out.println("Encrypted text: " + cipherText);
            String decryptedText = decrypt(algorithm, cipherText, key, iv);
            System.out.println("Decrypted text: " + decryptedText);
        } catch (NoSuchPaddingException | InvalidAlgorithmParameterException | InvalidKeyException |
                 BadPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    /**
     * The KeyGenerator class provides a simple way to generate a secret key.
     *
     * @param n - key size (128, 192, 256)
     * @return
     * @throws NoSuchAlgorithmException
     */
    public static SecretKey generateKey(int n) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(n);
        return keyGenerator.generateKey();
    }

    /**
     * IV is a pseudo-random value and has the same size as the block that is encrypted.
     * We can use the SecureRandom class to generate a random IV.
     *
     * @return
     */
    public static IvParameterSpec generateIv() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    public static String encrypt(String algorithm, String input, SecretKey key,
                                 IvParameterSpec iv) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] cipherText = cipher.doFinal(input.getBytes());
        return Base64.getEncoder()
                .encodeToString(cipherText);
    }

    public static String decrypt(String algorithm, String cipherText, SecretKey key,
                                 IvParameterSpec iv) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] plainText = cipher.doFinal(Base64.getDecoder()
                .decode(cipherText));
        return new String(plainText);
    }

    public static SealedObject encryptObject(String algorithm, Serializable object,
                                             SecretKey key, IvParameterSpec iv) throws NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            InvalidKeyException, IOException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        return new SealedObject(object, cipher);
    }

    public static Serializable decryptObject(String algorithm, SealedObject sealedObject,
                                             SecretKey key, IvParameterSpec iv) throws NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException,
            ClassNotFoundException, BadPaddingException, IllegalBlockSizeException,
            IOException {

        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        return (Serializable) sealedObject.getObject(cipher);
    }


}