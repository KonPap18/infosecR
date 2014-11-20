/*
 * RSA.java
 */
package crypto;

import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;


public class RSA
{
    private PublicKey pub;
    private PrivateKey priv;
    
    public RSA(PublicKey k1, PrivateKey k2)
    {
        pub = k1;
        priv = k2;
    }
    
    public byte[] encrypt(String input) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalStateException, IllegalBlockSizeException, BadPaddingException
    {
        Cipher rsaCipher = Cipher.getInstance("RSA");
        rsaCipher.init(Cipher.ENCRYPT_MODE, pub);
        return rsaCipher.doFinal(input.getBytes());
    }
    
    public byte[] encrypt(byte[] input) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalStateException, IllegalBlockSizeException, BadPaddingException
    {
        Cipher rsaCipher = Cipher.getInstance("RSA");
        rsaCipher.init(Cipher.ENCRYPT_MODE, pub);
        
        return rsaCipher.doFinal(input);
    }
    
    public byte[] decrypt(byte[] a) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalStateException, IllegalBlockSizeException, BadPaddingException
    {
        Cipher rsaCipher = Cipher.getInstance("RSA");
        rsaCipher.init(Cipher.DECRYPT_MODE, priv);
        
        return rsaCipher.doFinal(a);
    }
    
    public byte[] wrap(Key key) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException
    {
        Cipher rsaCipher = Cipher.getInstance("RSA");
        rsaCipher.init(Cipher.WRAP_MODE, pub);
        
        return rsaCipher.wrap(key);
    }
    
    public Key unwrap(byte[] key, String algorithm, int type) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException
    {
        Cipher rsaCipher = Cipher.getInstance("RSA");
        rsaCipher.init(Cipher.UNWRAP_MODE, priv);
        
        return rsaCipher.unwrap(key, algorithm, type);
    }
}
