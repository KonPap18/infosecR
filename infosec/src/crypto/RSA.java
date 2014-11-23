/*
 * RSA.java
 */
package crypto;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;


public class RSA
{
    private X509Certificate pubCert;
    private PrivateKey priv;
    
    public RSA(X509Certificate cert, PrivateKey k2)
    {
        pubCert = cert;
        priv = k2;
    }
    
    public byte[] encrypt(String input) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalStateException, IllegalBlockSizeException, BadPaddingException
    {
        Cipher rsaCipher = Cipher.getInstance("RSA");
        rsaCipher.init(Cipher.ENCRYPT_MODE, pubCert.getPublicKey());
        return rsaCipher.doFinal(input.getBytes());
    }
    
    public byte[] encrypt(byte[] input) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalStateException, IllegalBlockSizeException, BadPaddingException
    {
        Cipher rsaCipher = Cipher.getInstance("RSA");
        rsaCipher.init(Cipher.ENCRYPT_MODE, pubCert.getPublicKey());
        
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
        rsaCipher.init(Cipher.WRAP_MODE, pubCert.getPublicKey());
        
        return rsaCipher.wrap(key);
    }
    
    public Key unwrap(byte[] key, String algorithm, int type) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException
    {
        Cipher rsaCipher = Cipher.getInstance("RSA");
        rsaCipher.init(Cipher.UNWRAP_MODE, priv);
        
        return rsaCipher.unwrap(key, algorithm, type);
    }
}
