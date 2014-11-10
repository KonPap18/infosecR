/*
 * AES.java
 */
package crypto;

import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;;

/**
 *
 * @author JChrist
 */
public class AES
{
    private SecretKeySpec secKey;
    
    public AES(SecretKeySpec skey)
    {
        secKey = skey;
    }
    
    public byte[] encrypt(String input) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalStateException, IllegalBlockSizeException, BadPaddingException
    {
        Cipher aesCipher = Cipher.getInstance("AES");
        aesCipher.init(Cipher.ENCRYPT_MODE, secKey);
        
        return aesCipher.doFinal(input.getBytes());
    }
    public byte[] encrypt(byte[] input) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalStateException, IllegalBlockSizeException, BadPaddingException
    {
        Cipher aesCipher = Cipher.getInstance("AES");
        aesCipher.init(Cipher.ENCRYPT_MODE, secKey);
        
        return aesCipher.doFinal(input);
    }
    
    public byte[] decrypt(byte[] input) throws IllegalStateException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException
    {
        Cipher aesCipher = Cipher.getInstance("AES");
        aesCipher.init(Cipher.DECRYPT_MODE, secKey);
        
        return aesCipher.doFinal(input);
    }
    
    public byte[] wrap(Key key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException
    {
        Cipher aesCipher = Cipher.getInstance("AES");
        aesCipher.init(Cipher.WRAP_MODE, secKey);
        
        return aesCipher.wrap(key);
    }
    
    public Key unwrap(byte[] key, String algorithm, int type) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException
    {
        Cipher aesCipher = Cipher.getInstance("AES");
        aesCipher.init(Cipher.UNWRAP_MODE, secKey);
        
        return aesCipher.unwrap(key, algorithm, type);
    }
 }