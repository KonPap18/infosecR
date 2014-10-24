package RsaKeyGenerator;

import java.io.BufferedOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

public class keyGenerator {

	public static void main(String[] args) throws InvalidKeySpecException {
		// TODO Auto-generated method stub
		KeyPairGenerator kg=null;
		KeyFactory fact=null;
		try {
			kg=KeyPairGenerator.getInstance("RSA");
			 fact = KeyFactory.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		kg.initialize(1024);
		System.out.println(args[0]);
		if(args.length>0) {
			for(int i=0;i<Integer.parseInt(args[0]);i++) {
				KeyPair kp=kg.genKeyPair();
				RSAPublicKeySpec pub;
				
					pub = fact.getKeySpec(kp.getPublic(),
							  RSAPublicKeySpec.class);
				
				RSAPrivateKeySpec priv;
					priv = fact.getKeySpec(kp.getPrivate(),
							  RSAPrivateKeySpec.class);			
				
				try {
					saveToFile("public"+i+".key", pub.getModulus(),
							  pub.getPublicExponent());
					saveToFile("private"+i+".key", priv.getModulus(),
							  priv.getPrivateExponent());
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}						
				
			}
		}else {
			KeyPair kp=kg.genKeyPair();
			System.out.println(kp.getPublic().toString()+"\n");
			System.out.println(kp.getPrivate().toString());
		}

	}
	public static void saveToFile(String fileName,
			  BigInteger mod, BigInteger exp) throws IOException {
			  ObjectOutputStream oout = new ObjectOutputStream(
			    new BufferedOutputStream(new FileOutputStream(fileName)));
			  try {
			    oout.writeObject(mod);
			    oout.writeObject(exp);
			  } catch (Exception e) {
			    throw new IOException("Unexpected error", e);
			  } finally {
			    oout.close();
			  }
			}
}
