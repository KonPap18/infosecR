package RsaKeyGenerator;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;

public class Certificates {

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		
		try {
			FileInputStream f = new FileInputStream("client1keystore");
			KeyStore ks = KeyStore.getInstance("JKS");
			ks.load(f, "client1pass".toCharArray());
			System.out.println(ks.getCertificate("client1").toString());
			Key k=ks.getKey("client1", "client1pass".toCharArray());
			//System.out.println(((RSAPrivateKey)k).getPrivateExponent()+" \n"+((RSAPrivateKey)k).getModulus());
			System.out.println(ks.getCertificate("Server").getPublicKey());
			
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (UnrecoverableKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		

	}

}
