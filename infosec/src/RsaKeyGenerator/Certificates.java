package RsaKeyGenerator;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class Certificates {

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		
		try {
			FileInputStream f = new FileInputStream("client2Keystore.jks");
			KeyStore ks = KeyStore.getInstance("JKS");
			ks.load(f, "client2pass".toCharArray());
			X509Certificate cer=(X509Certificate) ks.getCertificate("server");
			
			//PrivateKey k=(PrivateKey) ks.getKey("selfsigned", "serverpass".toCharArray());		
			//System.out.println(k);
			System.out.println(cer);
			
			try{
				cer.verify(cer.getPublicKey());
			
			}catch(Exception e){
				e.printStackTrace();
			}
			System.out.println("verified");
			
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
		}
		
		

	}

}
