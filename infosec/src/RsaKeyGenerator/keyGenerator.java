package RsaKeyGenerator;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.util.encoders.Base64Encoder;
import org.bouncycastle.x509.X509V1CertificateGenerator;

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
	//	System.out.println(args[0]);
		java.security.cert.X509Certificate cert=null;
		if(args.length>0) {
			for(int i=0;i<Integer.parseInt(args[0]);i++) {
				KeyPair kp=kg.genKeyPair();				
				RSAPublicKeySpec pub;
				
					pub=fact.getKeySpec(kp.getPublic(),
							  RSAPublicKeySpec.class);
				
				RSAPrivateKeySpec priv;
					priv= fact.getKeySpec(kp.getPrivate(),
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
				String name="test";
				if(i==0) {
					name="Server";
				}else if(i==1) {
					name="Client1";
				}else if(i==2) {
					name="Client2";
				}
				try {
					 cert = generateV1Certificate(kp, name);
				} catch (InvalidKeyException | NoSuchProviderException
						| SignatureException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
				
				try {	
					
					certificateToFile(cert, name);
				} catch (Exception e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
				
			}
		}else {
			KeyPair kp=kg.genKeyPair();
			System.out.println(kp.getPublic().toString()+"\n");
			System.out.println(kp.getPrivate().toString());
		}

	}
	private static void certificateToFile(X509Certificate cert,String filename) throws Exception{
		// TODO Auto-generated method stub
		File file = new File(filename+".cer");
	    byte[] buf = cert.getEncoded();

	    FileOutputStream os = new FileOutputStream(file);
	    os.write(buf);
	    

	    Writer wr = new OutputStreamWriter(os, Charset.forName("UTF-8"));
	    wr.write(new Base64Encoder().encode(buf, 0, 0, os));
	    wr.flush();
	    os.close();
		
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
	 @SuppressWarnings("deprecation")
	public static java.security.cert.X509Certificate generateV1Certificate(KeyPair pair, String type) throws InvalidKeyException,
     NoSuchProviderException, SignatureException {
   Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

   X509V1CertificateGenerator certGen = new X509V1CertificateGenerator();
   certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
   certGen.setNotBefore(new Date(System.currentTimeMillis() - 10000));
   certGen.setNotAfter(new Date(System.currentTimeMillis() + 10000));
   certGen.setPublicKey(pair.getPublic());   
   certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");
   certGen.setIssuerDN(new X500Principal("CN=MyCA"));
   
  
   if(type.equals("Server")) {  
	   System.out.println("server");
   certGen.setSubjectDN(new X500Principal("CN=Server"));  
   }else if(type.equals("Client1")) {
	   System.out.println("client1");
	   certGen.setSubjectDN(new X500Principal("CN=Client1"));  
   }else {
	   certGen.setSubjectDN(new X500Principal("CN=Client2"));  
   }
   return certGen.generateX509Certificate(pair.getPrivate(), "BC");
 }

}
