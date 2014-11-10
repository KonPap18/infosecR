package cert;

import crypto.*;
import java.math.BigInteger;

import crypto.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.util.Date;
import java.util.LinkedList;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;
import java.io.*;

/**
 * @author epapath
 */
public class VPNCertificateHandler
{
    private BigInteger serial;
    private Principal issuer;
    private String subjectType;
    private KeyRing keyRing;
    private File serialFile;
    private File signedCertsFile;
    private Signature sig;
    private static final long year = (long)31536000 * 1000;
    
    public VPNCertificateHandler(KeyRing kr, File serialf, File signedf) throws Exception
    {
	keyRing = kr;
	serialFile = serialf;
	signedCertsFile = signedf;//apo8hkevei ola ta certificates...pou exeis ypograpsei
	serial = readSerialFile();
	issuer = new X500Principal("CN=VPNServer");
	sig = Signature.getInstance("SHA1withRSA");
	subjectType = "OU";
    }
    
    public synchronized LinkedList<VPNCertificate> getSignedCertificates() throws Exception
    {
	LinkedList<VPNCertificate> l = new LinkedList<VPNCertificate>();
	
	try
	{
	    if(signedCertsFile.exists())
	    {
		InputStream in = new FileInputStream(signedCertsFile);
		
		byte[] b = new byte[4];
		in.read(b);
		int numOfCerts = VPNCertificateHandler.byteArrayToInt(b);
		
		for(int i=0; i<numOfCerts; i++)
		{
		    VPNCertificate sc = VPNCertificateHandler.generateCertificate(in);
		    l.add(sc);
		}
		in.close();
	    }
	}
	catch(Exception e)
	{
	}
	
	return l;
    }
    
    public synchronized void saveSignedCertificate(VPNCertificate sc) throws Exception
    {
	LinkedList<VPNCertificate> l = getSignedCertificates();
	l.add(sc);
	OutputStream os = new FileOutputStream(signedCertsFile);
	int x = l.size();
	
	os.write(VPNCertificate.intToByteArray(x));
	

	for(int i=0; i<x; i++)
	{
	    VPNCertificate e = l.get(i);
	    byte[] cert = e.getBytes();
	    
	    os.write(cert);
	}
	os.close();
    }
    
    private BigInteger readSerialFile() throws Exception
    {
	InputStream in;
	
	if(serialFile.exists())
	{
	    in = new FileInputStream(serialFile);
	    try
	    {
		byte[] len = new byte[4];
		in.read(len);
		int length = VPNCertificateHandler.byteArrayToInt(len);
		byte[] ser = new byte[length];
		in.read(ser);
		serial = new BigInteger(ser);
	    }
	    catch(Exception e)
	    {
		serial = BigInteger.valueOf((long)0);
		saveSerialFile();
	    }
	}
	else
	{
	    serial = BigInteger.valueOf((long)0);
	    saveSerialFile();
	}
	
	return serial;
    }
    
    private void saveSerialFile() throws Exception
    {
	OutputStream os = new FileOutputStream(serialFile);
	byte[] ser = serial.toByteArray();
	int length = ser.length;
	os.write(VPNCertificate.intToByteArray(length));
	os.write(ser);
	os.close();
    }
    
    public VPNCertificate selfSignCertificate() throws Exception
    {
	VPNCertificate sc;
	Date start = new Date();
	Date end = new Date(start.getTime() + year);
	serial = serial.add(BigInteger.valueOf((long)1));
	saveSerialFile();
	
	sc = new VPNCertificate(start, end, serial, issuer, issuer, keyRing.getPublicKey());
	
	sign(sc);
	
	return sc;
    }
    
    public VPNCertificate createSignedCertificate(String subject, PublicKey pub) throws Exception
    {
	VPNCertificate sc;
	Date start = new Date();
	Date end = new Date(start.getTime() + year);
	serial = serial.add(BigInteger.valueOf((long)1));
	saveSerialFile();
	sc = new VPNCertificate(start, end, serial, issuer, new X500Principal(subjectType+"="+subject), pub);
	
	sign(sc);
	
	saveSignedCertificate(sc);
	
	return sc;
    }
    
    private void sign(VPNCertificate sc) throws Exception
    {
	PrivateKey priv = this.keyRing.getPrivateKey();
	this.sig.initSign(priv);
	this.sig.update(sc.getEncoded());
	byte[] s =this.sig.sign();
	
	sc.sign(s);
    }
    
    public boolean verify(VPNCertificate sc) throws Exception
    {
	PublicKey pub =this.keyRing.getPublicKey();
	this.sig.initVerify(pub);
	this.sig.update(sc.getEncoded());
	
	return this.sig.verify(sc.getSignature());
    }
    
    public static boolean verify(VPNCertificate sc, PublicKey pub) throws Exception
    {
	Signature s = Signature.getInstance("SHA1withRSA");
	s.initVerify(pub);
	s.update(sc.getEncoded());
	
	return s.verify(sc.getSignature());
    }
    
    public static VPNCertificate generateCertificate(InputStream in) throws Exception
    {

	byte[] input;
	byte[] len = new byte[4];
	
	in.read(len);
	int length = VPNCertificateHandler.byteArrayToInt(len);
	
	input = new byte[length];
	in.read(input);

	return readVPNCertificate(input);
    }
    
    public static VPNCertificate generateCertificate(InputStream in, AES aes) throws Exception
    {
	byte[] encoded, decoded;
	byte[] len = new byte[4];
	
	in.read(len);
	int length = VPNCertificateHandler.byteArrayToInt(len);
	
	encoded = new byte[length];
	in.read(encoded);
	
	decoded = aes.decrypt(encoded);
	
	for(int i=0; i<4; i++)
	    len[i] = decoded[i];
	
	length = VPNCertificateHandler.byteArrayToInt(len);
	byte[] input = new byte[length];
	int i, j=4;
	for(i=0; j<decoded.length; i++)
	    input[i] = decoded[j++];
	
	return readVPNCertificate(input);
    }
    
    protected static VPNCertificate readVPNCertificate(byte[] input) throws Exception
    {
	int index=0, i, j, length;
	byte[] b1, b2, len;
	long l;
	Date date1, date2;
	BigInteger ser;
	Principal iss, subj;
	PublicKey pub;
	SecretKeySpec sec;
	AES aes;
	VPNCertificate sc;
	
	len = new byte[4];
	
	for(i=0; i<4; i++)
	    len[i] = input[index++];
	length = VPNCertificateHandler.byteArrayToInt(len);
	b1 = new byte[length];			    // date start
	for(i = 0; i<length; i++)
	    b1[i] = input[index++];
	l = Long.valueOf(new String(b1), 2);
	date1 = new Date(l);
	
	
	for(i=0; i<4; i++)
	    len[i] = input[index++];
	length = VPNCertificateHandler.byteArrayToInt(len);
	b1 = new byte[length];
	for(i=0; i<length; i++)			    // date end
	    b1[i] = input[index++];
	l = Long.valueOf(new String(b1), 2);
	date2 = new Date(l);
	
	
	for(i=0; i<4; i++)
	    len[i] = input[index++];
	length = VPNCertificateHandler.byteArrayToInt(len);
	b1 = new byte[length];
	for(i=0; i<length; i++)			    // serial number
	    b1[i] = input[index++];
	ser = new BigInteger(b1);
	
	
	for(i=0; i<4; i++)
	    len[i] = input[index++];
	length = VPNCertificateHandler.byteArrayToInt(len);
	b1 = new byte[length];
	for(i=0; i<length; i++)			    // issuer
	    b1[i] = input[index++];
	iss = new X500Principal(new String(b1));
	
	
	for(i=0; i<4; i++)
	    len[i] = input[index++];
	length = VPNCertificateHandler.byteArrayToInt(len);
	b1 = new byte[length];
	for(i=0; i<length; i++)			    // subject
	    b1[i] = input[index++];
	subj = new X500Principal(new String(b1));
	
	
	for(i=0; i<4; i++)
	    len[i] = input[index++];
	length = VPNCertificateHandler.byteArrayToInt(len);
	b1 = new byte[length];
	for(i=0; i<length; i++)			    // AES key
	    b1[i] = input[index++];
	sec = new SecretKeySpec(b1, "AES");
	aes = new AES(sec);
	
	for(i=0; i<4; i++)
	    len[i] = input[index++];
	length = VPNCertificateHandler.byteArrayToInt(len);
	b1 = new byte[length];
	for(i=0; i<length; i++)			    // Public Key
	    b1[i] = input[index++];
	pub = (PublicKey) aes.unwrap(b1, "RSA", Cipher.PUBLIC_KEY);
	
	sc = new VPNCertificate(date1, date2, ser, iss, subj, pub, sec);
	
	if(input.length >= index + 20)
	{
	    for(i=0; i<4; i++)
		len[i] = input[index++];		    // signature
	    length = VPNCertificateHandler.byteArrayToInt(len);
	    
	    b1 = new byte[length];
	    for(i=0; i<length; i++)
		b1[i] = input[index++];
	    
	    sc.sign(b1);
	}
	
	return sc;
    }
    
    public static int byteArrayToInt(byte[] b)
    {
	int value = 0;
	for (int i = 0; i < 4; i++)
	{
	    int shift = (4 - 1 - i) * 8;
	    value += (b[i] & 0x000000FF) << shift;
	}
	
	return value;
    }
}
