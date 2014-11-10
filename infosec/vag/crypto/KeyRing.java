/*
 * KeyRing.java
 */
package crypto;

import cert.*;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.security.auth.x500.X500Principal;
import javax.swing.*;

/**
 * @author JChrist-Condiak
 */
public class KeyRing
{
    protected PublicKey pubKey;
    protected PrivateKey privKey;
    protected SecretKeySpec secKey;
    protected VPNCertificate sc;
    private File keyFile;
    private File certFile;
    private File pubFile;
    private File blackListFile;
    private File logFile;
    
    public KeyRing(String kf, String cf, String pf, String blf, String lf)
    {
	keyFile = new File(kf);
	certFile = new File(cf);
	pubFile = new File(pf);
	blackListFile = new File(blf);
	logFile = new File(lf);
	
	try
	{
	    loadKeyRing(keyFile);
	}
	catch (Exception e)
	{
	    try
	    {
		KeyPairGenerator keygen;
		keygen = KeyPairGenerator.getInstance("RSA");
		
		keygen.initialize(2048);
		
		KeyPair pair = keygen.generateKeyPair();
		
		pubKey = pair.getPublic();
		privKey = pair.getPrivate();
		
		KeyGenerator keygen2 = KeyGenerator.getInstance("AES");
		keygen2.init(128);
		SecretKey sk = keygen2.generateKey();
		byte[] raw = sk.getEncoded();
		
		secKey = new SecretKeySpec(raw, "AES");
		saveKeys();
	    }
	    catch(Exception ex)
	    {
		ex.printStackTrace();
		System.exit(1);
	    }
	}
	try
	{
	    loadCertificate();
	}
	catch(Exception e)
	{
	    JOptionPane.showMessageDialog(null, "No certificate found.");
	}
    }
    
    protected void saveKeyRing(File f) throws Exception
    {
	AES aes = new AES(secKey);
	byte[] b1, b2, b3;
	byte[] len1, len2, len3;
	OutputStream os = new FileOutputStream(f);
	
	b1 = secKey.getEncoded();
	len1 = VPNCertificate.intToByteArray(b1.length);
	
	b2 = aes.wrap(pubKey);
	b2 = aes.encrypt(b2);
	len2 = VPNCertificate.intToByteArray(b2.length);
	
	b3 = aes.wrap(privKey);
	b3 = aes.encrypt(b3);
	len3 = VPNCertificate.intToByteArray(b3.length);
	
	os.write(len1);
	os.write(b1);
	
	os.write(len2);
	os.write(b2);
	
	os.write(len3);
	os.write(b3);
	
	os.close();
    }
    
    protected void loadKeyRing(File f) throws Exception
    {
	AES aes;
	InputStream is = new FileInputStream(f);
	byte[] b1, b2, len;
	int length;
	
	len = new byte[4];
	
	is.read(len);
	length = VPNCertificateHandler.byteArrayToInt(len);
	b1 = new byte[length];
	is.read(b1, 0, length);
	
	secKey = new SecretKeySpec(b1, "AES");
	aes = new AES(secKey);
	
	
	is.read(len);
	length = VPNCertificateHandler.byteArrayToInt(len);
	b1 = new byte[length];
	is.read(b1, 0, length);
	b1 = aes.decrypt(b1);
	
	is.read(len);
	length = VPNCertificateHandler.byteArrayToInt(len);
	b2 = new byte[length];
	is.read(b2, 0, length);
	b2 = aes.decrypt(b2);
	
	pubKey = (PublicKey) aes.unwrap(b1, "RSA", Cipher.PUBLIC_KEY);
	privKey = (PrivateKey) aes.unwrap(b2, "RSA", Cipher.PRIVATE_KEY);
    }

    public void saveMsgToLog(String msg) throws Exception
    {
	RSA rsa = new RSA(getPublicKey(), null);
	String s = retreiveLog();
	OutputStream os = new FileOutputStream(logFile);
	
	String log = s.concat(msg);
	byte[] full = log.getBytes();
	int j;
 
	int len = full.length;
 
	while(len % 245 != 0)
	    len++;
 
	byte[] padded = new byte[len];
 
	for(int i=0; i<full.length; i++)
	    padded[i] = full[i];
 
	for(int i=full.length; i<padded.length; i++)
	    padded[i] = 0;
 
	byte[] startingEncrypted = new byte[2 * padded.length];
 
	byte[] block = new byte[245];
	byte[] encryptedBlock;
	j=0;
	int ind = 0;
	for(int i=0; i<padded.length; i+=245)
	{
	    j = 0;
	    for(int k=i; k<i+245; k++)
	    {
		block[j++] = padded[k];
	    }
	    encryptedBlock = rsa.encrypt(block);
 
	    for(int k=0; k<encryptedBlock.length; k++)
	    {
		startingEncrypted[ind++] = encryptedBlock[k];
	    }
	}
	byte[] write = new byte[ind];
	for(int i=0; i<ind; i++)
	    write[i] = startingEncrypted[i];
 
	os.write(VPNCertificate.intToByteArray(full.length));
	os.write(VPNCertificate.intToByteArray(write.length));
	os.write(write);
	os.close();
    }
 
    public String retreiveLog() throws Exception
    {
	String msg = new String("");
	
	if(logFile.exists())
	{
	    RSA rsa = new RSA(null, getPrivateKey());
	    InputStream in = new FileInputStream(logFile);
	    byte[] leng = new byte[4];
	    in.read(leng);
	    int startingMsgLength = VPNCertificateHandler.byteArrayToInt(leng);
	    byte[] startMsg = new byte[startingMsgLength];
	    
	    in.read(leng);
	    int encryptedLength = VPNCertificateHandler.byteArrayToInt(leng);
	    int paddedLength = encryptedLength;
	    
	    while(paddedLength % 256 != 0)
		paddedLength++;
	    
	    byte[] startingDecrypted = new byte[2*paddedLength];
	    byte[] encrypted = new byte[paddedLength];
	    in.read(encrypted);
	    
	    for(int i=encryptedLength; i<paddedLength; i++)
		encrypted[i] = 0;
	    
	    byte[] block = new byte[256];
	    byte[] decryptedBlock;
	    int j=0;
	    int ind=0;
	    for(int i=0; i<encrypted.length; i+=256)
	    {
		j=0;
		for(int k=i; k<i+256; k++)
		{
		    block[j++] = encrypted[k];
		}
		decryptedBlock = rsa.decrypt(block);
		
		for(int k=0; k<decryptedBlock.length; k++)
		    startingDecrypted[ind++] = decryptedBlock[k];
	    }
	    
	    for(int i=0; i<startingMsgLength; i++)
		startMsg[i] = startingDecrypted[i];
	    
	    msg = new String(startMsg);
	    
	    in.close();
	}
	
	return msg;
    }
    
    private void saveCertificate() throws Exception
    {
	OutputStream os = new FileOutputStream(certFile);
	
	os.write(sc.getBytes());
	os.close();
    }
    
    private void loadCertificate() throws Exception
    {
	InputStream in = new FileInputStream(certFile);
	
	sc = VPNCertificateHandler.generateCertificate(in);
	in.close();
    }
    
    public synchronized void loadKeys() throws Exception
    {
	loadKeyRing(keyFile);
    }
    
    public synchronized VPNCertificate getCertificate() throws Exception
    {
	loadCertificate();
	saveCertificate();
	return sc;
    }
    
    public synchronized PublicKey getPublicKey() throws Exception
    {
	loadKeys();
	PublicKey pub = pubKey;
	saveKeys();
	return pub;
    }
    
    public synchronized PrivateKey getPrivateKey() throws Exception
    {
	loadKeys();
	PrivateKey priv = privKey;
	saveKeys();
	return priv;
    }
    
    public synchronized SecretKeySpec getSecretKey() throws Exception
    {
	loadKeys();
	SecretKeySpec sec = secKey;
	saveKeys();
	return sec;
    }
    
    public synchronized void savePublicKeys(PublicKey iss, PublicKey ca) throws Exception
    {
	byte[] b1, b2, len1, len2;
	OutputStream os = new FileOutputStream(pubFile);
	SecretKeySpec sec = getSecretKey();
	AES aes = new AES(sec);
	
	b1 = aes.wrap(iss);
	len1 = VPNCertificate.intToByteArray(b1.length);
	
	b2 = aes.wrap(ca);
	len2 = VPNCertificate.intToByteArray(b2.length);
	
	os.write(len1);
	os.write(b1);
	os.write(len2);
	os.write(b2);
	os.close();
    }
    
    public synchronized PublicKey getIssuerPublicKey() throws Exception
    {
	PublicKey[] pub = new PublicKey[2];
	InputStream is = new FileInputStream(pubFile);
	AES aes = new AES(getSecretKey());
	byte[] b1, b2, len = new byte[4];
	int length;
	
	is.read(len);
	length = VPNCertificateHandler.byteArrayToInt(len);
	b1 = new byte[length];
	is.read(b1, 0, length);
	
	is.read(len);
	length = VPNCertificateHandler.byteArrayToInt(len);
	b2 = new byte[length];
	is.read(b2, 0, length);
	
	pub[0] = (PublicKey) aes.unwrap(b1, "RSA", Cipher.PUBLIC_KEY);
	pub[1] = (PublicKey) aes.unwrap(b2, "RSA", Cipher.PUBLIC_KEY);
	
	return pub[0];
    }
    
    public synchronized PublicKey getCAPublicKey() throws Exception
    {
	PublicKey[] pub = new PublicKey[2];
	InputStream is = new FileInputStream(pubFile);
	AES aes = new AES(getSecretKey());
	byte[] b1, b2, len = new byte[4];
	int length;
	
	is.read(len);
	length = VPNCertificateHandler.byteArrayToInt(len);
	b1 = new byte[length];
	is.read(b1, 0, length);
	
	is.read(len);
	length = VPNCertificateHandler.byteArrayToInt(len);
	b2 = new byte[length];
	is.read(b2, 0, length);
	
	pub[0] = (PublicKey) aes.unwrap(b1, "RSA", Cipher.PUBLIC_KEY);
	pub[1] = (PublicKey) aes.unwrap(b2, "RSA", Cipher.PUBLIC_KEY);
	
	return pub[1];
    }
    
    public synchronized boolean blackListContains(BigInteger serial) throws Exception
    {
	LinkedList<BlackListEntry> l = getBlackList();
	
	for(int i=0; i<l.size(); i++)
	{
	    BlackListEntry ble = l.get(i);
	    
	    if(ble.equals(serial))
		return true;
	}
	
	return false;
    }
    
    public synchronized LinkedList<BlackListEntry> getBlackList() throws Exception
    {
	LinkedList<BlackListEntry> l = new LinkedList<BlackListEntry>();
	byte[] b, len;
	int numOfListed = 0, length;
	
	if(blackListFile.exists())
	{
	    len = new byte[4];
	    InputStream in = new FileInputStream(blackListFile);
	    in.read(len);
	    numOfListed = VPNCertificateHandler.byteArrayToInt(len);

	    for(int i=0; i<numOfListed; i++)
	    {
		in.read(len);
		length = VPNCertificateHandler.byteArrayToInt(len);
		b = new byte[length];
		in.read(b);
		BigInteger bi = new BigInteger(b);
		
		BlackListEntry ble = new BlackListEntry(bi);
		l.addLast(ble);
	    }
	    in.close();
	}
	
	return l;
    }
    
    public synchronized void removeSerialFromBlackList(BigInteger serial) throws Exception
    {
	if(blackListContains(serial) == false)
	    return;
	
	LinkedList<BlackListEntry> l = getBlackList();
	
	int numOfListed = l.size();
	
	numOfListed--;
	OutputStream out = new FileOutputStream(blackListFile);
	out.write(VPNCertificate.intToByteArray(numOfListed));
	
	for(int i=0; i<l.size(); i++)
	{
	    BlackListEntry ble = l.get(i);
	    
	    if(ble.equals(serial) == false)
	    {
		BigInteger bi = ble.serial;
		int bil = bi.toByteArray().length;
		
		out.write(VPNCertificate.intToByteArray(bil));
		out.write(bi.toByteArray());
	    }
	}
	
	out.close();
    }
    
    public synchronized void clearBlackList()
    {
	blackListFile.delete();
    }
    
    public synchronized void addSerialtoBlackList(BigInteger serial) throws Exception
    {
	LinkedList<BlackListEntry> l = getBlackList();
	int numOfListed = l.size();

	numOfListed++;
	OutputStream out = new FileOutputStream(blackListFile);
	out.write(VPNCertificate.intToByteArray(numOfListed));
	for(int i=0; i<l.size(); i++)
	{
	    BlackListEntry ble = l.get(i);
	    BigInteger bi = ble.serial;
	    
	    int bil = bi.toByteArray().length;
	    
	    out.write(VPNCertificate.intToByteArray(bil));
	    out.write(bi.toByteArray());
	}
	
	int sl = serial.toByteArray().length;
	
	out.write(VPNCertificate.intToByteArray(sl));
	out.write(serial.toByteArray());
	
	out.close();
    }
    
    public synchronized void saveKeys() throws Exception
    {
	saveKeyRing(keyFile);
	destroyMemKeys();
    }
    
    protected void destroyMemKeys()
    {
	boolean notDone = true;
	
	do
	{
	    try
	    {
		KeyPairGenerator keygen;
		keygen = KeyPairGenerator.getInstance("RSA");
		
		keygen.initialize(1024);
		
		KeyPair pair = keygen.generateKeyPair();
		
		pubKey = pair.getPublic();
		privKey = pair.getPrivate();
		
		KeyGenerator keygen2 = KeyGenerator.getInstance("AES");
		keygen2.init(128);
		SecretKey sk = keygen2.generateKey();
		byte[] raw = sk.getEncoded();
		
		secKey = new SecretKeySpec(raw, "AES");
		notDone = false;
	    }
	    catch(Exception e)
	    {
		notDone = true;
	    }
	}while(notDone);
    }
    
    public File getCertFile()
    {
	return certFile;
    }
    
    public File getPubFile()
    {
	return pubFile;
    }
    
    public File getBlackListFile()
    {
	return blackListFile;
    }
    
    public class BlackListEntry
    {
	public BigInteger serial;
	
	public BlackListEntry(BigInteger ser)
	{
	    serial = ser;
	}
	
	@Override
	public String toString()
	{
	    return "Serial-Number: " + serial;
	}
	
	public boolean equals(BigInteger serial)
	{
	    if(this.serial.equals(serial) == false)
		return false;
	    
	    return true;
	}
    }
}