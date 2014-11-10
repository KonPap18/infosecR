package clients;

import cert.*;
import crypto.*;
import servers.*;
import java.awt.*;
import java.math.BigInteger;
import java.net.*;
import java.io.*;
import java.security.*;
import java.util.LinkedList;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;

/**
 * @author epapath
 */
public class BlackListClient extends Thread
{
    private int port;
    private String address;
    private JTextArea comp;
    private DataInputStream in;
    private DataOutputStream out;
    private boolean keepTalking;
    private KeyRing keyRing;
    private VPNCertificate other;
    private BigInteger serial;
    
    private AES aes;
    private int mode;
    
    public BlackListClient(String name, String a, int p, JTextArea c, KeyRing kr, BigInteger ser, int m)
    {
	super(name);
	address = a;
	port = p;
	comp = c;
	keyRing = kr;
	serial = ser;
	mode = m;
    }
    
    public boolean getHandshaked() throws Exception
    {
	Key[] keys;
	PublicKey pub;
	PrivateKey priv;
	
	boolean ok = sendReceiveCertificate();
	
	int s = in.readInt();
	
	if(ok)
	{
	    out.writeInt(mode);
	    out.flush();
	}
	else
	{
	    out.writeInt(BlackListServer.Error_Mode);
	    out.flush();
	}
	
	if(ok && s == BlackListServer.OK_Mode)
	{
	    pub = keyRing.getPublicKey();
	    priv = keyRing.getPrivateKey();
	    
	    boolean retry = false;
	    do
	    {
		keyAgreement(pub, priv);
		
		String line = readMsg();
		if(line.compareToIgnoreCase("OK?") == 0)
		{
		    sendMsg("OK");
		    retry = false;
		}
		else
		{
		    sendMsg("Retry");
		    retry = true;
		}
		
		line = readMsg();
		if(line.compareToIgnoreCase("Retry") == 0)
		    retry = true;
		
	    }while(retry);
	    
	    keepTalking = true;
	}
	else
	{
	    keepTalking = false;
	    ok = false;
	}
	
	return ok;
    }
    
    private boolean sendReceiveCertificate() throws Exception
    {
	boolean ok = false;
	byte[] myCert = keyRing.getCertificate().getBytes();
	
	other = VPNCertificateHandler.generateCertificate(in);
	
	out.write(myCert);
	out.flush();
	
	ok = VPNCertificateHandler.verify(other, keyRing.getCAPublicKey());
	
	return ok;
    }
    
    private void keyAgreement(PublicKey pub, PrivateKey priv) throws Exception
    {
	RSA rsa = new RSA(pub, priv);
	RSA rsaOther = new RSA(other.getPublicKey(), null);
	
	int length = in.readInt();
	byte[] crypt2 = new byte[length];
	in.read(crypt2);
	SecretKeySpec s2 = (SecretKeySpec) rsa.unwrap(crypt2, "AES", Cipher.SECRET_KEY);
	byte[] half2 = s2.getEncoded();
	
	KeyGenerator keygen = KeyGenerator.getInstance("AES");
	keygen.init(128);
	SecretKey sk = keygen.generateKey();
	byte[] raw = sk.getEncoded();
	SecretKeySpec s1 = new SecretKeySpec(raw, "AES");
	byte[] half1 = s1.getEncoded();
	byte[] crypt1 = rsaOther.wrap(s1);
	out.writeInt(crypt1.length);
	out.write(crypt1);
	out.flush();
	
	byte[] full = new byte[16];
	for(int i=0; i<8; i++)
	{
	    full[i] = half2[i];
	    full[8+i] = half1[i];
	}
	
	SecretKeySpec key = new SecretKeySpec(full, "AES");
	
	aes = new AES(key);
	
	for(int i=0; i<16; i++)
	{
	    full[i]=0;
	    half1[i]=0;
	    half2[i]=0;
	}
	s1=new SecretKeySpec(full, "AES");
	s2=new SecretKeySpec(full, "AES");
	key=new SecretKeySpec(full, "AES");
    }
    
    public boolean readIfListed() throws Exception
    {
	byte[] encoded;
	byte[] decoded;
	int length;
	
	length = in.readInt();
	encoded = new byte[length];
	in.read(encoded);
	decoded = aes.decrypt(encoded);
	
	boolean listed;
	
	if(decoded[0] == 0)
	    listed = false;
	else
	    listed = true;
	
	return listed;
    }
    
    public void sendSerial() throws Exception
    {
	byte[] encoded;
	
	encoded = aes.encrypt(serial.toByteArray());
	out.writeInt(encoded.length);
	out.write(encoded);
	
	out.flush();
    }
    
    public String readMsg() throws Exception
    {
	byte[] encoded;
	byte[] decoded;
	int length;
	
	length = in.readInt();
	encoded = new byte[length];
	in.read(encoded);
	decoded = aes.decrypt(encoded);
	String line = new String(decoded);
	
	enterText(getName()+": Received encrypted message: "+ VPNCertificate.Byte2Hex(encoded));
	
	return line;
    }
    
    public void sendMsg(String msg) throws Exception
    {
	byte[] encoded;
	
	encoded = aes.encrypt(msg);
	out.writeInt(encoded.length);
	out.write(encoded);
	out.flush();
    }
    
    public synchronized void enterText(String msg)
    {
	String previous = comp.getText();
	if(previous == null)
	    previous = new String("");
	String full = previous + "\n" + msg;
	
	comp.setText(full);
    }
    
    public void readBlackList() throws Exception
    {
	LinkedList<KeyRing.BlackListEntry> l = new LinkedList<KeyRing.BlackListEntry>();
	keyRing.clearBlackList();
	
	int x = in.readInt();
	
	for(int i=0; i<x; i++)
	{
	    String s = readMsg();
	    BigInteger b = new BigInteger(s);
	    
	    KeyRing.BlackListEntry ble = keyRing.new BlackListEntry(b);
	    l.add(ble);
	}
	
	for(int i=0; i<l.size(); i++)
	{
	    KeyRing.BlackListEntry ble = l.get(i);
	    keyRing.addSerialtoBlackList(ble.serial);
	}
    }
    
    public void run()
    {
	int serverPort = port; // make sure you give the port number on which the server is listening.
	//String address = address; //"127.0.0.1";  this is the IP address of the server program's computer.
	//the address given here means "the same computer as the client".
	
	try
	{
	    InetAddress ipAddress = InetAddress.getByName(address); // create an object that represents the above IP address.
	    enterText(getName()+": Connecting to socket with IP address " + address + " and port " + serverPort);
	    
	    Socket socket = new Socket(ipAddress, serverPort); // create a socket with the server's IP address and server's port.
	    enterText(getName()+": Connected.");
	    
	    // Get the input and output streams of the socket, so that you can receive and send data to the client.
	    InputStream sin = socket.getInputStream();
	    OutputStream sout = socket.getOutputStream();
	    
	    // Just converting them to different streams, so that string handling becomes easier.
	    in = new DataInputStream(sin);
	    out = new DataOutputStream(sout);
	    
	    keepTalking = getHandshaked();
	    
	    if(keepTalking)
	    {
		if(mode == BlackListServer.Ask_For_One_Certificate_Mode)
		{
		    sendSerial();
		    boolean listed = readIfListed();
		    
		    if(listed)
		    {
			enterText(getName()+": Server responded that SerialNumber:" + serial + " IS listed.");
			keyRing.addSerialtoBlackList(serial);
		    }
		    else
		    {
			enterText(getName()+": Server responded that SerialNumber:" + serial + " is NOT listed.");
		    }
		}
		else if(mode == BlackListServer.Get_Full_Update_Mode)
		{
		    enterText(getName()+": Wait while receiving black-list update.");
		    readBlackList();
		    enterText(getName()+": Black-List update completed.");
		}
	    }
	    else
		enterText(getName()+": handshake failed.");
	}
	catch(Exception e)
	{
	    enterText(getName()+": Error in connection. Terminating.");
	}
	
	return;
    }
}