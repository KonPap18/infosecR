package clients;

import cert.*;
import crypto.*;
import java.awt.*;
import java.net.*;
import java.io.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;

/**
 * @author epapath
 */
public class VPNCertificateClient extends Thread
{
    private int port;
    private String address;
    private Component comp;
    private DataInputStream in;
    private DataOutputStream out;
    private KeyRing keyRing;
    private File certFile;
    private VPNCertificate other;
    private AES aes;
    
    public VPNCertificateClient(String name, String a, int p, Component c, KeyRing kr, File certfn)
    {
	super(name);
	address = a;
	port = p;
	comp = c;
	keyRing = kr;
	certFile = certfn;
    }
    
    public void getHandshaked() throws Exception
    {
	PublicKey pub;
	PrivateKey priv;
	
	pub = keyRing.getPublicKey();
	priv = keyRing.getPrivateKey();
	
	JOptionPane.showMessageDialog(comp, getName() + "VPN-Certificate Client:\nReceiving server's certificate and sending Public Key.");
	sendReceivePubKey(pub, keyRing.getSecretKey());
	
	JOptionPane.showMessageDialog(comp, getName() + "VPN-Certificate Client:\nAgreeing a new session key.");
	
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
    }
    
    private void sendReceivePubKey(PublicKey pub, SecretKeySpec sec) throws Exception
    {
	byte[] b1, b2;
	int length;
	AES aes1;
	
	other = VPNCertificateHandler.generateCertificate(in);
	
	aes1 = new AES(sec);
	
	b1 = sec.getEncoded();
	
	b2 = aes1.wrap(pub);
	b2 = aes1.encrypt(b2);
	
	out.writeInt(b1.length);
	out.write(b1);
	out.writeInt(b2.length);
	out.write(b2);
	out.flush();
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
    
    @Override
    public void run()
    {
	int serverPort = port; // make sure you give the port number on which the server is listening.
	//String address = address; //"127.0.0.1";  this is the IP address of the server program's computer.
	//the address given here means "the same computer as the client".
	
	try
	{
	    InetAddress ipAddress = InetAddress.getByName(address); // create an object that represents the above IP address.
	    JOptionPane.showMessageDialog(comp, getName() + " VPN-Certificate Client:\nConnecting to socket with IP address " + address + " and port " + serverPort);
	    
	    Socket socket = new Socket(ipAddress, serverPort); // create a socket with the server's IP address and server's port.
	    JOptionPane.showMessageDialog(comp, getName() + "VPN-Certificate Client:\nConnected.");
	    
	    // Get the input and output streams of the socket, so that you can receive and send data to the client.
	    InputStream sin = socket.getInputStream();
	    OutputStream sout = socket.getOutputStream();
	    
	    // Just converting them to different streams, so that string handling becomes easier.
	    in = new DataInputStream(sin);
	    out = new DataOutputStream(sout);
	    
	    JOptionPane.showMessageDialog(comp, getName() + "VPN-Certificate Client:\nStarting handshake operation");
	    getHandshaked();
	    
	    JOptionPane.showMessageDialog(comp, getName() + "VPN-Certificate Client:\nHandshake completed. Sending name: |" + getName() + "| to server for the certificate.");
	    sendMsg(getName());
	    
	    JOptionPane.showMessageDialog(comp, getName() + "VPN-Certificate Client:\nWaiting for a VPN-Certificate to be sent.");
	    VPNCertificate sc = getCertificate();
	    
	    if(sc != null)
	    {
		PublicKey iss, ca;
		JOptionPane.showMessageDialog(comp, getName() + "VPN-Certificate Client:\nReceiving Server's Public Key.");
		ca = readPubKey();
		OutputStream os = new FileOutputStream(certFile);
		os.write(sc.getBytes());
		os.close();
		os = new FileOutputStream(keyRing.getPubFile());
		keyRing.savePublicKeys(other.getPublicKey(), ca);
		JOptionPane.showMessageDialog(comp, getName() + " VPN-Certificate Client:\nSaved Received VPN-Certificate in: " + certFile);
	    }
	    else
	    {
		JOptionPane.showMessageDialog(comp, getName() + " VPN-Certificate Client:\nServer refused to generate a VPN-Certificate for you.");
	    }
	}
	catch(Exception e)
	{
	    e.printStackTrace();
	    JOptionPane.showMessageDialog(comp, getName() + "VPN-Certificate Client:\nError in connection. Terminating.");
	}
	
	return;
    }
    
    private PublicKey readPubKey() throws Exception
    {
	byte[] encoded;
	PublicKey pub;
	int length;
	
	length = in.readInt();
	encoded = new byte[length];
	in.read(encoded);
	
	pub = (PublicKey) aes.unwrap(encoded, "RSA", Cipher.PUBLIC_KEY);
	
	return pub;
    }
    
    private VPNCertificate getCertificate()
    {
	VPNCertificate sc = null;
	try
	{
	    sc = VPNCertificateHandler.generateCertificate(in, aes);
	}
	catch(Exception e)
	{
	    sc = null;
	}
	
	return sc;
    }
}
