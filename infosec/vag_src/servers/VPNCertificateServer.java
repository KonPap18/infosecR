package servers;

import cert.*;
import java.awt.*;
import java.io.*;
import java.net.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import crypto.*;

/**
 * @author epapath
 */
public class VPNCertificateServer extends Thread
{
    protected int port;
    protected boolean keepServerRunning;
    protected Component comp;
    protected ServerSocket ss;
    protected DataInputStream in;
    protected DataOutputStream out;
    protected KeyRing keyRing;
    protected VPNCertificateHandler sch;
    private PublicKey other;
    private JLabel label;
    private AES aes;
    
    public VPNCertificateServer(String name, JLabel jl, VPNCertificateHandler sch1, Component c, KeyRing kr)
    {
	super(name);
	
	keyRing = kr;
	port = 6666;
	label = jl;
	sch = sch1;
	comp = c;
	keepServerRunning = true;
    }
    
    public int getPort()
    {
	return port;
    }
    
    public void end()
    {
	keepServerRunning = false;
    }
    
    protected void endTalk() throws IOException
    {
	ss.close();
    }
    
    protected void handshake() throws Exception
    {
	PublicKey pub;
	PrivateKey priv;
	
	pub = keyRing.getPublicKey();
	priv = keyRing.getPrivateKey();
	
	JOptionPane.showMessageDialog(comp, getName() + ": changing public keys with client.");
	sendReceivePubKey();
	
	JOptionPane.showMessageDialog(comp, getName() + ": Agreeing a new session key.");
	
	boolean retry = false;
	do
	{
	    keyAgreement(pub, priv);
	    
	    sendMsg("OK?");
	    String line = readMsg();
	    if(line.compareToIgnoreCase("ok") == 0)
	    {
		sendMsg("OK");
		retry = false;
	    }
	    else
	    {
		sendMsg("Retry");
		retry = true;
	    }
	    
	}while(retry);
    }
    
    protected void keyAgreement(PublicKey pubKey, PrivateKey privKey) throws Exception
    {
	RSA rsa = new RSA(pubKey, privKey);
	RSA rsaOther = new RSA(other, null);
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
	
	int length = in.readInt();
	byte[] crypt2 = new byte[length];
	in.read(crypt2);
	SecretKeySpec s2 = (SecretKeySpec) rsa.unwrap(crypt2, "AES", Cipher.SECRET_KEY);
	
	byte[] half2 = s2.getEncoded();
	
	byte[] full = new byte[16];
	for(int i=0; i<8; i++)
	{
	    full[i] = half1[i];
	    full[8+i] = half2[i];
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
    
    protected void sendReceivePubKey() throws Exception
    {
	byte[] b1, b2;
	int length;
	
	byte[] myCert = keyRing.getCertificate().getBytes();
	out.write(myCert);
	out.flush();
	
	length = in.readInt();
	b1 = new byte[length];
	in.read(b1, 0, length);
	
	SecretKeySpec sec2 = new SecretKeySpec(b1, "AES");
	aes = new AES(sec2);
	
	length = in.readInt();
	b1 = new byte[length];
	in.read(b1, 0, length);
	b1 = aes.decrypt(b1);
	
	other = (PublicKey) aes.unwrap(b1, "RSA", Cipher.PUBLIC_KEY);
    }
    
    @Override
    public void run()
    {
	while(keepServerRunning)
	{
	    try
	    {
		ss = new ServerSocket(port); // create a server socket and bind it to the above port number.
		//	JOptionPane.showMessageDialog(comp, getName() + " is running on port: " + port + ".");
		label.setText(getName() + " port: " + port);
		label.setVisible(true);
		
		Socket socket = ss.accept(); // make the server listen for a connection, and let you know when it gets one.
		
		JOptionPane.showMessageDialog(comp, getName() + ": Just got a client.");
		
		// Get the input and output streams of the socket, so that you can receive and send data to the client.
		InputStream sin = socket.getInputStream();
		OutputStream sout = socket.getOutputStream();
		
		// Just converting them to different streams, so that string handling becomes easier.
		in = new DataInputStream(sin);
		out = new DataOutputStream(sout);
		
		String line = null;
		
		JOptionPane.showMessageDialog(comp, getName() + ": Starting handshake operation.");
		handshake();
		
		JOptionPane.showMessageDialog(comp, getName() + ": Handshake completed. Receiving name from client for the certificate.");
		String name = readMsg();
		
		int choice = JOptionPane.showConfirmDialog(comp, getName()+": Will you sign a certificate for\n" +
			"name: " + name, name + " asks for certificate",
			JOptionPane.YES_NO_OPTION);
		
		if(choice == JOptionPane.YES_OPTION)
		{
		    JOptionPane.showMessageDialog(comp, getName()+"\nGenerating, signing and sending certificate.");
		    sendCertificate(name);
		    JOptionPane.showMessageDialog(comp, getName()+"\nSending CA's Public Key");
		    sendPublicKeys();
		}
		else
		{
		    JOptionPane.showMessageDialog(comp, getName()+ "\nYou denied to sign a certificate.");
		    sendMsg("No");
		}
		
		other = null;
		JOptionPane.showMessageDialog(comp, getName()+"\nSaved certificate and finished.");
	    }
	    catch(BindException be)
	    {
		try
		{
		    ss.close();
		}
		catch(Exception epapath)
		{
		    port++;
		}
	    }
	    catch(Exception e)
	    {
		JOptionPane.showMessageDialog(comp, e + "\n" + getName() + ": Error Occured. Connection terminated.");
	    }
	}
	
	return;
    }
    
    private String readMsg() throws Exception
    {
	byte[] encoded;
	byte[] decoded;
	int length;
	
	length = in.readInt(); // wait for the client to send a line of text.
	
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
    
    private void sendCertificate(String subj) throws Exception
    {
	VPNCertificate scert = sch.createSignedCertificate(subj, other);
	
	byte[] cert = scert.getBytes();
	byte[] encoded = aes.encrypt(cert);
	
	byte[] length = VPNCertificate.intToByteArray(encoded.length);
	out.write(length);
	out.write(encoded);
	out.flush();
    }
    
    private void sendPublicKeys() throws Exception
    {
	PublicKey ca;
	ca = keyRing.getCAPublicKey();
	
	byte[] b1;
	
	b1 = aes.wrap(ca);
	
	out.writeInt(b1.length);
	out.write(b1);
	out.flush();
    }
}
