package vpn;

import cert.*;
import clients.*;
import crypto.*;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.math.*;
import java.security.*;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.*;
import servers.*;

/**
 * @author epapath
 */
public class VPNServerMain extends JFrame
{
    private JLabel talkServerPort;
    private JLabel blacklistPort;
    private JLabel VPNCertificatePort;
    
    private JPanel center;
    private JPanel north;
    
    private JButton cert;
    private JButton exit;
    private JButton talk;
    private JButton black;
    
    private VPNServerMain c;
    
    private KeyRing keyRing;
    protected File logFile;
    private VPNCertificateHandler vch;
    protected TalkServer talkServer;
    protected BlackListServer listServer;
    protected VPNCertificateServer certServer;
    
    public VPNServerMain() throws Exception
    {
	super("VPN Server");
	setSize(330, 130);
	setLayout(new BorderLayout());
	
	cert = new JButton("Certificate");
	talk = new JButton("Talk");
	exit = new JButton("Exit");
	black = new JButton("Black-List");
	
	cert.addActionListener(new Cert());
	talk.addActionListener(new Talk());
	exit.addActionListener(new Exit());
	black.addActionListener(new BlackList());
	
	center = new JPanel();
	center.setLayout(new GridLayout(2, 2));
	
	center.add(cert);
	center.add(talk);
	center.add(black);
	center.add(exit);
	
	talkServerPort = new JLabel("The TalkServer's IP-Port will be displayed here.");
	blacklistPort = new JLabel("The BlackListServer's IP-Port will be displayed here.");
	VPNCertificatePort = new JLabel("The BlackListServer's IP-Port will be displayed here.");
	
	north = new JPanel();
	north.setLayout(new BorderLayout());
	
	north.add(talkServerPort, BorderLayout.NORTH);
	north.add(blacklistPort, BorderLayout.CENTER);
	north.add(VPNCertificatePort, BorderLayout.SOUTH);
	
	add(north, BorderLayout.NORTH);
	add(center, BorderLayout.CENTER);
	
	logFile = new File("ServerLog.txt");
        keyRing = new KeyRing("ServerKeyRing.kr", "ServerCertificate.crt", "ServerPublicKeysFile.pkf", "ServerBlackList.bl", "ServerLog.log");
	vch = new VPNCertificateHandler(keyRing, new File("ServerSerial.srn"), new File("CCSignedCerts.scr"));
	
	talkServer = new TalkServer("Server TalkServer", talkServerPort, keyRing);
        talkServer.start();
	
	listServer = new BlackListServer("Server BlackListServer", blacklistPort, keyRing, vch);
	listServer.start();
	
	certServer = new VPNCertificateServer("Server VPNCertificateServer", VPNCertificatePort, vch, c, keyRing);
	certServer.start();
	
	c = this;
	setVisible(true);
    }
    
    public class Talk implements ActionListener
    {
	public void actionPerformed(ActionEvent e)
	{
	    TalkClient client;
	    client = new TalkClient("TalkClient", keyRing);
	}
    }
    
    public class Cert implements ActionListener
    {
	public void actionPerformed(ActionEvent e)
	{
	    try
	    {
		VPNCertificate vc = keyRing.getCertificate();
		if(vc != null)
		{
		    JOptionPane.showMessageDialog(c, "You already have a certificate:\n" + vc);
		    return;
		}
	    }
	    catch(Exception epapath)
	    {
	    }
	    
	    JOptionPane.showMessageDialog(c, "Being a CA, a new Certificate will" +
		    " be created and self-signed.");
	    
	    try
	    {
		VPNCertificate sc = vch.selfSignCertificate();
		OutputStream os = new FileOutputStream(keyRing.getCertFile());
		os.write(sc.getBytes());
		os.close();
		PublicKey pub = keyRing.getPublicKey();
		keyRing.savePublicKeys(pub, pub);
		JOptionPane.showMessageDialog(c, "Created Certificate:\n" + sc);
	    }
	    catch(Exception ex)
	    {
		ex.printStackTrace();
		JOptionPane.showMessageDialog(c, "For some reason, operation failed");
	    }
	}
    }
    
    public class Exit implements ActionListener
    {
	public void actionPerformed(ActionEvent e)
	{
	    talkServer.end();
	    listServer.end();
	    certServer.end();
	    
	    System.exit(0);
	}
    }

    public static void main(String[] args)
    {
	try
	{
	    VPNServerMain sm = new VPNServerMain();
	    sm.setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE);
	} catch (Exception ex)
	{
	    Logger.getLogger(VPNServerMain.class.getName()).log(Level.SEVERE, null, ex);
	}
    }
    
    protected class BlackList implements ActionListener
    {
	private JFrame jf;
	private JScrollPane scroll;
	private JTextArea text;
	private JTextField serF;
	private JButton addSerial;
	private JButton update;
	private JButton exit;
	private JPanel south;
	private JPanel north;
	
	public BlackList()
	{
	    jf = new JFrame("Server Blacklist");
	    jf.setSize(300, 300);
	    jf.setLayout(new BorderLayout());
	    
	    text = new JTextArea();
	    scroll = new JScrollPane(text);
	    
	    serF = new JTextField("Serial of certificate to be black-listed.");
	    addSerial = new JButton("Add/Remove from black-list");
	    addSerial.addActionListener(new AddRemove());

	    south = new JPanel();
	    south.setLayout(new GridLayout(1, 4));
	    
	    south.add(serF);
	    south.add(addSerial);
	    
	    update = new JButton("Refresh Black-List Screen");
	    update.addActionListener(new UpdateText());
	    
	    exit = new JButton("Quit frame");
	    exit.addActionListener(new Exit());
	    
	    north = new JPanel();
	    north.setLayout(new GridLayout(1, 2));
	    north.add(update);
	    north.add(exit);
	    
	    jf.add(north, BorderLayout.NORTH);
	    jf.add(scroll, BorderLayout.CENTER);
	    jf.add(south, BorderLayout.SOUTH);
	    
	    jf.setDefaultCloseOperation(JFrame.HIDE_ON_CLOSE);
	    jf.setVisible(false);
	}
	
	private void enterText(String msg)
	{
	    String previous = text.getText();
	    if(previous == null)
		previous = new String("");
	    String full = previous + "\n" + msg;
	    text.setText(full);
	}
	
	public void actionPerformed(ActionEvent e)
	{
	    jf.setVisible(true);
	}
	
	public class AddRemove implements ActionListener
	{
	    public void actionPerformed(ActionEvent e)
	    {
		LinkedList<KeyRing.BlackListEntry> l;
		BigInteger serial = null;
		Principal issuer = null;
		String tp = null;
		String iss = null;
		
		try
		{
		    serial = new BigInteger(serF.getText());
		    
		    if(keyRing.blackListContains(serial))
			keyRing.removeSerialFromBlackList(serial);
		    else
			keyRing.addSerialtoBlackList(serial);
		    enterText("Changed black-list entry:\nsn: " + serial);
		}
		catch (Exception ex)
		{
		    enterText("Error occured while trying to add/remove black-list entry:\nSerial Number: " + serial);
		}
	    }
	}
	public class UpdateText implements ActionListener
	{
	    public void actionPerformed(ActionEvent e)
	    {
		try
		{
		    LinkedList<KeyRing.BlackListEntry> l = keyRing.getBlackList();
		    String s = new String("Black-Listed Certificates\n-------------------------\n");
		    for(int i=0; i<l.size(); i++)
		    {
			KeyRing.BlackListEntry ble = l.get(i);
			s += "Serial Number: " + ble.serial + "\n";
		    }
		    if(l.size() == 0)
			s += "empty";
		    
		    text.setText(s);
		}
		catch(Exception ex)
		{
		    ex.printStackTrace();
		    text.setText("");
		    enterText(ex + "\nError Occured while updating black-list screen");
		}
	    }
	}
	public class Exit implements ActionListener
	{
	    public void actionPerformed(ActionEvent e)
	    {
		jf.setVisible(false);
	    }
	}
    }
}
