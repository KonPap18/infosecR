package vpn;

import cert.*;
import clients.*;
import crypto.*;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.util.*;
import javax.swing.*;
import servers.*;

/**
 * @author epapath
 */
public class VPNClientMain extends JFrame
{
    private JLabel port;
    
    private JPanel center;
    
    private JButton cert;
    private JButton exit;
    private JButton talk;
    private JButton black;
    
    private VPNClientMain c;
    private String name;
    
    private KeyRing keyRing;
    protected File logFile;
    protected TalkServer server;
    
    public VPNClientMain()
    {
	name = JOptionPane.showInputDialog(null, "Unit's name?");
	
	this.setTitle(name + " VPN Client");
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
	
	port = new JLabel("The Client's IP-Port will be displayed here.");

	add(port, BorderLayout.NORTH);
	add(center, BorderLayout.CENTER);
	
	logFile = new File(name + "Log.txt");
        keyRing = new KeyRing(name + "KeyRing.kr", name + "Certificate.crt", name + "PublicKeysFile.pkf", name + "BlackList.bl", name + "Log.log");

	server = new TalkServer(name + " Server", port, keyRing);
        server.start();
	
	c = this;
	
	setVisible(true);
    }
    
    public class Talk implements ActionListener
    {
	public void actionPerformed(ActionEvent e)
	{
	    TalkClient client;
	    client = new TalkClient(name+" TalkClient", keyRing);
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
	    
	    JOptionPane.showMessageDialog(c, "Being a Client, a new Certificate must" +
		    "be created and signed by the Server.");
	    
	    String addr = (String) JOptionPane.showInputDialog(c, "Give Server's ip address");
	    int port = 0;
	    boolean notDone;
	    
	    do
	    {
		try
		{
		    port = Integer.parseInt(JOptionPane.showInputDialog(c, "Give Server's VPN Certificate Server port"));
		    notDone = false;
		}
		catch(Exception ex)
		{
		    notDone = true;
		}
	    }while(notDone);
	    
	    VPNCertificateClient client = new VPNCertificateClient(name,
		    addr, port, c, keyRing, keyRing.getCertFile());
	    client.start();
	    
	    try
	    {
		VPNCertificate vc = keyRing.getCertificate();
		JOptionPane.showMessageDialog(c, "Received Certificate:\n"+vc);
	    }
	    catch(Exception exc)
	    {
	    }
	}
    }
    
    public class Exit implements ActionListener
    {
	public void actionPerformed(ActionEvent e)
	{
	    server.end();
	    System.exit(0);
	}
    }
    
    protected class BlackList implements ActionListener
    {
	private JFrame jf;
	private JScrollPane scroll;
	private JTextArea text;
	private JTextField addrF;
	private JTextField portF;
	private JButton update;
	private JButton reshow;
	private JButton exit;
	private JPanel south;
	private JPanel north;
	
	public BlackList()
	{
	    jf = new JFrame(name+" Black-List Frame");
	    jf.setSize(300, 300);
	    jf.setLayout(new BorderLayout());
	    
	    text = new JTextArea();
	    scroll = new JScrollPane(text);
	    
	    addrF = new JTextField("Enter ip address of the CA.");
	    portF = new JTextField("Enter port on which the CA black-list server is listening.");
	    
	    update = new JButton("Update Black-List");
	    update.addActionListener(new GetUpdatedList());
	    update.setToolTipText("First enter ip address and port and then click here to connect to the CA and ask about every black-list entry.");
	    
	    south = new JPanel();
	    south.setLayout(new GridLayout(1, 4));
	    
	    south.add(addrF);
	    south.add(portF);
	    south.add(update);
	    
	    exit = new JButton("Quit frame");
	    exit.addActionListener(new BlackListExit());
	    exit.setToolTipText("Click here to close this window.");
	    
	    reshow = new JButton("Update black-list display");
	    reshow.addActionListener(new UpdateText());
	    reshow.setToolTipText("Click here to search again the black-list and update the results on the screen.");
	    
	    north = new JPanel();
	    north.setLayout(new GridLayout(1, 2));
	    north.add(reshow);
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
	
	public class BlackListExit implements ActionListener
	{
	    public void actionPerformed(ActionEvent e)
	    {
		jf.setVisible(false);
	    }
	}
	
	public class GetUpdatedList implements ActionListener
	{
	    public void actionPerformed(ActionEvent e)
	    {
		String addr = addrF.getText();
		String p = portF.getText();
		
		try
		{
		    int port = Integer.parseInt(p);
		    BlackListClient client;
		    client = new BlackListClient(getName()+" BlackListClient", addr, port, text, keyRing, null, BlackListServer.Get_Full_Update_Mode);
		    client.start();
		    client.join();
		    enterText("Update Finished.");
		}
		catch (Exception ex)
		{
		    enterText("Error occured while trying to get black-list update");
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
		    enterText("Error Occured while updating black-list screen");
		}
	    }
	}
    }

    public static void main(String[] args)
    {
	VPNClientMain cm = new VPNClientMain();
	cm.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
    }
}
