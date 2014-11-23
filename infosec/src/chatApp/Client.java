package chatApp;

//package ChatClient;

/*
 * Source code from http://www.dreamincode.net/forums/topic/259777-a-simple-chat-program-with-clientserver-gui-optional/
 */
import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.util.Date;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JOptionPane;

import crypto.AES;

/*
 * The Client that can be run both as a console or a GUI
 */
public class Client {
	private static final char[] keystorePass1={'c','l','i','e','n','t','1','p','a','s','s'};
	private static final char[] keystorePass2={'c','l','i','e','n','t','2','p','a','s','s'};
	private boolean isClient1;
	// for I/O
	private ObjectInputStream sInput; // to read from the socket
	private ObjectOutputStream sOutput; // to write on the socket
	private Socket socket;
	//private Socket byteBinded;

	// if I use a GUI or not
	private ClientGUI cg;

	// the server, the port and the username
	private String server, username;
	private int port;
	private RSAPrivateKey ClientPrivateKey;
	// private RSAPublicKey ServerPublicKey;
	private boolean trusted;
	private X509Certificate ClientCertificate;
	private X509Certificate ServerCertificate;
	private KeyStore clientKeystore;
	private boolean trustedconnection;
	public Object infoMessage;
	public String titleBar;
	
	private AES aes=null;
	private SecretKeySpec secKey;
	
	/*
	 * Constructor called by console mode server: the server address port: the
	 * port number username: the username
	 */
	Client(String server, int port, String username) {
		// which calls the common constructor with the GUI set to null
		this(server, port, username, null);
	}

	/*
	 * Constructor call when used from a GUI in console mode the ClienGUI
	 * parameter is null
	 */
	/**
	 * @param server
	 * @param port
	 * @param username
	 * @param cg
	 */
	Client(String server, int port, String username, ClientGUI cg) {
		boolean trusted;
		this.server = server;
		this.port = port;
		this.username = username;
		// save if we are in GUI mode or not
		this.cg = cg;
		loadKeystore();
		trustedconnection=false;
		secKey=new SecretKeySpec("+^\"%rjE+A-mnh".getBytes(), "AES");
	}

	private void loadKeystore() {
		// TODO Auto-generated method stub
		FileInputStream f;
		if(username.endsWith("1")){
			isClient1=true;
			try {
			 f= new FileInputStream("client1keystore");
				clientKeystore = KeyStore.getInstance("JKS");
				clientKeystore.load(f, keystorePass1);
				f.close();
			} catch (FileNotFoundException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (KeyStoreException e) {
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
			
		}else{
			isClient1=false;
			try {
				f = new FileInputStream("client2keystore");
				KeyStore ks = KeyStore.getInstance("JKS");
				ks.load(f, keystorePass2);
				f.close();
			} catch (FileNotFoundException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (KeyStoreException e) {
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

	private X509Certificate readCert(String filename) {
		// TODO Auto-generated method stub
		FileInputStream fis;
		BufferedInputStream bis = null;
		try {
			fis = new FileInputStream(filename);
			bis = new BufferedInputStream(fis);
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		CertificateFactory cf;
		Certificate cert = null;
		try {
			cf = CertificateFactory.getInstance("X.509");
			cert = cf.generateCertificate(bis);
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return (X509Certificate) cert;
	}

	/*
	 * To start the dialog
	 */
	public boolean start() {
		// try to connect to the server
		try {
			socket = new Socket(server, port);
		}
		// if it failed not much I can so
		catch (Exception ec) {
			display("Error connectiong to server:" + ec);
			return false;
		}

		

		/* Creating both Data Stream */
		try {
			sInput = new ObjectInputStream(socket.getInputStream());
			sOutput = new ObjectOutputStream(socket.getOutputStream());
		} catch (IOException eIO) {
			display("Exception creating new Input/output Streams: " + eIO);
			return false;
		}

		// creates the Thread to listen from the server
		new ListenFromServer().start();
		// Send our username to the server this is the only message that we
		// will send as a String. All other messages will be ChatMessage objects
		
		if(trustedconnection){
			String msg = "Connection accepted " + socket.getInetAddress() + ":"
					+ socket.getPort();
			display(msg);
			
			aes=new AES(secKey);
		try {
			
			sOutput.writeObject(username);

		} catch (IOException eIO) {
			display("Exception doing login : " + eIO);
			disconnect();
			return false;
		}
		}
		// success we inform the caller that it worked
		return true;
	}

	/*
	 * To send a message to the console or the GUI
	 */
	private void display(String msg) {
		if (cg == null)
			System.out.println(msg); // println in console mode
		else
			cg.append(msg + "\n"); // append to the ClientGUI JTextArea (or
									// whatever)
	}

	/*
	 * To send a message to the server
	 */
	void sendMessage(ChatMessage cmsg) {
		try {
			cmsg.setMessage(aes.encrypt(cmsg.getMessage()));
			sOutput.writeObject(cmsg);
		} catch (IOException | InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalStateException | IllegalBlockSizeException | BadPaddingException e) {
			display("Exception writing to server: " + e);
		}
	}

	/*
	 * When something goes wrong Close the Input/Output streams and disconnect
	 * not much to do in the catch clause
	 */
	private void disconnect() {
		try {
			if (sInput != null)
				sInput.close();
		} catch (Exception e) {
		} // not much else I can do
		try {
			if (sOutput != null)
				sOutput.close();
		} catch (Exception e) {
		} // not much else I can do
		try {
			if (socket != null)
				socket.close();
		} catch (Exception e) {
		} // not much else I can do

		// inform the GUI
		if (cg != null)
			cg.connectionFailed();

	}

	private RSAPrivateKey readPrivateKey(String fileName)
			throws FileNotFoundException, IOException, NoSuchAlgorithmException {
		// TODO Auto-generated method stub
		ObjectInputStream oin = new ObjectInputStream(new BufferedInputStream(
				new FileInputStream(fileName)));
		BigInteger mod;
		BigInteger exp;
		try {
			mod = (BigInteger) oin.readObject();
			exp = (BigInteger) oin.readObject();
		} catch (Exception e) {
			throw new IOException("Unexpected error", e);
		} finally {
			oin.close();
		}
		KeyFactory r = KeyFactory.getInstance("RSA");
		RSAPrivateKeySpec spec = new RSAPrivateKeySpec(mod, exp);
		RSAPrivateKey pk = null;
		try {
			pk = (RSAPrivateKey) r.generatePrivate(spec);
			// System.out.println(pk.toString());
		} catch (InvalidKeySpecException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		return pk;

	}

	/*
	 * To start the Client in console mode use one of the following command >
	 * java Client > java Client username > java Client username portNumber >
	 * java Client username portNumber serverAddress at the console prompt If
	 * the portNumber is not specified 1500 is used If the serverAddress is not
	 * specified "localHost" is used If the username is not specified
	 * "Anonymous" is used > java Client is equivalent to > java Client
	 * Anonymous 1500 localhost are eqquivalent
	 * 
	 * In console mode, if an error occurs the program simply stops when a GUI
	 * id used, the GUI is informed of the disconnection
	 */

	public static void main(String[] args) {
		// default values
		int portNumber = 1500;
		String serverAddress = "localhost";
		String userName = "Anonymous";
		

		// depending of the number of arguments provided we fall through
		switch (args.length) {

		// > javac Client username portNumber serverAddr
		case 3:
			serverAddress = args[2];
			// > javac Client username portNumber
		case 2:
			try {
				portNumber = Integer.parseInt(args[1]);
			} catch (Exception e) {
				System.out.println("Invalid port number.");
				System.out
						.println("Usage is: > java Client [username] [portNumber] [serverAddress]");
				return;
			}
			// > javac Client username
		case 1:
			userName = args[0];
			// > java Client
		case 0:
			break;
		// invalid number of arguments
		default:
			System.out
					.println("Usage is: > java Client [username] [portNumber] {serverAddress]");
			return;
		}
		// create the Client object
		Client client = new Client(serverAddress, portNumber, userName);
		// test if we can start the connection to the Server
		// if it failed nothing we can do
		if (!client.start())
			return;
		
		// wait for messages from user
		Scanner scan = new Scanner(System.in);
		// loop forever for message from the user
		while (true) {
			System.out.print("> ");
			// read message from user
			String msg = scan.nextLine();
			
			// logout if message is LOGOUT
			if (msg.equalsIgnoreCase("LOGOUT")) {
				client.sendMessage(new ChatMessage(ChatMessage.LOGOUT, "".getBytes()));
				// break to do the disconnect
				break;
			}
			// message WhoIsIn
			else if (msg.equalsIgnoreCase("WHOISIN")) {
				client.sendMessage(new ChatMessage(ChatMessage.WHOISIN, "".getBytes()));
			} else { // default to ordinary message
				client.sendMessage(new ChatMessage(ChatMessage.MESSAGE, msg.getBytes()));
			}
		}
		// done disconnect
		client.disconnect();
	}

	/*
	 * a class that waits for the message from the server and append them to the
	 * JTextArea if we have a GUI or simply System.out.println() it in console
	 * mode
	 */
	class ListenFromServer extends Thread {

		public void run() {
			X509Certificate ServerCert = null;
			boolean certok = false;
			// sOutput.writeObject(this.);
			try {
				ServerCert = (X509Certificate) sInput.readObject();// diavazoume
				System.out.println("CLIENT SIDE, WRITING SERVER'S CERTIFICATE \n "+ServerCert.getSubjectDN().getName());													// to
																	// pistopoiitiko
																	// tou
																	// server
			} catch (IOException | ClassNotFoundException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			// System.out.println(ServerCert.toString());
			
			certok = CertValidAndVerified(ServerCert);// an ftasei mexri edw kai einai se isxu tou server mporoume na
			if(certok){				// arxisoume tin epikonwnia kai na steiloume to diko mas
				try {
					sOutput.writeObject(clientKeystore.getCertificate("client"));
	
				} catch (IOException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (KeyStoreException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}else{
				
				 JOptionPane.showMessageDialog(null, "Server not trusted", "InfoBox: " + titleBar, JOptionPane.INFORMATION_MESSAGE);
			
					
					System.exit(0);
			}
			try {
				trustedconnection=sInput.readBoolean();
			} catch (IOException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
				
			}
			if(!trustedconnection){
				//display("Server says:Not trusted connection");
				 JOptionPane.showMessageDialog(null, "Server says:Not trusted connection", "InfoBox: " + titleBar, JOptionPane.INFORMATION_MESSAGE);
			
					
					System.exit(0);
			
			}
			while (trustedconnection) {
				// X509Certificate cer=null;
				// msg =" ";
				try {
					
					byte[] msg =aes.decrypt(((String) sInput.readObject()).getBytes());

					// if console mode print the message and add back the prompt
					if (cg == null) {
						System.out.println(msg.toString());
						System.out.print("> ");
					} else {
						cg.append(msg.toString());
					}
				} catch (IOException e) {
					display("Server has close the connection: " + e);
					if (cg != null)
						cg.connectionFailed();
					break;
				}
				// can't happen with a String object but need the catch anyhow
				catch (ClassNotFoundException e2) {
				} catch (InvalidKeyException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (IllegalStateException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (IllegalBlockSizeException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (BadPaddingException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (NoSuchAlgorithmException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (NoSuchPaddingException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		}
	}

	private boolean CertValidAndVerified(X509Certificate serverCert) {
		// TODO Auto-generated method stub
		try {
			serverCert.checkValidity();
		} catch (CertificateExpiredException | CertificateNotYetValidException e) {
			// TODO Auto-generated catch block
			//System.out.println()
			return false;
		} 
		try {
			System.out.println(serverCert.getSigAlgName());
			System.out.println(((X509Certificate) clientKeystore.getCertificate("server")).getSigAlgName());
			serverCert.verify(clientKeystore.getCertificate("server").getPublicKey(), "SHA256withRSA");
		} catch (InvalidKeyException | CertificateException | NoSuchAlgorithmException | NoSuchProviderException | SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			System.out.println("not verified MALAKA");
			return false;
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} 
		return true;
	}
}
