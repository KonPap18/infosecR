package chatApp;
//package ChatServer;

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
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import crypto.AES;

/*
 * The server that can be run both as a console application or a GUI
 */
public class Server {
	private static final char[] keystorePass = {'s','e','r','v','e','r','p','a','s','s'};;
	// a unique ID for each connection
	private static int uniqueId;
	// an ArrayList to keep the list of the Client
	private ArrayList<ClientThread> al;
	// if I am in a GUI
	private ServerGUI sg;
	// to display time
	private SimpleDateFormat sdf;
	// the port number to listen for connection
	private int port;
	// the boolean that will be turned of to stop the server
	private boolean keepGoing;
	//server public Key
	RSAPublicKey ServerPublicKey;
	RSAPrivateKey ServerPrivateKey;
	private X509Certificate ClientCertificate1;
	private X509Certificate ClientCertificate2;
	private KeyStore serverKeystore;
	private SecretKeySpec secKey;
	static X509Certificate ServerCertificate;
	/*
	 *  server constructor that receive the port to listen to for connection as parameter
	 *  in console
	 */
	public Server(int port) {
		this(port, null);
	}
	
	public Server(int port, ServerGUI sg) {
		// GUI or not
		this.sg = sg;
		// the port
		this.port = port;
		// to display hh:mm:ss
		sdf = new SimpleDateFormat("HH:mm:ss");
		// ArrayList for the Client list
		al = new ArrayList<ClientThread>();
		loadKeystore();
		secKey=new SecretKeySpec("+^\"%rjE+A-mnh".getBytes(), "AES");
		
	}
	
	private void loadKeystore() {
		
			// TODO Auto-generated method stub
			FileInputStream f;
			
				try {
				 f= new FileInputStream("serverkeystore.jks");
					serverKeystore = KeyStore.getInstance("JKS");
					serverKeystore.load(f, keystorePass);
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
		/*// TODO Auto-generated method stub
		// TODO Auto-generated method stub
				ServerCertificate = readCert("Server.cer");
				try {
					ServerPrivateKey = readPrivateKey("private0.key");
				} catch (NoSuchAlgorithmException | IOException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
				ClientCertificate1 = readCert("Client1.cer");
				ClientCertificate2=readCert("Client2.cer");
				Certificate[] certificatechain = new Certificate[1];
				try {
					serverKeystore = KeyStore.getInstance(KeyStore.getDefaultType());
					serverKeystore.load(null);
				} catch (KeyStoreException | NoSuchAlgorithmException
						| CertificateException | IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				try {
					TrustedCertificateEntry cl1 = new TrustedCertificateEntry(
							ClientCertificate1);
					TrustedCertificateEntry cl2 = new TrustedCertificateEntry(
							ClientCertificate2);

					serverKeystore.setKeyEntry(
							"Serverkey", ServerPrivateKey, "123456".toCharArray(), certificatechain);
					serverKeystore.setCertificateEntry(
							"Server", ServerCertificate);
					
					serverKeystore.setEntry("Client1", cl1, null);
					serverKeystore.setEntry("Client2", cl2, null);
				} catch (KeyStoreException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}		*/
				
				
		
	}

	private X509Certificate readCert(String filename) {
		// TODO Auto-generated method stub
		FileInputStream fis;
		BufferedInputStream bis=null;
		try {
			fis = new FileInputStream(filename);
			 bis= new BufferedInputStream(fis);
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		 

		 CertificateFactory cf;
		  Certificate cert=null;
		try {
			cf = CertificateFactory.getInstance("X.509");			
			    cert = cf.generateCertificate(bis);
//			    System.out.println("2");
			    //System.out.println(cert.toString());
		
		}catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
			
		
		return (X509Certificate) cert;
	}

	private RSAPrivateKey readPrivateKey(String fileName) throws FileNotFoundException,
			IOException,
			NoSuchAlgorithmException {
		// TODO Auto-generated method stub
		 ObjectInputStream oin = new ObjectInputStream(
				    new BufferedInputStream(new FileInputStream(fileName)));
		 BigInteger mod;
		 BigInteger exp;
		 try {
			 mod=(BigInteger) oin.readObject();
			 exp=(BigInteger) oin.readObject();
		 }catch (Exception e) {
			    throw new IOException("Unexpected error", e);
		 } finally {
		    oin.close();
		 }
		 KeyFactory r=KeyFactory.getInstance("RSA");
		 RSAPrivateKeySpec spec=new RSAPrivateKeySpec(mod, exp);
		 RSAPrivateKey pk=null;
		try {
			pk = (RSAPrivateKey) r.generatePrivate(spec);
		//	System.out.println(pk.toString());
		} catch (InvalidKeySpecException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}		
			return pk;
			 
		
	}

	private RSAPublicKey readPublicKey(String fileName) throws FileNotFoundException, IOException, NoSuchAlgorithmException {
		// TODO Auto-generated method stub
		 ObjectInputStream oin = new ObjectInputStream(
				    new BufferedInputStream(new FileInputStream(fileName)));
		 BigInteger mod;
		 BigInteger exp;
		 try {
			 mod=(BigInteger) oin.readObject();
			 exp=(BigInteger) oin.readObject();
		 }catch (Exception e) {
			    throw new IOException("Unexpected error", e);
		 } finally {
		    oin.close();
		 }
		 KeyFactory r=KeyFactory.getInstance("RSA");
		 RSAPublicKeySpec spec=new RSAPublicKeySpec(mod, exp);
		 RSAPublicKey pk=null;
		try {
			pk = (RSAPublicKey) r.generatePublic(spec);
		//	System.out.println(pk.toString());
		} catch (InvalidKeySpecException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}		
			return pk;
	}

	public void start() {
		keepGoing = true;
		/* create socket server and wait for connection requests */
		try 
		{
			// the socket used by the server
			ServerSocket serverSocket = new ServerSocket(port);

			// infinite loop to wait for connections
			while(keepGoing) 
			{
				// format message saying we are waiting
				display("Server waiting for Clients on port " + port + ".");
				
				Socket socket = serverSocket.accept();  	// accept connection
				// if I was asked to stop
				if(!keepGoing)
					break;
				ClientThread t = new ClientThread(socket);  // make a thread of it
				al.add(t);									// save it in the ArrayList
				t.start();
			}
			// I was asked to stop
			try {
				serverSocket.close();
				for(int i = 0; i < al.size(); ++i) {
					ClientThread tc = al.get(i);
					try {
					tc.sInput.close();
					tc.sOutput.close();
					tc.socket.close();
					}
					catch(IOException ioE) {
						// not much I can do
					}
				}
			}
			catch(Exception e) {
				display("Exception closing the server and clients: " + e);
			}
		}
		// something went bad
		catch (IOException e) {
            String msg = sdf.format(new Date()) + " Exception on new ServerSocket: " + e + "\n";
			display(msg);
		}
	}		
    /*
     * For the GUI to stop the server
     */
	protected void stop() {
		keepGoing = false;
		// connect to myself as Client to exit statement 
		// Socket socket = serverSocket.accept();
		try {
			new Socket("localhost", port);
		}
		catch(Exception e) {
			// nothing I can really do
		}
	}
	/*
	 * Display an event (not a message) to the console or the GUI
	 */
	private void display(String msg) {
		String time = sdf.format(new Date()) + " " + msg;
		if(sg == null)
			System.out.println(time);
		else
			sg.appendEvent(time + "\n");
	}
		/*
	 *  to broadcast a message to all Clients
	 */
	private synchronized void broadcast(String message) {
		// add HH:mm:ss and \n to the message
		String time = sdf.format(new Date());
		String messageLf = time + " " + message + "\n";
		// display message on console or GUI
		if(sg == null)
			System.out.print(messageLf);
		else
			sg.appendRoom(messageLf);     // append in the room window
		
		// we loop in reverse order in case we would have to remove a Client
		// because it has disconnected
		for(int i = al.size(); --i >= 0;) {
			ClientThread ct = al.get(i);
			// try to write to the Client if it fails remove it from the list
			if(!ct.writeMsg(messageLf)) {
				al.remove(i);
				display("Disconnected Client " + ct.username + " removed from list.");
			}
		}
	}

	// for a client who logoff using the LOGOUT message
	synchronized void remove(int id) {
		// scan the array list until we found the Id
		for(int i = 0; i < al.size(); ++i) {
			ClientThread ct = al.get(i);
			// found it
			if(ct.id == id) {
				al.remove(i);
				return;
			}
		}
	}
	
	/*
	 *  To run as a console application just open a console window and: 
	 * > java Server
	 * > java Server portNumber
	 * If the port number is not specified 1500 is used
	 */ 
	public static void main(String[] args) {
		// start server on port 1500 unless a PortNumber is specified 
		int portNumber = 1500;
		switch(args.length) {
			case 1:
				try {
					portNumber = Integer.parseInt(args[0]);
				}
				catch(Exception e) {
					System.out.println("Invalid port number.");
					System.out.println("Usage is: > java Server [portNumber]");
					return;
				}
			case 0:
				break;
			default:
				System.out.println("Usage is: > java Server [portNumber]");
				return;
				
		}
		// create a server object and start it
		Server server = new Server(portNumber);
		server.start();
	}

	/** One instance of this thread will run for each client */
	class ClientThread extends Thread {
		// the socket where to listen/talk
		Socket socket;
	//	Socket byteBinded;
		ObjectInputStream sInput;
		ObjectOutputStream sOutput;
		// my unique id (easier for deconnection)
		int id;
		// the Username of the Client
		String username;
		// the only type of message a will receive
		ChatMessage cm;
		// the date I connect
		String date;
		private SecretKeySpec secKey;
		private AES aes;
		

		// Constructore
		ClientThread(Socket socket) {
			
			// a unique id
			id = ++uniqueId;
			this.socket = socket;
			/* Creating both Data Stream */
			System.out.println("Thread trying to create Object Input/Output Streams");
			secKey=new SecretKeySpec("+^\"%rjE+A-mnh".getBytes(), "AES");
			try
			{
				// create output first
				sOutput = new ObjectOutputStream(socket.getOutputStream());
				sInput  = new ObjectInputStream(socket.getInputStream());
				
				try {
					sOutput.writeObject(serverKeystore.getCertificate("server"));
					//System.out.println(((X509Certificate) serverKeystore.getCertificate("server")).toString());
				} catch (KeyStoreException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				
				
				// read the username
				//username = (String) sInput.readObject();
				//display(username + " just connected.");
			}
			catch (IOException e) {
				display("Exception creating new Input/output Streams: " + e);
				return;
			}
            date = new Date().toString() + "\n";
		}

		// what will run forever
		public void run() {
			// to loop until LOGOUT
			boolean keepGoing = false;
			X509Certificate ClientCert=null;
			
			
			
			try {
				ClientCert=(X509Certificate) sInput.readObject();
				//System.out.println("SERVER SIDE WRITING CLIENT'S CERTIFICATE \n"+ClientCert.getSubjectDN().getName());
			//	System.out.println(ClientCert.getSignature());
			} catch (ClassNotFoundException | IOException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
			
			if(CertifiacteValidAndVerified(ClientCert)){
				keepGoing=true;
				try {
					
					sOutput.writeBoolean(true);
					aes=new AES(secKey);
					username = (String) sInput.readObject();
					display(username + " just connected.");
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (ClassNotFoundException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				
			}else{
				display("Not trusted connection");
				try {
					sOutput.writeBoolean(false);
					keepGoing=false;
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				
			}
			
			
			while(keepGoing) {
				// read a String (which is an object)
				try {
					cm = (ChatMessage) sInput.readObject();
				}
				catch (IOException e) {
					display(username + " Exception reading Streams: " + e);
					break;				
				}
				catch(ClassNotFoundException e2) {
					break;
				}
				// the messaage part of the ChatMessage
				String message="decryption went wrong";
				try {
					//message=null;
					message = new String(aes.decrypt(cm.getMessage()));
				} catch (InvalidKeyException | IllegalStateException
						| IllegalBlockSizeException | BadPaddingException
						| NoSuchAlgorithmException | NoSuchPaddingException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}

				// Switch on the type of message receive
				switch(cm.getType()) {

				case ChatMessage.MESSAGE:
					broadcast(username + ": " + message);
					break;
				case ChatMessage.LOGOUT:
					display(username + " disconnected with a LOGOUT message.");
					keepGoing = false;
					break;
				case ChatMessage.WHOISIN:
					writeMsg("List of the users connected at " + sdf.format(new Date()) + "\n");
					// scan al the users connected
					for(int i = 0; i < al.size(); ++i) {
						ClientThread ct = al.get(i);
						writeMsg((i+1) + ") " + ct.username + " since " + ct.date);
					}
					break;
				}
			}
			// remove myself from the arrayList containing the list of the
			// connected Clients
			remove(id);
			close();
		}
		
		

		private boolean CertifiacteValidAndVerified(X509Certificate clientCert) {
			
				// TODO Auto-generated method stub
				try {
					clientCert.checkValidity();
				} catch (CertificateExpiredException | CertificateNotYetValidException e) {
					// TODO Auto-generated catch block
					return false;
				} 
				try {
					Principal p=clientCert.getSubjectDN();
					String owner=p.getName().trim();
					
						if(owner.endsWith("1")){
						//	System.out.println(((X509Certificate) serverKeystore.getCertificate("client1")).getSubjectDN());
							clientCert.verify(serverKeystore.getCertificate("client1").getPublicKey());
						}else{
							System.out.println(((X509Certificate) serverKeystore.getCertificate("client2")).getSubjectDN());
							clientCert.verify(serverKeystore.getCertificate("client2").getPublicKey());
						}
					
					
				} catch (InvalidKeyException | CertificateException | NoSuchAlgorithmException | NoSuchProviderException | SignatureException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
					return false;
				} catch (KeyStoreException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} 
				return true;
			}
		


		// try to close everything
		private void close() {
			// try to close the connection
			try {
				if(sOutput != null) sOutput.close();
			}
			catch(Exception e) {}
			try {
				if(sInput != null) sInput.close();
			}
			catch(Exception e) {};
			try {
				if(socket != null) socket.close();
			}
			catch (Exception e) {}
		}

		/*
		 * Write a String to the Client output stream
		 */
		private boolean writeMsg(String msg) {
			// if Client is still connected send the message to it
			if(!socket.isConnected()) {
				close();
				return false;

			
			}// write the message to the stream
			try {
				sOutput.writeObject(aes.encrypt(msg));
			}
			// if an error occurs, do not abort just inform the user
			catch(IOException e) {
				display("Error sending message to " + username);
				display(e.toString());
			} catch (InvalidKeyException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (NoSuchPaddingException e) {
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
			}
			return true;
		}
	}
}


