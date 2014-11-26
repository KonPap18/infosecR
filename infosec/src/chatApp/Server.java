package chatApp;
//package ChatServer;

/*
 * Source code from http://www.dreamincode.net/forums/topic/259777-a-simple-chat-program-with-clientserver-gui-optional/
 */
import java.awt.HeadlessException;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JOptionPane;

import crypto.AES;
import crypto.RSA;

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
	private Signature sig;	
	private MessageDigest shaServer;
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
		private boolean ServerTrustedConnection;
		private MessageDigest sha1;
		private byte[] otherSideSig;

		// Constructore
		ClientThread(Socket socket) {
			try {
				sha1=MessageDigest.getInstance("SHA1");
			} catch (NoSuchAlgorithmException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
			
			// a unique id
			id = ++uniqueId;
			this.socket = socket;
			/* Creating both Data Stream */
			System.out.println("Thread trying to create Object Input/Output Streams");
			username=null;
		
			try
			{
				// create output first
				sOutput = new ObjectOutputStream(socket.getOutputStream());
				sInput  = new ObjectInputStream(socket.getInputStream());
				
				
			}
			catch (IOException e) {
				display("Exception creating new Input/output Streams: " + e);
				return;
			}
		}

		// what will run forever
		public void run() {
			// to loop until LOGOUT
			boolean keepGoing = false;
			try {
				ServerTrustedConnection=handshake();
			} catch (KeyStoreException | ClassNotFoundException | IOException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
				
			if(ServerTrustedConnection){
				keepGoing=true;
				try {
							
					if(username.endsWith("1")){
						keyAgreement((PrivateKey)serverKeystore.getKey("server", keystorePass), (X509Certificate) serverKeystore.getCertificate("client1"));
					}else{
						keyAgreement((PrivateKey)serverKeystore.getKey("server", keystorePass), (X509Certificate) serverKeystore.getCertificate("client2"));
					}
					display(username + " just connected.");
				} catch (IOException | InvalidKeyException | UnrecoverableKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | KeyStoreException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} 
				
			}else{
				display("Not trusted connection");
					
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
			
				//byte [] messageDigest=sha256.digest(message.getBytes());
			

				// Switch on the type of message receive
				switch(cm.getType()) {

				case ChatMessage.MESSAGE:
					String message=null;
					otherSideSig=cm.getSignature();
					try {
						//message=null;
						message = new String(this.aes.decrypt(cm.getMessage()));
					} catch (InvalidKeyException | IllegalStateException
							| IllegalBlockSizeException | BadPaddingException
							| NoSuchAlgorithmException | NoSuchPaddingException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
					if(cm.checkDigest(sha1.digest(message.getBytes()))){
					try {
						if(verify(otherSideSig, (X509Certificate) serverKeystore.getCertificate("client1"), message)){
							broadcast(username + " (signing with client1 signature): " + message);
						}else if(verify(otherSideSig, (X509Certificate) serverKeystore.getCertificate("client2"), message)){
							broadcast(username + " (signing with client2 signature): " + message);
						}else{
							JOptionPane.showMessageDialog(null, "Could not verify sender", "InfoBox: " + "Signature error", JOptionPane.INFORMATION_MESSAGE);
						}
						
					} catch (KeyStoreException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					} catch (HeadlessException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					} catch (SignatureException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
					}else{
						JOptionPane.showMessageDialog(null, "Message altered", "InfoBox: " + "Digest error", JOptionPane.INFORMATION_MESSAGE);
					}
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
				case ChatMessage.RECEIPT:
					String infoMessage="Message delivered";
					if(sg == null){
						System.out.print(infoMessage);
					}else{
						sg.appendRoom(infoMessage);  
					}
					break;
				
				}
			// remove myself from the arrayList containing the list of the
			// connected Clients
		}
			remove(id);
			close();
		
		}
		
		

		private boolean handshake() throws KeyStoreException, IOException, ClassNotFoundException {
			// TODO Auto-generated method stub
			X509Certificate ClientCert=null;
			sOutput.writeObject(serverKeystore.getCertificate("server"));
			username = (String) sInput.readObject();
			//while(!(username==null)&&(ClientCert==null)){
				ClientCert=(X509Certificate) sInput.readObject();				
		//	}
			if(CertifiacteValidAndVerified(ClientCert)){
				sOutput.writeBoolean(true);
				return true;
			}else{
				sOutput.writeBoolean(false);
				
				return false;
			}
			
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
					
						if(username.endsWith("1")){
						//	System.out.println(((X509Certificate) serverKeystore.getCertificate("client1")).getSubjectDN());
							clientCert.verify(serverKeystore.getCertificate("client1").getPublicKey());
						}else{
						//	System.out.println(((X509Certificate) serverKeystore.getCertificate("client2")).getSubjectDN());
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
				System.out.println("Clients cert verified");
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
				System.out.println("SOCKET CLOSED");
				return false;

			
			}// write the message to the stream
			//System.out.println(msg);
			try {
				ChatMessage toSend=new ChatMessage(ChatMessage.MESSAGE, this.aes.encrypt(msg.getBytes()));
				toSend.setSignature(otherSideSig);
				toSend.setDigest(sha1.digest(msg.getBytes()));				
				sOutput.writeObject(toSend);
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
		private void keyAgreement(PrivateKey privkey, X509Certificate cert ) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, IOException {
			// TODO Auto-generated method stub
			RSA localRSA=new RSA(cert, privkey);
			RSA remoteRSA = null;
		//	System.out.println("Server before try");
			try {
				if(username.endsWith("1")){
					remoteRSA=new RSA((X509Certificate)serverKeystore.getCertificate("client1"), null);
				}else{
					remoteRSA=new RSA((X509Certificate)serverKeystore.getCertificate("client2"), null);
				}
			
				
			} catch (KeyStoreException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			KeyGenerator keygen=KeyGenerator.getInstance("AES");
			keygen.init(128);
			SecretKey sk=keygen.generateKey();
			byte[] raw=sk.getEncoded();
			SecretKeySpec s1=new SecretKeySpec(raw, "AES");
			//System.out.println(s1.getEncoded());
			byte[] localHalf=s1.getEncoded();
			//write our half
			byte[] encryptedLocalHalf=remoteRSA.wrap(s1);
			sOutput.writeInt(encryptedLocalHalf.length);
			sOutput.write(encryptedLocalHalf);
			sOutput.flush();
			//get other side's half
			int length = sInput.readInt();
	        byte[] encryptedRemoteHalf = new byte[length];
	        sInput.read(encryptedRemoteHalf);
	        SecretKeySpec s2=(SecretKeySpec)localRSA.unwrap(encryptedRemoteHalf, "AES", Cipher.SECRET_KEY);
	       // System.out.println(s2.getEncoded());
	        byte[] remoteHalf=s2.getEncoded();
	        //construct secret Key
	        byte[] full=new byte[16];
	        for (int i = 0; i < 8; i++) {
	            full[i] = remoteHalf[i];
	            full[8 + i] = localHalf[i];
	        }
	        secKey = new SecretKeySpec(full, "AES");
	    //    System.out.println(Base64.toBase64String(secKey.getEncoded()));
	        aes=new AES(secKey);
	        for (int i = 0; i < 16; i++) {
	            full[i] = 0;
	            localHalf[i] = 0;
	            remoteHalf[i] = 0;
	        }
	        s1 = new SecretKeySpec(full, "AES");
	        s2 = new SecretKeySpec(full, "AES");
	       secKey = new SecretKeySpec(full, "AES");
	}
	}

	public boolean verify(byte[] otherSideSig, X509Certificate cer, String message) throws SignatureException {
		// TODO Auto-generated method stub
		byte[] decryptedSig=null;;
		try {
			shaServer=MessageDigest.getInstance("SHA1");
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		byte [] ourDigest=shaServer.digest(message.getBytes());
		try {
			sig=Signature.getInstance("SHA1withRSA");
			sig.initVerify(cer);
			sig.update(ourDigest);
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
			return sig.verify(otherSideSig);
		
		/*try {
			shaServer=MessageDigest.getInstance("SHA-256");
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		byte [] ourDigest=shaServer.digest(message.getBytes());
		RSA dec=new RSA(cer, null);
		try {
			decryptedSig=dec.decrypt(otherSideSig);
		} catch (InvalidKeyException | NoSuchAlgorithmException
				| NoSuchPaddingException | IllegalStateException
				| IllegalBlockSizeException | BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		if(Arrays.equals(decryptedSig, ourDigest)){
			return true;
		}else{
			return false;
		}*/
		
	}
}


