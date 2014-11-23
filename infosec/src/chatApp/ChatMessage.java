package chatApp;
//package ChatClient;

/*
 * Source code from http://www.dreamincode.net/forums/topic/259777-a-simple-chat-program-with-clientserver-gui-optional/
 */
import java.io.*;
/*
 * This class defines the different type of messages that will be exchanged between the
 * Clients and the Server. 
 * When talking from a Java Client to a Java Server a lot easier to pass Java objects, no 
 * need to count bytes or to wait for a line feed at the end of the frame
 */
public class ChatMessage implements Serializable {

	protected static final long serialVersionUID = 1112122200L;

	// The different types of message sent by the Client
	// WHOISIN to receive the list of the users connected
	// MESSAGE an ordinary message
	// LOGOUT to disconnect from the Server
	static final int WHOISIN = 0, MESSAGE = 1, LOGOUT = 2;
	private int type;
	private String message;
	private byte [] encrypted;
	
	
	// constructor
	/*ChatMessage(int type, String message) {
		this.type = type;
		this.message = message;
	}*/
	ChatMessage(int type, byte[] encrypted) {
		this.type = type;
		this.encrypted = encrypted;
	}
	
	// getters
	int getType() {
		return type;
	}
	byte[] getMessage() {
		return encrypted;
	}
	public String toString(){
		return new String(encrypted);
	}
	void setMessage(byte[] msg){
		encrypted=msg;
	}
}
