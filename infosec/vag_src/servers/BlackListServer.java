package servers;

import cert.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.security.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;
import javax.swing.*;
import crypto.*;

/**
 *
 * @author jchrist-condiak
 */
public class BlackListServer extends Thread {

    public static final int Ask_For_One_Certificate_Mode = 0;
    public static final int Get_Full_Update_Mode = 1;
    public static final int Error_Mode = 2;
    public static final int OK_Mode = 3;
    protected int port;
    protected boolean keepServerRunning;
    protected ServerSocket ss;
    protected DataInputStream in;
    protected DataOutputStream out;
    protected KeyRing keyRing;
    protected VPNCertificate other;
    private VPNCertificateHandler sch;
    private BigInteger serial;
    private JLabel label;
    private AES aes;
    private int clientMode;
    private JFrame jf;
    private JScrollPane scroll;
    private JTextArea text;
    private JButton exit;
    private JPanel north;

    /** Creates a new instance of BlackListServer */
    public BlackListServer(String name, JLabel jl, KeyRing kr, VPNCertificateHandler s) {
        super(name);

        jf = new JFrame("Black-List Server");
        jf.setSize(300, 300);
        jf.setLayout(new BorderLayout());

        text = new JTextArea();
        text.setEditable(false);
        scroll = new JScrollPane(text);

        exit = new JButton("Quit Frame");
        exit.addActionListener(new Exit());

        north = new JPanel();
        north.setLayout(new GridLayout(1, 2));
        north.add(exit);

        jf.add(north, BorderLayout.NORTH);
        jf.add(scroll, BorderLayout.CENTER);

        jf.setVisible(false);

        keyRing = kr;
        port = 6666;
        label = jl;
        sch = s;
        keepServerRunning = true;
    }

    public int getPort() {
        return port;
    }

    public void end() {
        keepServerRunning = false;
    }

    protected void endTalk() throws IOException {
        ss.close();
        other = null;
    }

    public void enterText(String msg) {
        String previous = text.getText();
        if (previous == null) {
            previous = new String("");
        }
        String full = previous + "\n" + msg;

        text.setText(full);
    }

    protected boolean handshake() throws Exception {
        PublicKey pub;
        PrivateKey priv;

        boolean ok = sendReceiveCertificate();

        if (ok) {
            out.writeInt(BlackListServer.OK_Mode);
            out.flush();
        } else {
            out.writeInt(BlackListServer.Error_Mode);
            out.flush();
        }
        clientMode = in.readInt();

        if (ok && clientMode != BlackListServer.Error_Mode) {
            pub = keyRing.getPublicKey();
            priv = keyRing.getPrivateKey();

            boolean retry = false;
            do {
                keyAgreement(pub, priv);

                sendMsg("OK?");
                String line = readMsg();
                if (line.compareToIgnoreCase("ok") == 0) {
                    sendMsg("OK");
                    retry = false;
                } else {
                    sendMsg("Retry");
                    retry = true;
                }

            } while (retry);

            enterText(getName() + ": Connection accepted from: " + other.getSubject());
        } else {
            if (other != null) {
                enterText(getName() + ": Connection refused to: " + other.getSubject());
            } else {
                enterText(getName() + ": Connection refused to client.");
            }
        }

        return ok;
    }

    private boolean sendReceiveCertificate() throws Exception {
        boolean ok = false, listed = true;
        byte[] myCert = keyRing.getCertificate().getBytes();
        out.write(myCert);
        out.flush();

        other = VPNCertificateHandler.generateCertificate(in);
        listed = keyRing.blackListContains(other.getSerialNumber());

        VPNCertificate sc = keyRing.getCertificate();


        if (!listed) {

            ok = VPNCertificateHandler.verify(other, keyRing.getCAPublicKey());
            if (!ok) {
                enterText(getName() + ": Certificate verification failed.");
                ok = false;}
        }
        else {
                enterText(getName() + ": " + other.getSubjectName() + " IS in your list.");
        }
        
            return (ok && !listed);
        
    }

protected void keyAgreement(PublicKey pubKey, PrivateKey privKey) throws Exception {
        int length;
        RSA rsa = new RSA(pubKey, privKey);
        RSA rsaOther = new RSA(other.getPublicKey(), null);
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

        length =
                in.readInt();
        byte[] crypt2 = new byte[length];
        in.read(crypt2);
        SecretKeySpec s2 = (SecretKeySpec) rsa.unwrap(crypt2, "AES", Cipher.SECRET_KEY);

        byte[] half2 = s2.getEncoded();

        byte[] full = new byte[16];
        for (int i = 0; i < 8; i++) {
            full[i] = half1[i];
            full[8 + i] = half2[i];
        }

        SecretKeySpec key = new SecretKeySpec(full, "AES");

        aes =
                new AES(key);

        for (int i = 0; i < 16; i++) {
            full[i] = 0;
            half1[i] = 0;
            half2[i] = 0;
        }

        s1 = new SecretKeySpec(full, "AES");
        s2 = new SecretKeySpec(full, "AES");
        key = new SecretKeySpec(full, "AES");
    }

    public void readSerial() throws Exception 
    {
        byte[] encoded;
        byte[] decoded;
        int length;

        length = in.readInt(); // wait for the client to send a line of text.

        encoded = new byte[length];
        in.read(encoded);
        decoded = aes.decrypt(encoded);

        serial = new BigInteger(decoded);
    }

    public void sendIfListed(boolean listed) throws Exception 
    {
        byte[] encoded;
        byte[] msg = new byte[1];

        if (listed) {
            msg[0] = 1;
        } else {
            msg[0] = 0;
        }

        encoded = aes.encrypt(msg);
        out.writeInt(encoded.length);
        out.write(encoded);
        out.flush();
    }

    public String readMsg() throws Exception 
    {
        byte[] encoded;
        byte[] decoded;
        int length;

        length =
                in.readInt();
        encoded =
                new byte[length];
        in.read(encoded);
        decoded = aes.decrypt(encoded);
        String line = new String(decoded);

        enterText(getName() + ": Received encrypted message: " + VPNCertificate.Byte2Hex(encoded));

        return line;
    }

    public void sendMsg(String msg) throws Exception {
        byte[] encoded;

        encoded = aes.encrypt(msg);
        out.writeInt(encoded.length);
        out.write(encoded);
        out.flush();
    }

    public void sendBlackList() throws Exception {
        LinkedList<KeyRing.BlackListEntry> l = keyRing.getBlackList();

        out.writeInt(l.size());
        for (int i = 0; i < l.size(); i++) {
            KeyRing.BlackListEntry ble = l.get(i);

            sendMsg(ble.serial.toString());
        }

    }

    public void run() {
        while (keepServerRunning) {
            try {
                ss = new ServerSocket(port); // create a server socket and bind it to the above port number.
                //	JOptionPane.showMessageDialog(comp, getName() + " is running on port: " + port + ".");
                label.setText(getName() + " port: " + port);
                Socket socket = ss.accept(); // make the server listen for a connection, and let you know when it gets one.

                jf.setVisible(true);
                enterText(getName() + ": Just got a client.");

                // Get the input and output streams of the socket, so that you can receive and send data to the client.
                InputStream sin = socket.getInputStream();
                OutputStream sout = socket.getOutputStream();

                // Just converting them to different streams, so that string handling becomes easier.
                in =
                        new DataInputStream(sin);
                out =
                        new DataOutputStream(sout);

                String line = null;

                boolean ok = handshake();

                if (ok) {
                    if (clientMode == BlackListServer.Ask_For_One_Certificate_Mode) {
                        readSerial();

                        enterText(getName() + ": " +
                                other.getSubject() + " asks if SerialNumber: " +
                                serial + " is black-listed.");

                        boolean listed = keyRing.blackListContains(serial);

                        if (listed) {
                            enterText(getName() + ": SerialNumber: " + serial + " IS black listed. Sending true");
                        } else {
                            enterText(getName() + ": SerialNumber: " + serial + " is NOT black listed. Sending false");
                        }
                        sendIfListed(listed);
                        serial =
                                null;
                    } else if (clientMode == BlackListServer.Get_Full_Update_Mode) {
                        enterText(getName() + ": sending black-list update to client: " + other.getSubjectName() + "...");
                        sendBlackList();
                        enterText(getName() + ": Sent black-list update to client: " + other.getSubjectName());
                    }

                }
            } catch (BindException b) {
                try {
                    ss.close();
                } catch (Exception epapath) {
                    port++;
                }

            } catch (Exception e) {
                enterText(e + "\n" + getName() + "\n Error Occured. Connection terminated.");
            }
            enterText("------------------------");
        }

        return;
    }

    public class Exit implements ActionListener {

        public void actionPerformed(ActionEvent e) {
            jf.setVisible(false);
        }
    }
}
