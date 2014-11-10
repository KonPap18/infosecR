/*
 * TalkServer.java
 */
package servers;

import cert.*;
import clients.*;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.net.*;
import java.security.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import crypto.*;

/**
 * @author JChrist-Condiak
 */
public class TalkServer extends Thread 
{
    protected int port;
    protected boolean keepServerRunning;
    protected boolean keepTalking;
    protected ServerSocket ss;
    protected DataInputStream in;
    protected DataOutputStream out;
    protected KeyRing keyRing;
    protected VPNCertificate other;
    protected VPNCertificate sc;
    private JLabel label;
    private AES aes;
    private byte[] logRecord;
    protected Read read;
    protected Write write;
    protected JScrollPane scroll;
    protected JTextArea textArea;
    protected JTextField input;
    protected JButton submit;
    protected JButton exit;
    protected JFrame talkFrame;
    protected JPanel north;
    protected JPanel south;

    public TalkServer(String name, JLabel jl, KeyRing kr) 
    {
        super(name);
        port = 7111;
        label = jl;
        keyRing = kr;
        keepServerRunning = true;
        other = null;
        logRecord = null;

        write = new Write();
        read = new Read();

        talkFrame = new JFrame(name + " Frame");

        north = new JPanel();
        north.setLayout(new GridLayout(1, 3));

        south = new JPanel();
        south.setLayout(new GridLayout(1, 2));

        exit = new JButton("Quit Talk");
        exit.addActionListener(new Exit());

        textArea = new JTextArea(null, null, 50, 50);
        textArea.setEditable(false);

        scroll = new JScrollPane(textArea);

        input = new JTextField();
        input.setText("");

        submit = new JButton("Submit");
        submit.addActionListener(new Submit());

        talkFrame.setSize(500, 500);
        talkFrame.setLayout(new BorderLayout());

        north.add(exit);

        south.add(input);
        south.add(submit);

        talkFrame.add(north, BorderLayout.NORTH);
        talkFrame.add(scroll, BorderLayout.CENTER);
        talkFrame.add(south, BorderLayout.SOUTH);

        talkFrame.setDefaultCloseOperation(JFrame.HIDE_ON_CLOSE);
    }

    public int getPort() {
        return port;
    }

    public void end() {
        keepServerRunning = false;
    }

    protected void handshake() throws Exception {
        PublicKey pub;
        PrivateKey priv;

        boolean ok = sendReceiveCertificate();
        String s;
        if (ok) {
            s = new String("OK");
        } else {
            s = new String("NO");
        }

        out.writeUTF(s);
        out.flush();
        String st = in.readUTF();

        if (ok && st.compareToIgnoreCase("OK") == 0) {
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
            keepTalking = true;
        } else {
            if (other != null) {
                enterText(getName() + ": Connection refused to: " + other.getSubject());
            } else {
                enterText(getName() + ": Connection refused to client.");
            }
            ok = false;
            endTalk();
        }
    }

    private boolean sendReceiveCertificate() throws Exception 
    {
        boolean ok = false, listed = false, checkCAIfListed = false;
        byte[] myCert = sc.getBytes();
        out.write(myCert);
        out.flush();

        other = VPNCertificateHandler.generateCertificate(in);

	ok = VPNCertificateHandler.verify(other, keyRing.getCAPublicKey());
        listed = keyRing.blackListContains(other.getSerialNumber());
        if (!listed) {
            enterText(getName()+": "+other.getSubjectName()+" IS not in your list.");
        } else {
            enterText(getName() + ": " + other.getSubjectName() + " IS in your list.");
        }

        return (ok && !listed);
    }

    protected void keyAgreement(PublicKey pubKey, PrivateKey privKey) throws Exception {
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

        int length = in.readInt();
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

        aes = new AES(key);

        for (int i = 0; i < 16; i++) {
            full[i] = 0;
            half1[i] = 0;
            half2[i] = 0;
        }
        s1 = new SecretKeySpec(full, "AES");
        s2 = new SecretKeySpec(full, "AES");
        key = new SecretKeySpec(full, "AES");
    }

    private synchronized String readMsg() throws Exception {
        byte[] encoded;
        byte[] decoded;
        int length;

        length = in.readInt();

        encoded = new byte[length];
        in.read(encoded);
        decoded = aes.decrypt(encoded);
        String line = new String(decoded);

        enterText(getName() + ": Received encrypted message:" + VPNCertificate.Byte2Hex(encoded));

        return line;
    }

    private synchronized void sendMsg(String msg) throws Exception {
        byte[] encoded;

        encoded = aes.encrypt(msg);
        out.writeInt(encoded.length);
        out.write(encoded);
        out.flush();
    }

    public void enterText(String text) {
        String previous = textArea.getText();
        String full = previous.concat(text + "\n");
        textArea.setText(full);
    }

    protected void endTalk() throws Exception {
        keepTalking = false;
        other = null;
        if (logRecord != null) {
            String log = new String(aes.decrypt(logRecord));
            keyRing.saveMsgToLog(log);
            log = "flushed";
        }
        aes = null;
        textArea.setText("");
    }

    protected void addMsgToLog(Date time, Principal sender, Principal receiver, String msg) throws Exception {
        String record = new String("\n**************************************\n" +
                "time: " + time.toString() + "\n" +
                "sender: " + sender.getName() + "\n" +
                "receiver: " + receiver.getName() + "\n" +
                msg + "\n**************************************\n");
        String previous = new String("");
        if (logRecord != null) {
            byte[] dec = aes.decrypt(logRecord);
            previous = new String(dec);
        }
        String full = previous + record;

        logRecord = aes.encrypt(full);
    }

    public void run() {
        while (keepServerRunning) {
            try {
                ss = new ServerSocket(port); // create a server socket and bind it to the above port number.
                //	JOptionPane.showMessageDialog(comp, getName() + " is running on port: " + port + ".");
                label.setText(getName() + " port: " + port);
                label.setVisible(true);

                Socket socket = ss.accept(); // make the server listen for a connection, and let you know when it gets one.

                talkFrame.setVisible(true);
                enterText(getName() + ": Just got a client.");

                // Get the input and output streams of the socket, so that you can receive and send data to the client.
                InputStream sin = socket.getInputStream();
                OutputStream sout = socket.getOutputStream();

                // Just converting them to different streams, so that string handling becomes easier.
                in = new DataInputStream(sin);
                out = new DataOutputStream(sout);

                sc = keyRing.getCertificate();

                String line = null;

                handshake();

                if (keepTalking) {
                    logRecord = null;
                    read.start();
                    write.start();

                    enterText("Connection made. You are ready to talk.");
                }

                while (keepTalking) {
                }

                enterText("Connection Finished.");

                try {
                    ss.close();
                } catch (Exception lol) {
                }
            } catch (BindException b) {
                try {
                    ss.close();
                } catch (Exception lol2) {
                    port++;
                }
            } catch (Exception e) {
                enterText(getName() + "\nError Occured. Connection terminated.");
                try {
                    ss.close();
                } catch (Exception lol) {
                }
            }
        }
        return;
    }

    public class Read extends Thread {

        public void run() {
            try {
                while (keepTalking) {
                    String line = readMsg();

                    if (line.compareToIgnoreCase("!end") == 0) {
                        addMsgToLog(new Date(), other.getSubject(), sc.getSubject(), line);
                        line = new String("End of talk");
                        enterText(line);
                        endTalk();
                    } else {
                        String detail = new String(new Date() + " - " + other.getSubjectName() + " says:\n" + line);
                        enterText(detail);

                        addMsgToLog(new Date(), other.getSubject(), sc.getSubject(), line);
                        line = null;
                    }
                }
            } catch (Exception e) {
                enterText("Error Occured. Connection Terminating.");
                try {
                    write.sendMsg("!end");
                    endTalk();
                } catch (Exception ex) {
                }
            }
        }
    }

    public class Write extends Thread {

        public void run() {
            while (keepTalking) {
            }
        }

        public void sendMsg(String msg) throws Exception {
            byte[] encoded;

            encoded = aes.encrypt(msg);
            out.writeInt(encoded.length);
            out.write(encoded);
            out.flush();

            String full = new String(new Date() + " - " + sc.getSubjectName() + " says:\n" + msg);
            enterText(full);
            addMsgToLog(new Date(), sc.getSubject(), other.getSubject(), msg);

            msg = null;
        }
    }

    public class Exit implements ActionListener {

        public void actionPerformed(ActionEvent e) {
            try {
                if (write.isAlive()) {
                    write.sendMsg("!end");
                }
                endTalk();
                ss.close();
            } catch (Exception ex) {
            }
            talkFrame.setVisible(false);
        }
    }

    public class Submit implements ActionListener {

        public void actionPerformed(ActionEvent e) {
            try {
                String in = input.getText();
                if (in.charAt(0) == '!') {
                    in = null;
                    JOptionPane.showMessageDialog(null, "Cannot start message with <!>\nKept for operational purposes.");
                }
                if (in != null && in.length() != 0) {
                    write.sendMsg(in);
                    input.setText("");
                }
            } catch (Exception ex) {
                input.setText("");
            }
        }
    }
}
