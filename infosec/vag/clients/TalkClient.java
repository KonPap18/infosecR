package clients;

import cert.*;
import crypto.*;
import servers.*;
import java.awt.*;
import java.awt.event.*;
import java.net.*;
import java.io.*;
import java.security.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;

public class TalkClient extends Thread 
{

    private int port;
    private String address;
    private DataInputStream in;
    private DataOutputStream out;
    private boolean keepTalking;
    private KeyRing keyRing;
    private VPNCertificate other;
    private VPNCertificate sc;
    private AES aes;
    private byte[] logRecord;
    protected Read read;
    protected Write write;
    protected TalkClient client;
    protected JTextField addrField;
    protected JTextField portField;
    protected JToggleButton connect;
    protected JScrollPane scroll;
    protected JTextArea textArea;
    protected JTextField input;
    protected JButton submit;
    protected JButton exit;
    protected JFrame talkFrame;
    protected JPanel north;
    protected JPanel south;

    public TalkClient(String name, KeyRing kr) 
    {
        super(name);

        keyRing = kr;
        read = new Read();
        write = new Write();

        talkFrame = new JFrame(getName());

        north = new JPanel();
        north.setLayout(new GridLayout(1, 4));

        south = new JPanel();
        south.setLayout(new GridLayout(1, 2));

        addrField = new JTextField();
        addrField.setText("Enter ip address here.");

        portField = new JTextField();
        portField.setText("Enter Talk Server's port here.");

        connect = new JToggleButton("Click to Connect");
        connect.addActionListener(new Connect());

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

        north.add(addrField);
        north.add(portField);
        north.add(connect);
        north.add(exit);

        south.add(input);
        south.add(submit);

        talkFrame.add(north, BorderLayout.NORTH);
        talkFrame.add(scroll, BorderLayout.CENTER);
        talkFrame.add(south, BorderLayout.SOUTH);

        talkFrame.setDefaultCloseOperation(JFrame.HIDE_ON_CLOSE);
        talkFrame.setVisible(true);

        client = this;
    }

    public boolean getHandshaked() throws Exception {
        PublicKey pub;
        PrivateKey priv;
        sc = keyRing.getCertificate();
        boolean ok = sendReceiveCertificate();
        String st;
        if (ok) {
            st = new String("OK");
        } else {
            st = new String("NO");
        }

        String s = in.readUTF();
        out.writeUTF(st);
        out.flush();

        if (ok && s.compareToIgnoreCase("OK") == 0) {
            pub = keyRing.getPublicKey();
            priv = keyRing.getPrivateKey();

            boolean retry = false;
            do {
                keyAgreement(pub, priv);

                String line = readMsg();
                if (line.compareToIgnoreCase("OK?") == 0) {
                    sendMsg("OK");
                    retry = false;
                } else {
                    sendMsg("Retry");
                    retry = true;
                }

                line = readMsg();
                if (line.compareToIgnoreCase("Retry") == 0) {
                    retry = true;
                }

            } while (retry);

            enterText(getName() + ": Connection accepted from: " + other.getSubject());
            keepTalking = true;
        } else {
            if (other != null) {
                enterText(getName() + ": Connection refused to: " + other.getSubject());
            } else {
                enterText(getName() + ": Connection refused");
            }
            ok = false;
            end();
        }

        return ok;
    }

    private boolean sendReceiveCertificate() throws Exception {
        boolean ok = false, listed = false, checkCAIfListed = false;
        byte[] myCert = sc.getBytes();

        other = VPNCertificateHandler.generateCertificate(in);

        out.write(myCert);
        out.flush();

        listed = keyRing.blackListContains(other.getSerialNumber());
        if (!listed) {
            ok = VPNCertificateHandler.verify(other, keyRing.getCAPublicKey());
            if (!ok) {
                enterText(getName() + ": Certificate verification failed");
            } else {
		enterText(getName() + ": Certificate verification succeeded");
            }
        } else {
            enterText(getName() + ": " + other.getSubjectName() + " IS in your list.");
        }

        return (ok && !listed);
    }

    private void keyAgreement(PublicKey pub, PrivateKey priv) throws Exception {
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
        for (int i = 0; i < 8; i++) {
            full[i] = half2[i];
            full[8 + i] = half1[i];
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

    public String readMsg() throws Exception {
        byte[] encoded;
        byte[] decoded;
        int length;

        length = in.readInt();
        encoded = new byte[length];
        in.read(encoded);
        decoded = aes.decrypt(encoded);
        String line = new String(decoded);

        enterText(getName() + ": Received encrypted message: " + VPNCertificate.Byte2Hex(encoded));

        return line;
    }

    public synchronized void sendMsg(String msg) throws Exception {
        byte[] encoded;

        encoded = aes.encrypt(msg);
        out.writeInt(encoded.length);
        out.write(encoded);
        out.flush();
    }

    public void end() throws Exception {
        if (logRecord != null) {
            String log = new String(aes.decrypt(logRecord));
            keyRing.saveMsgToLog(log);
            log = "flushed";
            logRecord = null;
        }
        keepTalking = false;
        connect.setSelected(false);
        enterText("You are disconnected.");
    }

    public void addMsgToLog(Date time, Principal sender, Principal receiver, String msg) throws Exception {
        String record = new String("\n**************************************\n" +
                "time: " + time.toString() + "\n" +
                "sender: " + sender.getName() + "\n" +
                "receiver: " + receiver.getName() + "\n" +
                msg + "	\n**************************************\n");
        String previous = new String("");
        if (logRecord != null) {
            byte[] dec = aes.decrypt(logRecord);
            previous = new String(dec);
        }
        String full = previous + record;

        logRecord = aes.encrypt(full);
    }

    public synchronized void enterText(String text) {
        String previous = textArea.getText();
        String full = previous.concat(text + "\n");
        textArea.setText(full);
    }

    public void run() {
        int serverPort = port; // make sure you give the port number on which the server is listening.
        //String address = address; //"127.0.0.1";  this is the IP address of the server program's computer.
        //the address given here means "the same computer as the client".
        Socket socket = null;
        try {
            InetAddress ipAddress = InetAddress.getByName(address); // create an object that represents the above IP address.
            enterText(getName() + ": Connecting to socket with IP address " + address + " and port " + serverPort);

            socket = new Socket(ipAddress, serverPort); // create a socket with the server's IP address and server's port.
            enterText(getName() + ": Connected.");

            // Get the input and output streams of the socket, so that you can receive and send data to the client.
            InputStream sin = socket.getInputStream();
            OutputStream sout = socket.getOutputStream();

            // Just converting them to different streams, so that string handling becomes easier.
            in = new DataInputStream(sin);
            out = new DataOutputStream(sout);

            keepTalking = getHandshaked();

            if (keepTalking) {
                read.start();
                write.start();

                enterText("Connection made. You are ready to talk.");
            }

            while (keepTalking) {
            }
        } catch (Exception e) {
            enterText(getName() + ": Error in connection. Terminating.");
            try {
                socket.close();
            } catch (Exception ex) {
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
                        end();
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
                    client.end();
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
                connect.setSelected(false);
                connect.setText("Click to Connect");
                addrField.setText("Enter ip address here.");
                portField.setText("Enter Talk Server's port here.");

                if (write.isAlive()) {
                    write.sendMsg("!end");
                }

                client.end();
            } catch (Exception ex) {
            }
            talkFrame.setVisible(false);
        }
    }

    public class Connect implements ActionListener {

        public void actionPerformed(ActionEvent e) {
            if (connect.isSelected()) {
                try {
                    address = addrField.getText();
                    port = Integer.parseInt(portField.getText());

                    client.start();
                } catch (Exception ex) {
                    connect.setSelected(false);
                    connect.setText("Click to Connect");
                    addrField.setText("Enter ip address here.");
                    portField.setText("Enter Talk Server's port here.");
                }
            } else {
                try {
                    client.end();
                    connect.setSelected(false);
                    connect.setText("Click to Connect");
                    addrField.setText("Enter ip address here.");
                    portField.setText("Enter Talk Server's port here.");

                    write.sendMsg("!end");

                    enterText("You are disconnected.");
                } catch (Exception exc) {
                    connect.setSelected(false);
                    connect.setText("Click to Connect");
                    addrField.setText("Enter ip address here.");
                    portField.setText("Enter Talk Server's port here.");
                }
            }
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
