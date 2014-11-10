package cert;

import crypto.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.util.Date;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;

public class VPNCertificate {

    private Date startDate;
    private Date endDate;
    private BigInteger serial;
    private Principal issuer;
    private Principal subject;
    private PublicKey pubKey;
    private byte[] signature;
    private SecretKeySpec secKey;

    public VPNCertificate(Date start, Date end, BigInteger sn, Principal iss,
            Principal subj, PublicKey pub) throws Exception {
        startDate = start;
        endDate = end;
        serial = sn;
        issuer = iss;
        subject = subj;
        pubKey = pub;
        signature = null;
        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        keygen.init(128);
        SecretKey sk = keygen.generateKey();
        byte[] raw = sk.getEncoded();
        secKey = new SecretKeySpec(raw, "AES");
    }

    public VPNCertificate(Date start, Date end, BigInteger sn, Principal iss,
            Principal subj, PublicKey pub,SecretKeySpec sec) throws Exception {
        startDate = start;
        endDate = end;
        serial = sn;
        issuer = iss;
        subject = subj;
        pubKey = pub;
        signature = null;
        secKey = sec;
    }

    public void sign(byte[] sig) {
        this.signature = new byte[sig.length];
        for (int i = 0; i < sig.length; i++) {
            this.signature[i] = sig[i];
        }
    }

    public boolean checkValidity(Date d) {
        return d.after(this.startDate) && d.before(this.endDate);
    }

    public boolean checkValidity() {
        Date d = new Date();

        return d.after(this.startDate) && d.before(this.endDate);
    }

    public BigInteger getSerialNumber() {
        return this.serial;
    }

    public Principal getIssuer() {
        return this.issuer;
    }

    public String getIssuerName() {
        String s = this.issuer.getName();
        String[] str = s.split("=", 2);
        return str[1];
    }

    public Principal getSubject() {
        return this.subject;
    }

    public String getSubjectName() {
        String s = this.subject.getName();
        String[] str = s.split("=", 2);

        return str[1];
    }

    public PublicKey getPublicKey() {
        return this.pubKey;
    }

    public byte[] getSignature() {
        return this.signature;
    }

    public byte[] getEncoded() throws Exception {
        int length;
        byte[] encoded;
        byte[] date1, date2, ser;
        byte[] sec, pub;
        byte[] iss, subj;
        byte[] date1Len, date2Len, serLen, issLen, subjLen, secLen, pubLen;

        date1 = Long.toBinaryString(this.startDate.getTime()).getBytes();
        date2 = Long.toBinaryString(this.endDate.getTime()).getBytes();
        ser = this.serial.toByteArray();

        sec = this.secKey.getEncoded();

        AES aes = new AES(this.secKey);
        pub = aes.wrap(this.pubKey);

        iss = this.issuer.getName().getBytes();
        subj = this.subject.getName().getBytes();

        // 7*4 = gia tous integers pou deixnoun to mhkos twn pediwn
        length = 7 * 4 + date1.length + date2.length + ser.length + sec.length + pub.length + iss.length + subj.length;

        encoded = new byte[length];

        int i, j = 0;

        date1Len = VPNCertificate.intToByteArray(date1.length);
        for (i = 0; i < date1Len.length; i++) {
            encoded[j++] = date1Len[i];
        }		// date start
        for (i = 0; i < date1.length; i++) {
            encoded[j++] = date1[i];
        }


        date2Len = VPNCertificate.intToByteArray(date2.length);
        for (i = 0; i < date2Len.length; i++) {
            encoded[j++] = date2Len[i];
        }		// date end
        for (i = 0; i < date2.length; i++) {
            encoded[j++] = date2[i];
        }


        serLen = VPNCertificate.intToByteArray(ser.length);
        for (i = 0; i < serLen.length; i++) {
            encoded[j++] = serLen[i];
        }		// serial number
        for (i = 0; i < ser.length; i++) {
            encoded[j++] = ser[i];
        }


        issLen = VPNCertificate.intToByteArray(iss.length);
        for (i = 0; i < issLen.length; i++) {
            encoded[j++] = issLen[i];
        }		// issuer
        for (i = 0; i < iss.length; i++) {
            encoded[j++] = iss[i];
        }


        subjLen = VPNCertificate.intToByteArray(subj.length);
        for (i = 0; i < subjLen.length; i++) {
            encoded[j++] = subjLen[i];
        }		// subject
        for (i = 0; i < subj.length; i++) {
            encoded[j++] = subj[i];
        }


        secLen = VPNCertificate.intToByteArray(sec.length);
        for (i = 0; i < secLen.length; i++) {
            encoded[j++] = secLen[i];
        }		// AES key
        for (i = 0; i < sec.length; i++) {
            encoded[j++] = sec[i];
        }

        pubLen = VPNCertificate.intToByteArray(pub.length);
        for (i = 0; i < pubLen.length; i++) {
            encoded[j++] = pubLen[i];
        }		// Public Key
        for (i = 0; i < pub.length; i++) {
            encoded[j++] = pub[i];
        }

        return encoded;
    }

    public byte[] getBytes() throws Exception {
        int length = 0;
        byte[] enc = this.getEncoded();
        byte[] sig = this.signature;
        byte[] sigLen;
        byte[] b = null;
        byte[] len = null;

        length = enc.length;
        if (this.signature != null) {
            length += 4 + sig.length;
        }

        len = VPNCertificate.intToByteArray(length);

        b = new byte[4 + length];

        int j = 0;

        for (int i = 0; i < len.length; i++) {
            b[j++] = len[i];
        }

        for (int i = 0; i < enc.length; i++) {
            b[j++] = enc[i];
        }

        if (this.signature != null) {
            sigLen = VPNCertificate.intToByteArray(sig.length);
            for (int i = 0; i < sigLen.length; i++) {
                b[j++] = sigLen[i];
            }
            for (int i = 0; i < sig.length; i++) {
                b[j++] = sig[i];
            }
        }

        return b;
    }

    public boolean equals(VPNCertificate sc) {
        if (this.startDate.compareTo(sc.startDate) != 0) {
            return false;
        }
        if (this.endDate.compareTo(sc.endDate) != 0) {
            return false;
        }
        if (this.serial.compareTo(sc.serial) != 0) {
            return false;
        }
        if (this.issuer.equals(sc.issuer) == false) {
            return false;
        }
        if (this.subject.equals(sc.subject) == false) {
            return false;
        }
        if (this.pubKey.equals(sc.pubKey) == false) {
            return false;
        }
        if (compareByteArrays(this.signature, sc.getSignature()) == false) {
            return false;
        }

        return true;
    }

    public static final byte[] intToByteArray(int value) {
        return new byte[]{
            (byte) (value >>> 24), (byte) (value >> 16 & 0xff), (byte) (value >> 8 & 0xff), (byte) (value & 0xff)
        };
    }

    private static boolean compareByteArrays(byte[] b1, byte[] b2) {
        if (b1 == null && b2 == null) {
            return true;
        } else if (b1 == null || b2 == null) {
            return false;
        }


        if (b1.length != b2.length) {
            return false;
        }

        for (int i = 0; i < b1.length; i++) {
            if (b1[i] != b2[i]) {
                return false;
            }
        }

        return true;
    }

    public static String Byte2Hex(byte[] b) {
        StringBuffer hexString = new StringBuffer();
        String tmp;
        for (int i = 0; i < b.length; i++) {
            tmp = Integer.toHexString(0xFF & b[i]);
            if (tmp.length() == 1) {
                hexString.append("0" + tmp);
            } else {
                hexString.append(tmp);
            }
            hexString.append(" ");
        }
        return (hexString.toString());
    }

    public String toString() {
        return "VPNCertificate\nIssuer:" + this.issuer + "\nSubject:" + this.subject + "\nSerial Number:" + this.serial + "\nStarting: " + this.startDate + "\nExpiring: " + this.endDate;
    }
}

