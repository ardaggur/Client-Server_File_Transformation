import java.util.*;
import java.math.*;
import javax.crypto.Cipher;
import java.security.*;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;
import javax.crypto.spec.*;

public class PGP{

    static Cipher ecipher, dcipher;//Required for DES

    public static void main(String args[]) throws Exception{

        // 23 ve 29. satırlarda Alice ve Bob icin key generate ettim.
        KeyPair senderkeyPair = buildKeyPair();
        PublicKey senderpubKey = senderkeyPair.getPublic();
        PrivateKey senderprivateKey = senderkeyPair.getPrivate();

        KeyPair receiverkeyPair = buildKeyPair();
        PublicKey receiverpubKey = receiverkeyPair.getPublic();
        PrivateKey receiverprivateKey = receiverkeyPair.getPrivate();

        //Digital signature veya asymmetric encryption için public ve private keyleri paylaştım.
        String messagetoreceiver[] = senderside(senderpubKey, senderprivateKey, receiverpubKey, receiverprivateKey);
        receiverside(messagetoreceiver, senderpubKey, senderprivateKey, receiverpubKey, receiverprivateKey);
    }


    public static void receiverside(String messagetoreceiver[], PublicKey senderpubKey, PrivateKey senderprivateKey, PublicKey receiverpubKey, PrivateKey receiverprivateKey) throws Exception {

        //Receiver receives the message messagetoreceiver[] with messagetoreceiver[2] as secret key encrypted with receiver pub key
        //Receiver decrypts the messagetoreceiver[2] with his/her privatekey
        String receiverencodedsecretkey = decrypt(receiverpubKey, receiverprivateKey, messagetoreceiver[2], 1);
        //Key after decryption is in base64 encoded form
        byte[] decodedKey = Base64.getDecoder().decode(receiverencodedsecretkey);
        SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "DES");
        System.out.println("\nReceiver Side: Receiver SecretKey DES after Decryption with his/her Private Key=\n"+originalKey.toString());

        //Decrypt the rest of the message in messagetoreceiver with SecretKey originalKey

        String receiverdecryptedmessage[] = new String[messagetoreceiver.length-1];
        System.out.println("\nReceiver Side: Message After Decryption with SecretKey=");
        for (int i=0;i<messagetoreceiver.length-1;i++) {
            messagetoreceiver[i] = decryptDES(messagetoreceiver[i], originalKey);
            System.out.println(messagetoreceiver[i]);
        }

        //mesajı messagegotreceiver ile unzipliyorum
        String unzipstring[] = new String[receiverdecryptedmessage.length];
        System.out.println("\nReceiver Side: UnZipped Message=");
        for (int i=0;i<unzipstring.length;i++) {
            unzipstring[i] = decompress(messagetoreceiver[i]);
            System.out.println(unzipstring[i]);
        }

        //Message has been received and is in unzipstring but check the digital signature of the sender i.e. verify the hash with senderpubkey
        //So decrypting the encrypted hash in unzipstring with sender pub key
        String receivedhash = decrypt(senderpubKey, senderprivateKey, unzipstring[1], 0);
        System.out.println("\nReceiver Side: Received Hash=\n"+receivedhash);
        //Calculating SHA512 at receiver side of message
        String calculatedhash = sha512(unzipstring[0]);
        System.out.println("\nReceiver Side: Calculated Hash by Receiver=\n"+calculatedhash);
        if (receivedhash.equalsIgnoreCase(calculatedhash)) {
            System.out.println("\nReceived Hash = Calculated Hash\nThus, Confidentiality and Authentication both are achieved\nSuccessful PGP Simulation\n");
        }

    }


    public static String[] senderside(PublicKey senderpubKey, PrivateKey senderprivateKey, PublicKey receiverpubKey, PrivateKey receiverprivateKey) throws Exception {

        //Input from user
        System.out.print("\nPGP Simulation:\nSender Side: Input messsage=\n");
        Scanner sc = new Scanner(System.in);
        String rawinput;
        rawinput = sc.nextLine();

        //Generating SHA-512 hash of original message
        String hashout = sha512(rawinput);
        System.out.println("\nSender Side: Hash of Message=\n"+hashout);

        //Encrypt the message hash with sender private keys -> Digital Signature
        String encryptedprivhash = encrypt(senderpubKey, senderprivateKey, hashout, 0);
        System.out.println("\nSender Side: Hash Encrypted with Sender Private Key (Digital Signature)=\n"+ encryptedprivhash);

        //Append original message and encrypted hash
        String beforezipstring[] = {rawinput, encryptedprivhash};
        System.out.println("\nSender Side: Message before Compression=\n"+beforezipstring[0]+beforezipstring[1]);

        //Apply zip to beforezipbytes[][]
        String afterzipstring[] = new String[beforezipstring.length];
        System.out.println("\nSender Side: Message after Compression=");
        for (int i=0;i<beforezipstring.length;i++) {
            afterzipstring[i] = compress(beforezipstring[i]);
            System.out.println(afterzipstring[i]);
        }

        //Encrypt zipstring with DES
        SecretKey key = KeyGenerator.getInstance("DES").generateKey();
        System.out.println("\nSender Side: SecretKey DES=\n"+key.toString());
        String afterzipstringDES[] = new String[afterzipstring.length+1];
        System.out.println("\nSender Side: Compressed Message Encrypted with SecretKey=");
        for (int i=0;i<afterzipstring.length;i++) {
            afterzipstringDES[i] = encryptDES(afterzipstring[i], key);
            System.out.println(afterzipstringDES[i]);
        }

        //Encrypt DES key with Receiver Public Key using RSA
        String encodedKey = Base64.getEncoder().encodeToString(key.getEncoded());
        //SecretKey is base64 encoded since direct string enccryption gives key in string format during decryption which cant be converted to SecretKey Format
        String keyencryptedwithreceiverpub = encrypt(receiverpubKey, receiverprivateKey, encodedKey, 1);
        System.out.println("\nSender Side: DES SecretKey Encrypted with Receiver Public Key=\n"+keyencryptedwithreceiverpub);

        //Decrypting DES key with Receiver Private Key using RSA
        afterzipstringDES[2]=keyencryptedwithreceiverpub;
        String messagetoreceiver[] = afterzipstringDES;
        System.out.println("\nFinal Message to receiver=");
        for (int i=0;i<messagetoreceiver.length;i++) {
            System.out.println(messagetoreceiver[i]);
        }
        return messagetoreceiver;
    }


    public static String encryptDES(String str, SecretKey key) throws Exception {
        ecipher = Cipher.getInstance("DES");
        ecipher.init(Cipher.ENCRYPT_MODE, key);
        // Encode the string into bytes using utf-8
        byte[] utf8 = str.getBytes("UTF8");
        // Encrypt
        byte[] enc = ecipher.doFinal(utf8);
        // Encode bytes to base64 to get a string
        return Base64.getEncoder().encodeToString(enc); //new sun.misc.BASE64Encoder().encode(enc);
    }


    public static String decryptDES(String st, SecretKey key) throws Exception {
        dcipher = Cipher.getInstance("DES");
        dcipher.init(Cipher.DECRYPT_MODE, key);
        // Decode base64 to get bytes
        byte[] dec = Base64.getDecoder().decode(st);  //new sun.misc.BASE64Decoder().decodeBuffer(st);
        byte[] utf8 = dcipher.doFinal(dec);
        // Decode using utf-8
        return new String(utf8, "UTF8");
    }


    public static String decompress(String st) throws IOException {
        byte[] compressed = Base64.getDecoder().decode(st);  //new sun.misc.BASE64Decoder().decodeBuffer(st);
        ByteArrayInputStream bis = new ByteArrayInputStream(compressed);
        GZIPInputStream gis = new GZIPInputStream(bis);
        BufferedReader br = new BufferedReader(new InputStreamReader(gis, "UTF-8"));
        StringBuilder sb = new StringBuilder();
        String line;
        while((line = br.readLine()) != null) {
            sb.append(line);
        }
        br.close();
        gis.close();
        bis.close();
        return sb.toString();
    }


    public static String compress(String data) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream(data.length());
        GZIPOutputStream gzip = new GZIPOutputStream(bos);
        gzip.write(data.getBytes());
        gzip.close();
        byte[] compressed = bos.toByteArray();
        bos.close();
        return  Base64.getEncoder().encodeToString(compressed); //new sun.misc.BASE64Encoder().encode(compressed);
    }


    //Takes any string as input and calculates sha 512 bit hash. Output is in 128 bit hex string
    public static String sha512(String rawinput){
        String hashout = "";
        try{
            MessageDigest digest = MessageDigest.getInstance("SHA-512");
            digest.reset();
            digest.update(rawinput.getBytes("utf8"));
            hashout = String.format("%040x", new BigInteger(1, digest.digest()));
        }
        catch(Exception E){
            System.out.println("Hash Exception");
        }
        return hashout;
    }


    public static KeyPair buildKeyPair() throws NoSuchAlgorithmException {
        final int keySize = 2048;
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(keySize);
        return keyPairGenerator.genKeyPair();
    }


    //n: 0->encryptwithprivatekey 1->encryptwithpublickey
    public static String encrypt(PublicKey publicKey, PrivateKey privateKey, String message, int ch) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        if (ch == 0) {
            cipher.init(Cipher.ENCRYPT_MODE, privateKey);
            byte[] utf8 = cipher.doFinal(message.getBytes("UTF-8"));
            return Base64.getEncoder().encodeToString(utf8);
        }
        else {
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] utf8 = cipher.doFinal(message.getBytes("UTF-8"));
            return Base64.getEncoder().encodeToString(utf8);
        }
    }


    //n: 0->decryptwithpublickey 1->decryptwithprivatekey
    public static String decrypt(PublicKey publicKey,PrivateKey privateKey, String st, int ch) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        byte[] encrypted = Base64.getDecoder().decode(st);
        if (ch == 0) {
            cipher.init(Cipher.DECRYPT_MODE, publicKey);
            byte[] utf8 = cipher.doFinal(encrypted);
            return new String(utf8, "UTF8");
        }
        else {
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] utf8 = cipher.doFinal(encrypted);
            return new String(utf8, "UTF8");
        }
    }
}