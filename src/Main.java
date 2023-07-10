import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Scanner;

public class Main {

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {


        byte[] bytes2 = Files.readAllBytes(Paths.get("./cert/cert.key"));   //37 49 arası client
        PKCS8EncodedKeySpec ks2 = new PKCS8EncodedKeySpec(bytes2);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey pvt = kf.generatePrivate(ks2);


        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, pvt);
        try (FileInputStream in = new FileInputStream("file.txt");      // gonderıcegım kısım path olucak
             FileOutputStream out = new FileOutputStream("enc.txt")) {  //path verebilirim
            processFile(cipher, in, out);
        }

        byte[] bytes = Files.readAllBytes(Paths.get("./cert/cert.pub"));    // 51 61 arası server
        X509EncodedKeySpec ks = new X509EncodedKeySpec(bytes);
        kf = KeyFactory.getInstance("RSA");
        PublicKey pub = kf.generatePublic(ks);

        Cipher cipher2 = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher2.init(Cipher.DECRYPT_MODE, pub);
        try (FileInputStream in = new FileInputStream("enc.txt");
             FileOutputStream out = new FileOutputStream("dec.txt")) {
            processFile(cipher2, in, out);
        }

    }

    static private void processFile(Cipher ci,InputStream in,OutputStream out)
            throws javax.crypto.IllegalBlockSizeException,
            javax.crypto.BadPaddingException,
            java.io.IOException
    {
        byte[] ibuf = new byte[1024];
        int len;
        while ((len = in.read(ibuf)) != -1) {
            byte[] obuf = ci.update(ibuf, 0, len);
            if ( obuf != null ) out.write(obuf);
        }
        byte[] obuf = ci.doFinal();
        if ( obuf != null ) out.write(obuf);
    }

}




