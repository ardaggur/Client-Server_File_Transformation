import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

public class Client {

    static private byte[] processFile(Cipher ci, ByteArrayInputStream in)
            throws javax.crypto.IllegalBlockSizeException,
            javax.crypto.BadPaddingException,
            java.io.IOException
    {
        byte[] ibuf = new byte[1024];
        int len;
        byte[] obuf;
        while((len = in.read(ibuf)) != -1) {
            ci.update(ibuf, 0, len);
        }
        obuf = ci.doFinal();
        return obuf;
    }


    public static void main(String[] agrs)
    {
        final File[] fileToSend = new File[1];

        JFrame jFrame = new JFrame("Client");
        jFrame.setSize(450,450);
        jFrame.setLayout(new BoxLayout(jFrame.getContentPane(), BoxLayout.Y_AXIS));
        jFrame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

        JLabel jlTitle = new JLabel("File Sender");
        jlTitle.setFont(new Font("Arial",Font.BOLD, 25));
        jlTitle.setBorder(new EmptyBorder(20,0,10,0));
        jlTitle.setAlignmentX(Component.CENTER_ALIGNMENT);

        JLabel jlFileName = new JLabel("Choose the file you want to send.");
        jlFileName.setFont(new Font("Arial",Font.BOLD, 20));
        jlFileName.setBorder(new EmptyBorder(50,0,0,0));
        jlFileName.setAlignmentX(Component.CENTER_ALIGNMENT);

        JPanel jpButton = new JPanel();
        jpButton.setBorder(new EmptyBorder(75,0,10,0));

        JButton jbSendFile = new JButton("Send File");
        jbSendFile.setPreferredSize(new Dimension(150,75));
        jbSendFile.setFont(new Font("Arial",Font.BOLD, 20));

        JButton jbChooseFile = new JButton("Choose File");
        jbChooseFile.setPreferredSize(new Dimension(150,75));
        jbChooseFile.setFont(new Font("Arial",Font.BOLD,20));

        jpButton.add(jbSendFile);
        jpButton.add(jbChooseFile);

        jbChooseFile.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                JFileChooser jFileChooser = new JFileChooser();
                jFileChooser.setDialogTitle("Choose the file you want to send");

                if(jFileChooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION)
                {
                    fileToSend[0] = jFileChooser.getSelectedFile();
                    jlFileName.setText("The file you want to send is: " + fileToSend[0].getName());
                }
            }
        });


        jbSendFile.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try
                {
                if(fileToSend[0] == null)
                {
                    jlFileName.setText("Please choose a file first ");
                }
                else {
                    byte[] bytes2 = Files.readAllBytes(Paths.get("./cert/cert.key"));   //37 49 arası client
                    PKCS8EncodedKeySpec ks2 = new PKCS8EncodedKeySpec(bytes2);
                    KeyFactory kf = KeyFactory.getInstance("RSA");
                    PrivateKey pvt = kf.generatePrivate(ks2);


                    Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                    cipher.init(Cipher.ENCRYPT_MODE, pvt);

                    byte[] fileContentBytes = processFile(cipher,new ByteArrayInputStream(Files.readAllBytes(Path.of(fileToSend[0].getAbsolutePath()))));

                    FileInputStream fileInputStream = new FileInputStream(fileToSend[0].getAbsolutePath());
                    Socket socket = new Socket("localhost", 1234);

                    DataOutputStream dataOutputStream = new DataOutputStream(socket.getOutputStream());

                    String fileName = fileToSend[0].getName();
                    byte[] fileNameBytes = fileName.getBytes();


                    dataOutputStream.writeInt(fileNameBytes.length);
                    dataOutputStream.write(fileNameBytes);

                    dataOutputStream.writeInt(fileContentBytes.length);
                    dataOutputStream.write(fileContentBytes);
                }
                }
                catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException error)
                {
                    error.printStackTrace();
                }
            }
        });

        jFrame.add(jlTitle);
        jFrame.add(jlFileName);
        jFrame.add(jpButton);
        jFrame.setVisible(true);


    }

}
