import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;


import java.security.MessageDigest;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JTextField;

public abstract class Utility {

    Editor editor;
    public File dir;
    public String username, password;

    public Utility(Editor e) {
        editor = e;
        //file = null;
        //set_username_password();
        //new_file();
    }

    public abstract void create(String file_name, String user_name, String password) throws Exception;

    public abstract String findUser(String file_name) throws Exception;

    public abstract int length(String file_name, String password) throws Exception;

    public abstract byte[] read(String file_name, int starting_position, int len, String password) throws Exception;

    public abstract void write(String file_name, int starting_position, byte[] content, String password) throws Exception;

    public abstract boolean check_integrity(String file_name, String password) throws Exception;

    public abstract void cut(String file_name, int len, String password) throws Exception;

    public void set_username_password() {
        JPanel loginPanel = new JPanel();
        loginPanel.setLayout(new java.awt.GridLayout(2, 2));

        JLabel username_tag = new JLabel();
        JTextField username_field = new JTextField();

        username_tag.setText("username");
        loginPanel.add(username_tag);
        loginPanel.add(username_field);

        JLabel password_tag = new JLabel();
        JPasswordField password_field = new JPasswordField();

        password_tag.setText("password");
        loginPanel.add(password_tag);
        loginPanel.add(password_field);

        int okCxl = JOptionPane.showConfirmDialog(null, loginPanel, "Enter Password", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);

        if (okCxl == JOptionPane.OK_OPTION) {
            this.password = new String(password_field.getPassword());
            this.username = new String(username_field.getText());

        }
    }

    public byte[] read_from_file(File file) throws Exception {
        DataInputStream in = new DataInputStream(
                new BufferedInputStream(
                new FileInputStream(file)));

        int size = in.available();

        byte[] toR = new byte[size];

        in.read(toR);

        in.close();
        return toR;

    }

    public void save_to_file(byte[] s, File file) throws Exception {
        if (file == null) {
            return;
        }
        DataOutputStream out = new DataOutputStream(new FileOutputStream(file));
        out.write(s);
        out.close();

    }

    public File set_dir() {
        JFileChooser fileChooser  = new JFileChooser();
        fileChooser.setFileSelectionMode(fileChooser.DIRECTORIES_ONLY);
        if (fileChooser.showOpenDialog(editor) == JFileChooser.APPROVE_OPTION) {
            return fileChooser.getSelectedFile();
        } else {

            return null;
        }
    }

    public static byte[] encript_AES(byte[] plainText, byte[] key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(plainText);
    }

    public static byte[] decript_AES(byte[] cypherText, byte[] key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        return cipher.doFinal(cypherText);
    }

    public static byte[] hash_SHA256(byte[] message) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash1 = digest.digest(message);
        return hash1;
    }

    public static byte[] hash_SHA384(byte[] message) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-384");
        byte[] hash1 = digest.digest(message);
        return hash1;
    }

    public static byte[] hash_SHA512(byte[] message) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-512");
        byte[] hash1 = digest.digest(message);
        return hash1;
    }

    public static byte[] secureRandomNumber(int randomNumberLength) {
        byte[] randomNumber = new byte[randomNumberLength];
        SecureRandom random = new SecureRandom();
        random.nextBytes(randomNumber);
        return randomNumber;
    };

    public static String byteArray2String(byte[] array) {
        String ret = "";
        for (int i = 0; i < array.length; i++) {
            if (array[i] < 0)
            {
                javax.swing.JOptionPane.showMessageDialog(null, "Error: cannot convert negative number " + array[i] + " into character");
                //return "";
            }
            ret += (char) array[i];
        }

        return ret;
    }
}
