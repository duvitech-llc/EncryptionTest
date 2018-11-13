package com.duvitech.encryptiontest;

import android.os.Environment;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.Button;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class MainActivity extends AppCompatActivity {

    private static String TAG = "MainActivity";
    public static final int KEY_SIZE = 1024;

    private static RSAPrivateKey priv;
    private static RSAPublicKey pub;

    private static String prvKeyString = "MIICXAIBAAKBgQDxj8SY2s9wAqaxoJ8wgZ6/+VndSxxkunHyYe6eIH4g+S+cTZVD" +
            "tifVeJiLBFrwXa4npRDoarhttLTMd8f4vRV5MpNOTp2kMYQZAqyXphLvLPWt9a3+" +
            "2NG0qSlq/SS8n9tFVFBJ9QHDrsppR5JsQFAoiZPCj2Q4eoBkQ763y3S57wIDAQAB" +
            "AoGAKw0UXKmijrPqQX3+4QY45L3r5iScytbvt+L8Q/JGiFngwlqRX5/3OXRku2Hr" +
            "Uyte/nHMsZ9TfznVfxtZ6FrKmJZgjMgkmt0X6XLPtoEkwnyWRF3DxUTLISRh90SM" +
            "HxR6ex5TStFS3K8Hwl4zn2ejgycF9Kgbnda6GjsI0vDEdQECQQD+yGX2ZcRnClDe" +
            "GYSk8/2y1sqssIRYPvicPbeHxMG5oyJSSh+A0y7Cr2uljst08xYshk/FiKONZ92d" +
            "XJr/FWSlAkEA8rczM12uqGYABHYdJ8zNrXq/E4H4j6TXEFwD+Sh+CtTm2QdeQQhm" +
            "lyRtuK1pfXKT4tCGHl3n/LPbwPfmO2CcAwJBAKKxYvKxT3YgzzzT/LC8oR8nK2qU" +
            "mR4kr+pNOrn2uWIKOutjK7S+pdhp3gptIZx/cYRjC+NuekncrlZDATKr/YUCQDDb" +
            "P6svSGENZyN+ww+n4h7xflTm7Km9fK0GWKZmyDhV8sHtAcQFdOEnrA5ombtuvOYD" +
            "I3wpWvE7IxkMzYNWRxECQBRwhT/p/VCjDz1g1Xb/YVQiCXOyNMCmfwH6zH6sBud9" +
            "dwr2BkHCCamgAnE9F7kDyMSMMk9PdZbo1hdRmNHBsH8=";


    public byte[] RSAEncrypt(final String plain) throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, pub);
        byte[] encryptedBytes = cipher.doFinal(plain.getBytes());
        Log.d(TAG, "Encrypted: " + Base64.encodeToString(encryptedBytes, Base64.DEFAULT));
        return encryptedBytes;
    }

    public String RSADecrypt(final byte[] encryptedBytes, PrivateKey key) throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        Cipher cipher1 = Cipher.getInstance("RSA/NONE/OAEPPadding");
        cipher1.init(Cipher.DECRYPT_MODE, key);
        byte[] decryptedBytes = cipher1.doFinal(encryptedBytes);
        String decrypted = new String(decryptedBytes);
        Log.d(TAG, "Decrypted: " + decrypted);
        return decrypted;
    }


    private static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
        generator.initialize(KEY_SIZE);

        KeyPair keyPair = generator.generateKeyPair();
        Log.d(TAG,"RSA key pair generated.");
        return keyPair;
    }

    private static void writePemFile(Key key, String description, String filename)
            throws FileNotFoundException, IOException {
        PemFile pemFile = new PemFile(key, description);
        pemFile.write(filename);

        Log.d(TAG,String.format("%s successfully writen in file %s.", description, filename));
    }

    private static void writePemToLog(Key key, String description)
            throws IOException {
        PemFile pemFile = new PemFile(key, description);
        String sPem =  pemFile.getString();

        Log.d(TAG,String.format("%s:\n %s.", description, sPem));
    }

    private static void writePrivatePemToLog(Key key, String description)
            throws IOException {
        PemFile pemFile = new PemFile(key, description);
        byte[] content = pemFile.getPemObject().getContent();
        PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(content);

        String sPem =  new String(privKeySpec.getEncoded());

        Log.d(TAG,String.format("%s:\n %s.", description, sPem));
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        Security.addProvider(new BouncyCastleProvider());
        Log.d(TAG, "BouncyCastle provider added.");


        try {

            KeyPair keyPair = generateRSAKeyPair();
            priv = (RSAPrivateKey) keyPair.getPrivate();
            pub = (RSAPublicKey) keyPair.getPublic();


            byte[] decoded = Base64.decode(prvKeyString, Base64.DEFAULT);
            PKCS8EncodedKeySpec spec =
                    new PKCS8EncodedKeySpec(decoded);
            KeyFactory kf = KeyFactory.getInstance("RSA", "BC");
            PrivateKey generatePrivate = kf.generatePrivate(spec);
            RSADecrypt(Base64.decode("BRl2nfZysbi4aLl+4Ei1eVkWWyfN64gQWddeEU3pUldjHG1oNBh+XE2oHwfhBIYKN+DlF/e92pxpK30CPWkcGP7IYQe2Ggr8cNKbglpacWR+M4PX+8E+W8SFxIDkPLjhjmjAZpnxDD7KQp3GxtDbowo1Q97LsdyMnaajqUTUV+E=" , Base64.DEFAULT), generatePrivate);

            //writePemFile(priv, "Private KEYFILE", new File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS), "private.pem").getPath());

            //writePemToLog(pub,"Public Key");
            //writePrivatePemToLog(priv,"Private Key");

            Log.d(TAG, "PublicKey: \n" + Base64.encodeToString(pub.getEncoded(), Base64.DEFAULT));
            Log.d(TAG, "PrivateKey: \n" + Base64.encodeToString(priv.getEncoded(), Base64.DEFAULT));

        }catch (Exception ex){
            Log.e(TAG, "Error: " + ex.getMessage());
        }

        Button btnTest = findViewById(R.id.btnTest);
        btnTest.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                try {
                    byte[] arr = RSAEncrypt("Hello world!");
                    // String s = RSADecrypt(arr);
                }catch(Exception ex){
                    Log.e(TAG, ex.getMessage());
                }

            }
        });
    }
}
