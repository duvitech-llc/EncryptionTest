package com.duvitech.encryptiontest;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.Button;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class MainActivity extends AppCompatActivity {

    private String TAG = "MainActivity";
    private static KeyPair kp;

    public byte[] RSAEncrypt(final String plain) throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        PublicKey publicKey = kp.getPublic();

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(plain.getBytes());
        Log.d(TAG, "Encrypted: " + Base64.encodeToString(encryptedBytes, Base64.DEFAULT));
        return encryptedBytes;
    }

    public String RSADecrypt(final byte[] encryptedBytes) throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        PrivateKey privateKey = kp.getPrivate();

        Cipher cipher1 = Cipher.getInstance("RSA");
        cipher1.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher1.doFinal(encryptedBytes);
        String decrypted = new String(decryptedBytes);
        Log.d(TAG, "Decrypted: " + decrypted);
        return decrypted;
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(1024);
            kp = kpg.genKeyPair();
            PublicKey publicKey = kp.getPublic();
            PrivateKey privateKey = kp.getPrivate();

            Log.d(TAG, "PublicKey: \n" + Base64.encodeToString(publicKey.getEncoded(), Base64.DEFAULT));
            Log.d(TAG, "PrivateKey: \n" + Base64.encodeToString(privateKey.getEncoded(), Base64.DEFAULT));

        }catch (Exception ex){
            Log.e(TAG, "Error: " + ex.getMessage());
        }

        Button btnTest = findViewById(R.id.btnTest);
        btnTest.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                try {
                    byte[] arr = RSAEncrypt("Hello world!");
                    String s = RSADecrypt(arr);
                }catch(Exception ex){
                    Log.e(TAG, ex.getMessage());
                }

            }
        });
    }
}
