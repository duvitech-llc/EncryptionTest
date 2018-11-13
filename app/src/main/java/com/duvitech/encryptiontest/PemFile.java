package com.duvitech.encryptiontest;

import android.util.Log;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.security.Key;

public class PemFile {

    private PemObject pemObject;

    public PemFile (Key key, String description) {

        System.out.println(key.getAlgorithm());

        this.pemObject = new PemObject(description, key.getEncoded());

    }

    public void write(String filename) throws FileNotFoundException, IOException {
        PemWriter pemWriter = new PemWriter(new OutputStreamWriter(new FileOutputStream(filename)));
        try {
            pemWriter.writeObject(this.pemObject);
            Log.d("WROTE", filename);
        }catch (Exception ex){
            Log.e("FAILED WRITE", ex.getMessage());
        } finally {
            pemWriter.close();
        }
    }

    public String getString() throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        String retString = null;
        PemWriter pemWriter = new PemWriter(new OutputStreamWriter(baos));
        try {
            pemWriter.writeObject(this.pemObject);
        } finally {
            pemWriter.close();
            retString = new String(baos.toByteArray());
        }

        return  retString;
    }

    public PemObject getPemObject() {
        return pemObject;
    }
}