/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package CertificatesJ;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

/**
 *
 * @author rodion
 */
public class GettingKeyStores {
    
    private static final String STORE_URL = "C:\\Users\\rodion\\Documents\\";
    private static final String POSTFIX = ".keystore";
    
    public KeyStore instenceCertStore(String typeKeyStore, String nameKeyStore, String password) throws KeyStoreException, FileNotFoundException, IOException, NoSuchAlgorithmException, CertificateException{
       KeyStore keyStore = KeyStore.getInstance(typeKeyStore);
       keyStore.load(new FileInputStream(new File(STORE_URL+nameKeyStore+POSTFIX)), password.toCharArray());
       
       return keyStore;
    }
    
    public KeyStore instenceHDImageStore(String typeKeyStore) throws KeyStoreException, FileNotFoundException, IOException, NoSuchAlgorithmException, CertificateException{
       KeyStore keyStore = KeyStore.getInstance(typeKeyStore);
       keyStore.load(null, null);
       
       return keyStore;
    }
    
}
