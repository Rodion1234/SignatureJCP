/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package CertificatesJ;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

/**
 *
 * @author rodion
 */
public class GettingKeys {

    public PublicKey getPublicKeyFromCertificate(String typeKeyStore, String nameKeyStore, String password, String nameCetr) throws KeyStoreException, IOException, FileNotFoundException, NoSuchAlgorithmException, CertificateException {

        KeyStore keyStore = new GettingKeyStores().instenceCertStore(typeKeyStore, nameKeyStore, password);
        Certificate certificate = keyStore.getCertificate(nameCetr);

        PublicKey publicKey = certificate.getPublicKey();
        return publicKey;
    }

    public PrivateKey getPrivateKeyFromHDImageStore(String typeKeyStore, String nameKey, String password) throws UnrecoverableKeyException, IOException, KeyStoreException, FileNotFoundException, NoSuchAlgorithmException, CertificateException {

        KeyStore keyStore1 = new GettingKeyStores().instenceHDImageStore(typeKeyStore);
        PrivateKey privateKey = (PrivateKey) keyStore1.getKey(nameKey, password.toCharArray());

        return privateKey;
    }
}
