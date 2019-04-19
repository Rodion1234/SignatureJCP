/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package jcpsignature;

import CertificatesJ.CreateKeyStores;
import CertificatesJ.GettingKeyStores;
import CertificatesJ.GettingKeys;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import ru.CryptoPro.JCP.JCP;
import java.io.FileNotFoundException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

/**
 *
 * @author rodiong
 */
public class JCPSignature {

   SecureRandom rnd;
//    KeyPair pair;
//    KeyStore keyStore;

    public JCPSignature() throws NoSuchAlgorithmException, NoSuchProviderException, KeyStoreException {
//        KeyPairGenerator kpg = KeyPairGenerator.getInstance(JCP.GOST_EL_DEGREE_NAME, JCP.PROVIDER_NAME);
//        this.pair = kpg.generateKeyPair();
//
       this.rnd = SecureRandom.getInstance(JCP.CP_RANDOM, JCP.PROVIDER_NAME);
//        this.keyStore = KeyStore.getInstance("CertStore", JCP.PROVIDER_NAME);

    }

    //подпись документа
    public byte[] dataSign(byte[] date) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException, UnrecoverableKeyException, IOException, KeyStoreException, FileNotFoundException, CertificateException {
        Signature signature = Signature.getInstance(JCP.GOST_EL_SIGN_NAME, JCP.PROVIDER_NAME);

        PrivateKey privateKey = new GettingKeys().getPrivateKeyFromHDImageStore("HDImageStore", "keynewCert_2001", "password");
        signature.initSign(privateKey,rnd);

        byte[] data1 = getMessageDigest(date);

        printData(data1);

        signature.update(data1);

        byte[] signData = signature.sign();

        printData(signData);

        return signData;
    }

    //проверка ЭЦП
    public boolean dataSignVer(byte[] date, byte[] signDate) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException, KeyStoreException, IOException, FileNotFoundException, CertificateException {

        Signature signature = Signature.getInstance(JCP.GOST_EL_SIGN_NAME, JCP.PROVIDER_NAME);


        PublicKey publicKey = new GettingKeys().getPublicKeyFromCertificate("CertStore", "new_2001", "password", "newcert_2001");
        signature.initVerify(publicKey);

        byte[] data1 = getMessageDigest(date);

        printData(data1);

        signature.update(data1);

        boolean verified = signature.verify(signDate);

        System.out.println(verified);

        return verified;
    }

    //вычисление хеша
    private byte[] getMessageDigest(byte[] date) throws NoSuchAlgorithmException, NoSuchProviderException {
        MessageDigest digest = MessageDigest.getInstance(JCP.GOST_DIGEST_NAME, JCP.PROVIDER_NAME);
        byte[] data1 = date;
        return digest.digest(data1);
    }

    //вывод хешей и данных для наглядности.(удалить: нужно для примера)
    public void printData(byte[] data) {
        for (int i = 0; i < data.length; i++) {
            System.out.print(data[i]);
        }
        System.out.println("\n");
    }

    //открытие файла с HD (удалить: нужно для примера)
    public byte[] fileOpen(String url) throws IOException {
        byte[] array = Files.readAllBytes(Paths.get(url));

        return array;
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, IOException, InvalidKeyException, SignatureException, KeyStoreException, Exception {
//       JCPSignature jcps = new JCPSignature();
//
//        byte[] data = jcps.fileOpen("test.xml");
//
//        byte[] signData = jcps.dataSign(data);
//        boolean flag = jcps.dataSignVer(data, signData);
        // jcps.workWithCertificates();
          //System.out.println(System.getProperty(JCP.HD_STORE_NAME));

// cj = new CertificatesJ.CertificatesJ();
//        CertificatesJ.CertificatesJ.writeCertSample(JCP.GOST_EL_DEGREE_NAME, JCP.GOST_EL_SIGN_NAME, "newCert_2001",
//                "C:\\Users\\rodion\\Documents" + File.separator + "new_2001.keystore", "CN=" + "newCert_2001" + ", O=CryptoPro, C=RU");
//
//        CertificatesJ.CertificatesJ.readCertSample("C:\\Users\\rodion\\Documents" + File.separator + "new_2001.keystore",
//                "newCert_2001", "C:\\Users\\rodion\\Documents" + File.separator + "newCertificate_2001.cer");
      CreateKeyStores cks = new CreateKeyStores();
      
        cks.createStoresKey("newCert_2001",
               "C:\\Users\\rodion\\Documents" + File.separator + "new_2001.keystore", "CN=" + "newCert_2001" + ", O=CryptoPro, C=RU","password");
        
//KeyStore keyStore = KeyStore.getInstance("CertStore");
//       keyStore.load(new FileInputStream(new File("C:\\Users\\rodion\\Documents\\new_2001.keystore")), "password".toCharArray());
//       Certificate certificate = keyStore.getCertificate("newcert_2001");
        //keyStore.
//        KeyStore keyStore = new GettingKeyStores().instenceCertStore("CertStore", "new_2001", "password");
//        Certificate certificate = keyStore.getCertificate("newcert_2001");
//
//        KeyStore keyStore1 = new GettingKeyStores().instenceHDImageStore("HDImageStore");
//        //Certificate certificate1 = keyStore.getCertificate("newcert_2001");
//        PrivateKey key = (PrivateKey) keyStore1.getKey("keynewCert_2001", "password".toCharArray());
//        System.out.println(key.toString());

//        cks.readCertSample("C:\\Users\\rodion\\Documents" + File.separator + "new_2001.keystore",
//                "newCert_2001", "C:\\Users\\rodion\\Documents" + File.separator + "newCertificate_2001.cer");
    }

}
