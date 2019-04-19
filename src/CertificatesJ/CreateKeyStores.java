/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package CertificatesJ;

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import ru.CryptoPro.JCP.JCP;
import ru.CryptoPro.JCPRequest.GostCertificateRequest;

import com.objsys.asn1j.runtime.Asn1Boolean;
import com.objsys.asn1j.runtime.Asn1ObjectIdentifier;
import com.objsys.asn1j.runtime.Asn1OctetString;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import ru.CryptoPro.JCP.ASN.PKIX1Explicit88.Extension;
import ru.CryptoPro.JCP.JCP;
import ru.CryptoPro.JCPRequest.GostCertificateRequest;

/**
 *
 * @author rodion
 */
public class CreateKeyStores {


    private static final String HTTP_ADDRESS = "http://www.cryptopro.ru/certsrv/";
    //провайдер
    private static final String PROVIDER_NAME = JCP.PROVIDER_NAME;

    //алгоритм для генерации ключевой пары KeyPairGenerator -> KeyPair
    private static final String KEY_ALG = JCP.GOST_EL_DEGREE_NAME;

    //алгоритм Алгоритм подписи сертификата
    private static final String SIGN_ALG = JCP.GOST_EL_SIGN_NAME;


// * @param alias Алиас ключа для сохранения.
// * @param storePath Путь к хранилищу сертификатов.
// * @param dnName DN-имя сертификата.
// * @param passw паролль на хранилища.
// * @throws Exception 
    public void createStoresKey(
            String alias, String storePath, String dnName, String passw) throws NoSuchAlgorithmException, NoSuchProviderException, Exception {

        //генератор ключевой пары, по алгоритму 
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(KEY_ALG, PROVIDER_NAME);
        KeyPair keyPair = kpg.generateKeyPair();

        // отправка запроса центру сертификации и получение от центра
        // сертификата в DER-кодировке
        byte[] encoded = createRequestAndGetCert(keyPair, SIGN_ALG, PROVIDER_NAME, dnName);

        // инициализация генератора X509-сертификатов
        CertificateFactory cf = CertificateFactory.getInstance("X509");
        // генерирование X509-сертификата из закодированного представления сертификата
        Certificate cert
                = cf.generateCertificate(new ByteArrayInputStream(encoded));
        
        //создание хранилища контейнеров HDImageStore
        createHDImageStore(cert, alias, keyPair, passw);
        //создание хранилища сертификатов createCertStore
        createCertStore(alias, cert, storePath, passw);
        
        //проверка на совпадение
        PublicKey publicKey = new GettingKeys().getPublicKeyFromCertificate("CertStore", "new_2001", "password", "newcert_2001");
        PrivateKey privateKey = new GettingKeys().getPrivateKeyFromHDImageStore("HDImageStore", "keynewCert_2001", "password");
        
        if (publicKey.equals(keyPair.getPublic())) System.out.println("publicKey : true");
        else System.out.println("publicKey : false");
       // if(privateKey == null) System.out.println("asdf");
       
        if (privateKey.equals(keyPair.getPrivate())) System.out.println("privateKey : true");
        else System.out.println("privateKey : false");
    }

    //создание хранилища контейнеров HDImageStore
    private void createHDImageStore(Certificate cert, String alias, KeyPair keyPair, String passw) throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException {
        Certificate[] chainCert = new Certificate[1];
        chainCert[0] = cert;

        //* запись закрытого ключа и цепочки сертификатов в хранилище
        // определение типа ключевого носителя, на который будет осуществлена запись ключа
        final KeyStore hdImageStore = KeyStore.getInstance(JCP.HD_STORE_NAME);
        // загрузка содержимого носителя (предполагается, что не существует
        // хранилища доверенных сертификатов)
        hdImageStore.load(null, null);
        // запись на носитель закрытого ключа и цепочки
        hdImageStore.setKeyEntry("key" + alias, keyPair.getPrivate(), passw.toCharArray(), chainCert);
        File file = new File("C:\\Users\\rodion\\Documents" + File.separator + "_new_2001.keystore");
        // сохранение содержимого хранилища
        hdImageStore.store(new FileOutputStream(file), passw.toCharArray());
    }

    //создание хранилища сертификатов createCertStore
    private void createCertStore(String alias, Certificate cert, String storePath, String passw) throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException {
        /* Запись полученного от центра сертификата*/
        // инициализация хранилища доверенных сертификатов именем ключевого носителя
        // (жесткий диск)
        KeyStore keyStore = KeyStore.getInstance(JCP.CERT_STORE_NAME);
        System.out.println(JCP.HD_STORE_NAME);
        // загрузка содержимого хранилища (предполагается, что инициализация
        // хранилища именем CertStoreName производится впервые, т.е. хранилища
        // с таким именем пока не существует)
        keyStore.load(null, null);

        // запись сертификата в хранилище доверенных сертификатов
        // (предполагается, что на носителе с именем CertStoreName не существует
        // ключа с тем же именем alias)
        keyStore.setCertificateEntry(alias, cert);

        // определение пути к файлу для сохранения в него содержимого хранилища
        File file = new File(storePath);
        // сохранение содержимого хранилища в файл
        keyStore.store(new FileOutputStream(file), passw.toCharArray());
    }

    public static byte[] createRequestAndGetCert(KeyPair pair, String signAlgorithm,
            String signatureProvider, String dnName) throws Exception {

        // формирование запроса
        GostCertificateRequest request = createRequest(pair,
                signAlgorithm, signatureProvider, dnName);

        // отправка запроса центру сертификации и получение от центра
        // сертификата в DER-кодировке
        return request.getEncodedCert(HTTP_ADDRESS);
    }

    public static GostCertificateRequest createRequest(KeyPair pair, String signAlgorithm,
            String signatureProvider, String dnName) throws Exception {
        /* Генерирование запроса на сертификат в соответствии с открытым ключом*/
        // создание генератора запроса на сертификат
        GostCertificateRequest request = new GostCertificateRequest(signatureProvider);
        // инициализация генератора
        // @deprecated с версии 1.0.48
        // вместо init() лучше использовать setKeyUsage() и addExtKeyUsage()
        // request.init(KEY_ALG);

        /*
    Установить keyUsage способ использования ключа можно функцией
    setKeyUsage. По умолчанию для ключа подписи, т.е. для указанного в первом
    параметре функции init() алгоритма "GOST3410EL" используется комбинация
    DIGITAL_SIGNATURE | NON_REPUDIATION. Для ключа шифрования, т.е. для
    алгоритма "GOST3410DHEL" добавляется KEY_ENCIPHERMENT | KEY_AGREEMENT.
         */
        final String keyAlgorithm = pair.getPrivate().getAlgorithm();
        if (keyAlgorithm.equalsIgnoreCase(JCP.GOST_EL_DEGREE_NAME)
                || keyAlgorithm.equalsIgnoreCase(JCP.GOST_EL_2012_256_NAME)
                || keyAlgorithm.equalsIgnoreCase(JCP.GOST_EL_2012_512_NAME)) {
            int keyUsage = GostCertificateRequest.DIGITAL_SIGNATURE
                    | GostCertificateRequest.NON_REPUDIATION;
            request.setKeyUsage(keyUsage);
        } // if
        else {
            int keyUsage = GostCertificateRequest.DIGITAL_SIGNATURE
                    | GostCertificateRequest.NON_REPUDIATION
                    | GostCertificateRequest.KEY_ENCIPHERMENT
                    | GostCertificateRequest.KEY_AGREEMENT;
            request.setKeyUsage(keyUsage);
        } // else

        /*
    Добавить ExtendedKeyUsage можно так. По умолчанию для ключа подписи,
    т.е. для алгоритма "GOST3410EL" список будет пустым. Для ключа
    шифрования, т.е. для алгоритма "GOST3410DHEL" добавляется OID
    INTS_PKIX_CLIENT_AUTH "1.3.6.1.5.5.7.3.2", а при установленном в true
    втором параметре функции init() еще добавляется INTS_PKIX_SERVER_AUTH
    "1.3.6.1.5.5.7.3.1"
         */
        request.addExtKeyUsage(GostCertificateRequest.INTS_PKIX_EMAIL_PROTECTION);
        /**
         * ExtendedKeyUsage можно указывать строкой "1.3.6.1.5.5.7.3.3", или
         * можно массивом int[]{1, 3, 6, 1, 5, 5, 7, 3, 4} или объектом типа
         * ru.CryptoPro.JCP.params.OID
         */
        request.addExtKeyUsage("1.3.6.1.5.5.7.3.3");
        /**
         * пример добавления в запрос собственного расширения Basic Constraints
         */

        Extension ext = new Extension();
        int[] extOid = {2, 5, 29, 19};
        ext.extnID = new Asn1ObjectIdentifier(extOid);
        ext.critical = new Asn1Boolean(true);
        byte[] extValue = {48, 6, 1, 1, -1, 2, 1, 5};
        ext.extnValue = new Asn1OctetString(extValue);
        request.addExtension(ext);

        /*
    //1

    Extension basic;
    byte[] enc;
    Asn1BerEncodeBuffer buf = new Asn1BerEncodeBuffer();

    basic = new Extension();
    basic.extnID = new Asn1ObjectIdentifier(ALL_CertificateExtensionsValues.id_ce_basicConstraints);

    basic.critical = new Asn1Boolean(false);
    BasicConstraintsSyntax basicVal = new BasicConstraintsSyntax();

    basicVal.encode(buf);
    enc = buf.getMsgCopy();

    basic.extnValue = new Asn1OctetString(enc);
    request.addExtension(basic);

    //2

    Extension unknown;
    buf = new Asn1BerEncodeBuffer();

    unknown = new Extension();
    unknown.extnID = new Asn1ObjectIdentifier(new int[] {1,2,643,3,123,3,1});

    unknown.critical = new Asn1Boolean(false);
    Asn1UTF8String unknownValue = new Asn1UTF8String("V2QL0020sИванов");

    unknownValue.encode(buf);
    enc = buf.getMsgCopy();

    unknown.extnValue = new Asn1OctetString(enc);
    request.addExtension(unknown);

    //3

    Extension oidExt;
    buf = new Asn1BerEncodeBuffer();

    oidExt = new Extension();
    oidExt.extnID = new Asn1ObjectIdentifier(new int[] {1,2,643,3,123,3,4});

    oidExt.critical = new Asn1Boolean(false);
    Asn1ObjectIdentifier oid = new Asn1ObjectIdentifier(new int[] {1,2,643,3,123,5,4});

    oid.encode(buf);
    enc = buf.getMsgCopy();

    oidExt.extnValue = new Asn1OctetString(enc);
    request.addExtension(oidExt);

    //4

    Extension extAlt = new Extension();
    int[] extOidAlt = {2, 5, 29, 17};
    extAlt.extnID = new Asn1ObjectIdentifier(extOidAlt);
    extAlt.critical = new Asn1Boolean(false);

    InetAddress address = InetAddress.getByName("172.24.8.31");
    byte [] address_ip = address.getAddress();

    GeneralName name = new GeneralName();
    name.set_iPAddress(new Asn1OctetString(address_ip)); // ip v4 - 4 байта

    GeneralNames names = new GeneralNames(new GeneralName[] {name});
    buf = new Asn1BerEncodeBuffer();

    names.encode(buf);
    enc = buf.getMsgCopy();

    extAlt.extnValue = new Asn1OctetString(enc);
    request.addExtension(extAlt);
         */
        // определение параметров и значения открытого ключа
        request.setPublicKeyInfo(pair.getPublic());
        // определение имени субъекта для создания запроса
        request.setSubjectInfo(dnName);
        // подпись сертификата на закрытом ключе и кодирование запроса
        request.encodeAndSign(pair.getPrivate(), signAlgorithm);

        return request;
    }
}
