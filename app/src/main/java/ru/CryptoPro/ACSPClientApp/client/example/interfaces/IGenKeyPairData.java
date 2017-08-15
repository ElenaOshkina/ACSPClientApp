/**
 * Copyright 2004-2013 Crypto-Pro. All rights reserved.
 * Программный код, содержащийся в этом файле, предназначен
 * для целей обучения. Может быть скопирован или модифицирован
 * при условии сохранения абзацев с указанием авторства и прав.
 *
 * Данный код не может быть непосредственно использован
 * для защиты информации. Компания Крипто-Про не несет никакой
 * ответственности за функционирование этого кода.
 */
package ru.CryptoPro.ACSPClientApp.client.example.interfaces;

import android.content.Context;

import com.objsys.asn1j.runtime.Asn1DerEncodeBuffer;
import com.objsys.asn1j.runtime.Asn1Integer;
import com.objsys.asn1j.runtime.Asn1ObjectIdentifier;
import com.objsys.asn1j.runtime.Asn1OctetString;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import ru.CryptoPro.ACSPClientApp.client.LogCallback;
import ru.CryptoPro.ACSPClientApp.util.AlgorithmSelector;
import ru.CryptoPro.ACSPClientApp.util.KeyStoreType;

import ru.CryptoPro.JCP.ASN.CA_Definitions.CertificateTemplate;
import ru.CryptoPro.JCP.ASN.PKIX1Explicit88.Extension;

import ru.CryptoPro.JCP.JCP;
import ru.CryptoPro.JCP.params.AlgIdSpec;
import ru.CryptoPro.JCP.params.OID;

import ru.CryptoPro.JCP.tools.Encoder;
import ru.CryptoPro.JCPRequest.GostCertificateRequest;
import ru.CryptoPro.JCPRequest.ca15.request.CA15GostCertificateRequest;
import ru.CryptoPro.JCPRequest.ca15.status.CA15RequestStatus;
import ru.CryptoPro.JCPRequest.ca15.status.CA15Status;
import ru.CryptoPro.JCPRequest.ca15.status.CA15UserRegisterInfoStatus;
import ru.CryptoPro.JCPRequest.ca15.status.CA15UserRegisterStatus;
import ru.CryptoPro.JCPRequest.ca15.user.CA15User;
import ru.CryptoPro.JCPRequest.ca20.decoder.CA20CertificateRecord;
import ru.CryptoPro.JCPRequest.ca20.request.CA20GostCertificateRequest;
import ru.CryptoPro.JCPRequest.ca20.status.CA20RequestStatus;
import ru.CryptoPro.JCPRequest.ca20.status.CA20Status;
import ru.CryptoPro.JCPRequest.ca20.status.CA20UserRegisterInfoStatus;
import ru.CryptoPro.JCPRequest.ca20.user.CA20AuxiliaryUserInfo;
import ru.CryptoPro.JCPRequest.ca20.user.CA20CertAuthUser;
import ru.CryptoPro.JCPRequest.ca20.user.CA20User;

import ru.CryptoPro.JCSP.JCSP;
import ru.CryptoPro.JCSP.params.NameAlgIdSpec;
import ru.CryptoPro.JCSP.support.BKSTrustStore;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * Служебный класс IGenKeyPairData предназначен для
 * реализации примеров генерации ключевых пар и
 * установки сертификата в контейнер.
 *
 * 28/06/2013
 *
 */
public abstract class IGenKeyPairData extends ISignData {

    /**
     * Адрес УЦ 1.4 для получения сертификата.
     */
    public static final String CA_14_ADDRESS = "http://www.cryptopro.ru/certsrv/";

    /**
     * Адрес УЦ 1.5 для получения сертификата.
     */
    public static final String CA_15_ADDRESS = "https://www.cryptopro.ru:5555/ui/";

    /**
     * Адрес УЦ 2.0 для получения сертификата.
     */
    // JCP-387: пока нет внещнего тестового УЦ 2.0 - заблокировано (адрес не указан)!
    public static final String CA_20_ADDRESS = "";

    /**
     * Дополнительная информация для регистрации
     * пользователя (УЦ 2.0).
     */
    public static final CA20AuxiliaryUserInfo USER_INFO = new CA20AuxiliaryUserInfo(
        "comment", "description", "test@cryptopro.ru", "key phrase");

    /**
     * Папка пользователя (УЦ 2.0).
     */
    public static final String USER_FOLDER = "MainRA";

    /**
     * Тип (версия) УЦ.
     */
    public static enum CAType {ca14, ca15, ca20};

    /**
     * Название контейнера.
     */
    protected String storeAlias = "defaultStore";

    /**
     * Путь к контейнеру с полным именем (fqcn).
     */
    protected String storeName = null;

    /**
     * Пароль на контейнер, который можно задать
     * программно при сохранении.
     */
    protected char[] defaultPassword = null;

    /**
     * Конструктор.
     * Тут же происходит создание генератора чисел.
     *
     * @param adapter Настройки примера.
     */
    protected IGenKeyPairData(ContainerAdapter adapter) {

        super(adapter, false);

        storeAlias = adapter.getClientAlias();
        storeName = "\\\\.\\" + KeyStoreType.currentType() + "\\" + storeAlias;

    }

    /**
     * Получение алиаса ключа.
     *
     * @return алиас ключа.
     */
    public String getStoreAlias() {
        return storeAlias;
    }

    /**
     * Установка пароля по умолчанию.
     *
     * @param password пароль по умолчанию.
     */
    public void setDefaultPassword(char[] password) {
        defaultPassword = password;
    }

    /**
     * Формирование самодподписанного сертификата в
     * качестве временной заглушки до получения
     * сертификата из УЦ до установки сертификата
     * пользователя.
     *
     * @param name CN сертификата.
     * @param keyPair Ключевая пара.
     * @param callback Объект для выполнения логирования.
     * @return сформированный самоподписанный сертификат.
     * @throws Exception
     */
    protected X509Certificate getSelfSignedCertStub(String name,
        KeyPair keyPair, LogCallback callback) throws Exception {

        callback.log("Prepare self-signed certificate.");

        final CA20GostCertificateRequest req = new CA20GostCertificateRequest(JCSP.PROVIDER_NAME);
        final Map<String, String> regFields = getRegFields(name);

        final String subjectNameString = convertRegFieldsToSubject(regFields);
        callback.log("Create self-signed certificate with subject: " + subjectNameString);

        callback.log("Signature algorithm: " + algorithmSelector.getSignatureAlgorithmName());

        final byte[] selfSigned = req.getEncodedSelfCert(keyPair, subjectNameString,
            algorithmSelector.getSignatureAlgorithmName());

        callback.log("Return self-signed certificate.");

        return (X509Certificate) CertificateFactory.getInstance("X.509").
            generateCertificate(new ByteArrayInputStream(selfSigned));

    }

    /**
     * Генерация запроса на сертификат (PKCS#10) и
     * получение сертификата. В зависимости от версии УЦ
     * получение сертификата выполняется по-разному.
     *
     * @param caType Версия УЦ.
     * @param name CN сертификата.
     * @param privateKey Закрытый ключ.
     * @param publicKey Открытый ключ.
     * @param callback Объект для выполнения логирования.
     * @return сформированный сертификат.
     * @throws Exception
     */
    protected X509Certificate generateCertificate(CAType caType,
        String name, PrivateKey privateKey, PublicKey publicKey,
        LogCallback callback) throws Exception {

        // Адрес УЦ по умолчанию.
        String address = CA_14_ADDRESS;

        switch (caType) {
            case ca15: address = CA_15_ADDRESS; break;
            case ca20: address = CA_20_ADDRESS; break;
        } // switch

        callback.log("Address of CA: " + address);

        // Создание запроса -> получение сертификата.
        byte[] certContent = generateRequestThenSend2CAAndGetCertificate(
                caType, address, name, privateKey, publicKey, callback);

        callback.log("Convert byte array to certificate.");

        CertificateFactory cf = CertificateFactory.getInstance("X509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate
            (new ByteArrayInputStream(certContent));

        callback.log("Certificate: " + cert.getSubjectDN() +
            ", public key: " + cert.getPublicKey());

        return cert;
    }

    /**
     * В случае УЦ 1.4 - создание запроса на сертификат, отправка
     * его в УЦ, получение сертификата;
     * В случае УЦ 1.5 - регистрация пользователя, получение его
     * токена и пароля, проверка статуса пользователя, создание
     * запроса на сертификат, отправка его в УЦ, проверка статуса
     * запроса, получение сертификата.
     * в случае УЦ 2.0 - регистрация пользователя, получение его
     * токена и пароля, проверка статуса пользователя, создание
     * запроса на сертификат, отправка его в УЦ, проверка статуса
     * запроса, получение сертификата, подтверждение установки
     * (правда, до установки сертификата в контейнер, но здесь
     * удобно обратиться по токену и паролю в последний раз!).
     *
     * @param caType Версия УЦ.
     * @param address Адрес УЦ.
     * @param name CN в сертификате.
     * @param privateKey Закрытый ключ.
     * @param publicKey Открытый ключ.
     * @param callback Объект для выполнения логирования.
     * @return сертификат пользователя.
     * @throws Exception
     */
    private byte[] generateRequestThenSend2CAAndGetCertificate(
        CAType caType, String address, String name, PrivateKey
        privateKey, PublicKey publicKey, LogCallback callback)
        throws Exception {

        switch (caType) {

            // УЦ версии 1.5.
            case ca15: {

                // 1. Регистрация пользователя.

                callback.log("Register user: " + name);

                // Нужно обращаться в УЦ за списком полей, но
                // эти известны заранее. В случае УЦ 1.5 поля
                // в списке имеют иные имена, чем те, что передаются
                // в запрос на сертификат, хотя значения совпадают.

                final Map<String, String> regUserFields = getRegFieldsForCA15(name);
                final Map<String, String> regRequestFields = getRegFields(name);

                CA15User user = new CA15User(regUserFields);
                final CA15UserRegisterInfoStatus userStatus = user.registerUser(address);

                callback.log("User tokenID: " + userStatus.getTokenID() +
                    ", user password: " + userStatus.getPassword());

                if (userStatus.getValue() != CA15Status.CR_DISP_ISSUED &&
                    userStatus.getValue() != CA15Status.CR_DISP_UNDER_SUBMISSION) {

                    callback.log("User registration failed.");
                    throw new Exception("User registration failed.");

                } // if

                // 2. Проверка статуса регистрации пользователя.

                user = new CA15User(userStatus.getTokenID(), userStatus.getPassword());
                if (userStatus.getValue() == CA15Status.CR_DISP_UNDER_SUBMISSION) {

                    boolean statusComplete = false;
                    int counter = 60;

                    while (counter > 0) {

                        Thread.sleep(1000);
                        counter--;

                        // Проверка статуса регистрации.
                        final CA15UserRegisterStatus status = user.checkUserStatus(address);
                        callback.log("Waiting user status: " + status.getValue());

                        // Если регистрация выполнена, то продолжаем.
                        if (userStatus.getValue() == CA15Status.CR_DISP_ISSUED) {
                            statusComplete = true;
                            break;
                        } // if

                    } // while

                    if (!statusComplete) {
                        callback.log("User status failed: not complete!");
                        throw new Exception("Hmm... Still not complete?");
                    } // if

                } // if

                // 3. Создание запроса на сертификат.

                callback.log("Combine subject name.");
                final String subjectNameString = convertRegFieldsToSubject(regRequestFields);

                callback.log("Create certificate request with subject: " +
                    subjectNameString + " for user: " + user.getTokenID());

                // Создание запроса (аналогично УЦ 1.4).
                final GostCertificateRequest request = createCertificateRequest(
                    subjectNameString, privateKey, publicKey, callback, null);

                final byte[] reqEncoded = request.getEncoded();
                callback.log("Send certificate request.");

                // Кодирование запроса в base64, чтобы использовать
                // статическую функцию из класса при отправке запроса.

                final Encoder encoder = new Encoder();
                final ByteArrayOutputStream outStream = new ByteArrayOutputStream();

                encoder.encode(reqEncoded, outStream);
                outStream.close();

                final byte[] reqEncodedB64 = outStream.toByteArray();

                // 4. Отправка запроса в УЦ.

                CA15RequestStatus requestStatus = CA15GostCertificateRequest.
                    sendCertificateRequestB64(address, user, reqEncodedB64);

                if (requestStatus.getValue() == CA15Status.CR_DISP_ERROR) {
                    callback.log("Sending certificate request failed.");
                    throw new Exception("Sending certificate request failed");
                } // if

                // 5. Проверка статуса обработки запроса на сертификат.

                if (requestStatus.getValue() == CA15Status.CR_DISP_UNDER_SUBMISSION) {

                    boolean statusComplete = false;
                    int counter = 60;

                    while (counter > 0) {

                        Thread.sleep(1000);
                        counter--;

                        // Проверка статуса обработки запроса.
                        requestStatus = CA15GostCertificateRequest.checkCertificateStatus(
                            address, user, requestStatus.getRequestIdentifier());

                        callback.log("Waiting certificate status: " + requestStatus.getValue());

                        // Если обработка выполнена, то продолжаем.
                        if (requestStatus.getValue() == CA15Status.CR_DISP_ISSUED) {
                            statusComplete = true;
                            break;
                        } // if

                    } // while

                    if (!statusComplete) {
                        callback.log("Certificate status failed: not complete!");
                        throw new Exception("Hmm... Still not complete?");
                    } // if

                } // if

                callback.log("Receive certificate by id: " +
                    requestStatus.getRequestIdentifier());

                // Получение сертификата по идентификатору.
                return CA15GostCertificateRequest.getCertificateByRequestId(
                    address, user, requestStatus.getRequestIdentifier());

            }

            /** JCP-387: пока нет внещнего тестового УЦ 2.0 - заблокировано!
            // УЦ версии 2.0.
            case ca20: {

                // 1. Регистрация пользователя.

                callback.log("Register user: " + name);

                // Нужно обращаться в УЦ за списком полей, но
                // эти известны заранее.

                final Map<String, String> regFields = getRegFields(name);
                CA20User user = new CA20User(regFields, USER_FOLDER);

                final CA20UserRegisterInfoStatus regUserStatus =
                    user.registerUser(address, USER_INFO);

                // Проверка статуса регистрации пользователя. Пользователь
                // считается зарегистрированным, если статус Complete.

                callback.log("User status: " + regUserStatus);

                user = new CA20User(regUserStatus.getTokenID(),
                    regUserStatus.getPassword(), USER_FOLDER);

                // 2. Проверка статуса регистрации пользователя.
                // Запрос считается обработанным, если статус Complete.

                if (!regUserStatus.getStatus().equalsIgnoreCase(CA20Status.STATUS_REQUEST_C)) {

                    boolean statusComplete = false;
                    int counter = 60;

                    while (counter > 0) {

                        Thread.sleep(1000);
                        counter--;

                        // Проверка статуса регистрации.
                        final CA20Status userStatus = user.checkUserStatus(address);
                        callback.log("Waiting user status: " + userStatus);

                        // Если регистрация выполнена, то продолжаем.
                        if (userStatus.getStatus().equalsIgnoreCase(CA20Status.STATUS_REQUEST_C)) {
                            statusComplete = true;
                            break;
                        } // if

                    } // while

                    if (!statusComplete) {
                        callback.log("User status failed: not complete!");
                        throw new Exception("Hmm... Still not complete?");
                    } // if

                } // if

                // 3. Создание запроса на сертификат по шаблону.

                // Нужно обращаться в УЦ за списком шаблонов, но
                // этот известен заранее.

                callback.log("Create template extension.");
                final Extension templateExtension = createTemplateExtension("1.2.643.2.2.46.0.8"); // шаблон "пользователь"

                callback.log("Combine subject name.");
                final String subjectNameString = convertRegFieldsToSubject(regFields);

                callback.log("Create certificate request with subject: " +
                    subjectNameString + " for user: " + user);

                final GostCertificateRequest request = createCertificateRequest(
                    subjectNameString, privateKey, publicKey, callback, templateExtension);

                final byte[] reqEncoded = request.getEncoded();
                callback.log("Send certificate request.");

                // 4. Отправка запроса в УЦ.

                final CA20RequestStatus certRequestStatus = CA20GostCertificateRequest.
                    sendCertificateRequest(address, user, reqEncoded);

                final String userCertReqId = certRequestStatus.getCertRequestId();
                callback.log("Certificate status: " + certRequestStatus);

                // 5. Проверка статуса обработки запроса на сертификат. Запрос
                // считается обработанным, если статус Complete.

                if (!certRequestStatus.getStatus().equalsIgnoreCase(CA20Status.STATUS_REQUEST_C)) {

                    boolean statusComplete = false;
                    int counter = 60;

                    while (counter > 0) {

                        Thread.sleep(1000);
                        counter--;

                        // Проверка статуса запроса на сертификат.
                        final CA20RequestStatus requestStatus =  CA20GostCertificateRequest.
                            checkCertificateStatus(address, user, userCertReqId);

                        callback.log("Waiting certificate status: " + requestStatus);

                        // Если обработка выполнена, то продолжаем.
                        if (requestStatus.getStatus().equalsIgnoreCase(CA20Status.STATUS_REQUEST_C)) {
                            statusComplete = true;
                            break;
                        } // if

                    } // while

                    if (!statusComplete) {
                        callback.log("Certificate status failed: not complete!");
                        throw new Exception("Hmm... Still not complete?");
                    } // if

                } // if

                // 6. Получение сертификата по его идентификатору.

                callback.log("Receive certificate by id: " + userCertReqId);

                final byte[] certContent = CA20GostCertificateRequest.
                    getCertificateByRequestId(address, user, userCertReqId);

                // 7. Уведомление УЦ о том, что сертификат установлен.
                // По факту он еще не установлен: установка будет выполнена
                // позже, после вызова данной функции, то есть уведомление
                // надо отправлять после setCertificateEntry(), просто здесь
                // еще известны токен и пароль. После отправки такого сообщения
                // авторизация будет возможна только по сертификату пользователя,
                // что и будет продемонстрировано позже в этом же примере
                // {@link #tryToAuthorizeByCertificateAndLoadCertList}.

                callback.log("Notify about installation.");

                final CA20RequestStatus installedCertStatus = CA20GostCertificateRequest.
                    markCertificateInstalled(address, user, userCertReqId);

                callback.log("Notification status: " + installedCertStatus);

                if (!installedCertStatus.getStatus().equalsIgnoreCase(CA20Status.STATUS_REQUEST_K)) {
                    throw new Exception("Hmm... Bad response about installed certificate!");
                } // if

                callback.log("Return certificate.");
                return certContent;

            }
            */

            // УЦ версии 1.3-1.4.
            default: {

                // 1. Запрос на сертификат. Список полей известен
                // заранее.

                final Map<String, String> regFields = getRegFields(name);
                final String subjectNameString = convertRegFieldsToSubject(regFields);

                callback.log("Create certificate request with subject: " + subjectNameString);

                final GostCertificateRequest request = createCertificateRequest(
                    subjectNameString, privateKey, publicKey, callback, null);

                // 2. Отправка запроса центру сертификации и получение
                // от центра сертификата в DER-кодировке.

                callback.log("Return certificate.");
                return request.getEncodedCert(address);

            }

        } // switch

    }

    /**
     * В случае УЦ 2.0 - авторизация по сертификату
     * пользователя и получение списка его сертификатов.
     * Выполняется для проверки такой возможности.
     * Используется способ авторизации с заданием хранилищ
     * ключей и сертификатов.
     *
     * @param keyStoreType Тип контейнера.
     * @param keyStorePassword Пароль к ключу.
     * @param callback Объект для выполнения логирования.
     * @param context Контекст приложения.
     * @throws Exception
     */
    protected void tryToAuthorizeByCertificateAndLoadCertList(
        String keyStoreType, String keyStorePassword, LogCallback
        callback, Context context) throws Exception {

        // 1. Получение параметров хранилища корневых сертификатов.

        final String trustStorePath = context.getApplicationInfo().dataDir +
            File.separator + BKSTrustStore.STORAGE_DIRECTORY + File.separator +
                BKSTrustStore.STORAGE_FILE_TRUST;

        callback.log("Trust store: " + trustStorePath);

        // 2. Авторизуемый по сертификату пользователь.

        final CA20CertAuthUser authUser = getCA20UserAuthorizedByCertificate(
            BKSTrustStore.STORAGE_TYPE, BouncyCastleProvider.PROVIDER_NAME,
                trustStorePath, BKSTrustStore.STORAGE_PASSWORD, keyStoreType,
                    keyStorePassword, USER_FOLDER);

        callback.log("Receive certificate list for user (by certificate): " +
            authUser);

        // 3. Получение списка сертификатов
        // авторизованного пользователя в качестве
        // примера авторизации.

        final Vector<CA20CertificateRecord> certificates =
            CA20GostCertificateRequest.getCertificateList(CA_20_ADDRESS,
                authUser);

        for (CA20CertificateRecord certificate : certificates) {
            callback.log("User certificate: " + certificate);
        } // for

    }

    /**
     * Создание запроса на сертификат.
     *
     * @param name CN в сертификате.
     * @param privateKey Закрытый ключ.
     * @param publicKey Открытый ключ.
     * @param callback Объект для выполнения логирования.
     * @param templateExtension Шаблон сертификата (УЦ 2.0).
     * Может быть null.
     * @return запрос на сертификат.
     * @throws Exception
     */
    private GostCertificateRequest createCertificateRequest(String name,
        PrivateKey privateKey, PublicKey publicKey, LogCallback
        callback, Extension templateExtension) throws Exception {

        callback.log("Prepare certificate request.");

        // Создание запроса на сертификат аутентификации сервера.

        GostCertificateRequest request =
            new GostCertificateRequest(JCSP.PROVIDER_NAME);

        callback.log("Set certificate request params.");

        request.setKeyUsage(GostCertificateRequest.CRYPT_DEFAULT);
        request.addExtKeyUsage(GostCertificateRequest.INTS_PKIX_CLIENT_AUTH);

        // Задаем DN-имя.
        request.setSubjectInfo(name);
        request.setPublicKeyInfo(publicKey);

        callback.log("Create certificate request. " +
            "Private key algorithm: " + privateKey.getAlgorithm());

        // Для УЦ 2.0.
        if (templateExtension != null) {
            callback.log("Add template extension.");
            request.addExtension(templateExtension);
        } // if

        callback.log("Signature algorithm: " + algorithmSelector.getSignatureAlgorithmName());
        request.encodeAndSign(privateKey, algorithmSelector.getSignatureAlgorithmName());

        callback.log("Return certificate request.");
        return request;

    }

    /**
     * Создание расширения с указанием шаблона сертификата
     * (УЦ 2.0).
     *
     * @param oid OID шаблона.
     * @return расширение.
     * @throws Exception
     */
    private static Extension createTemplateExtension(String oid) throws Exception {

        final String szOID_CERTIFICATE_TEMPLATE = "1.3.6.1.4.1.311.21.7"; // OID расширения в запросе
        final OID OID_CERTIFICATE_TEMPLATE = new OID(szOID_CERTIFICATE_TEMPLATE);

        final OID  selectedTemplateOid = new OID(oid);

        // Формат: шаблон, 1, 0.
        final CertificateTemplate certificateTemplate = new CertificateTemplate(
            new Asn1ObjectIdentifier(selectedTemplateOid.value),
                new Asn1Integer(1), new Asn1Integer(0));

        final Asn1DerEncodeBuffer buffer = new Asn1DerEncodeBuffer();
        certificateTemplate.encode(buffer);

        final byte[] encodedCertificateTemplate = buffer.getMsgCopy();

        final Asn1OctetString certificateTemplateValue = new
            Asn1OctetString(encodedCertificateTemplate);

        return new Extension(new Asn1ObjectIdentifier(
            OID_CERTIFICATE_TEMPLATE.value), certificateTemplateValue);

    }

    /**
     * Получение списка полей для регистрации пользователя.
     * Они должны определяться и заполняться после выполнения
     * запроса списка полей, но известно, что эти два поля
     * (CommonName и Country) точно будут присутствовать в списке,
     * поэтому, чтобы не усложнять код, сразу используем именно
     * их, меняя только имя пользователя.
     *
     * @param userName Имя пользователя.
     * @return список заполненных полей для регистрации
     * пользователя.
     */
    private static Map<String, String> getRegFields(String userName) {

        final Map<String, String> regFields = new HashMap<String, String>();

        regFields.put("2.5.4.3", userName);
        regFields.put("2.5.4.6", "RU");

        return regFields;

    }

    /**
     * Получение списка полей для регистрации пользователя в УЦ
     * 1.5. Они должны определяться и заполняться после выполнения
     * запроса списка полей, но известно, что эти два поля
     * (CommonName и Country) точно будут присутствовать в списке,
     * поэтому, чтобы не усложнять код, сразу используем именно
     * их, меняя только имя пользователя.
     *
     * @param userName Имя пользователя.
     * @return список заполненных полей для регистрации
     * пользователя в УЦ 1.5.
     */
    private static Map<String, String> getRegFieldsForCA15(String userName) {

        final Map<String, String> regFields = new HashMap<String, String>();

        regFields.put("RDN_CN_1", userName);
        regFields.put("RDN_C_1", "RU");

        return regFields;

    }

    /**
     * Формирование subject name в виде строки из списка полей
     * regFields, т.е. фактически из результатов списка полей
     * для регистрации пользователя.
     *
     * @param regFields Список полей.
     * @return строка для Subject.
     */
    private static String convertRegFieldsToSubject(Map<String, String> regFields) {

        final StringBuilder subjectName = new StringBuilder();
        final Set<Map.Entry<String, String>> regFieldsSet = regFields.entrySet();

        final Iterator<Map.Entry<String, String>> regFieldsIterator = regFieldsSet.iterator();
        while (regFieldsIterator.hasNext()) {

            final Map.Entry<String, String> entry = regFieldsIterator.next();
            subjectName.append(entry.getKey());

            subjectName.append("=");
            subjectName.append(entry.getValue());

            if (regFieldsIterator.hasNext()) {
                subjectName.append(",");
            } // if

        } // while

        return subjectName.toString();

    }

    /**
     * Создание авторизуемого по сертификату пользователя, уже ранее
     * зарегистрированного в УЦ (CA20), получившего и установившего
     * сертификат.
     *
     * @param trustStoreType Тип хранилища.
     * @param trusStoreProvider Провайдер хранилища.
     * @param trustStorePath Файл хранилища доверенных сертификатов.
     * @param trustStorePassword Пароль к хранилищу сертификатов.
     * @param keyStoreType Тип контейнера.
     * @param keyStorePassword Пароль к ключевому контейнеру.
     * @param folder Папка пользователя.
     * @return авторизуемый пользователь УЦ.
     * @throws Exception
     */
    private static CA20CertAuthUser getCA20UserAuthorizedByCertificate(String
        trustStoreType, String trusStoreProvider, String trustStorePath, char[]
        trustStorePassword, String keyStoreType, String keyStorePassword, String
        folder) throws Exception {

        final KeyStore trustStore = KeyStore.getInstance(trustStoreType, trusStoreProvider);
        trustStore.load(new FileInputStream(trustStorePath), trustStorePassword);

        final KeyStore keyStore = KeyStore.getInstance(keyStoreType, JCSP.PROVIDER_NAME);
        keyStore.load(null, null);

        return new CA20CertAuthUser(keyStore, keyStorePassword,
            trustStore, folder);

    }

    /**
     * Определение алгоритма ключа по типу провайдера и ключа.
     *
     * @param type Тип провайдера.
     * @param exchange Тип ключа, true - ключ обмена,
     * false - ключ подписи.
     * @return алгоритм ключа.
     */
    protected static String getKeyAlgorithm(AlgorithmSelector.DefaultProviderType
        type, boolean exchange) {

        switch (type) {

            case pt2012Short:
                return exchange ? JCP.GOST_DH_2012_256_NAME : JCP.GOST_EL_2012_256_NAME;

            case pt2012Long:
                return exchange ? JCP.GOST_DH_2012_512_NAME : JCP.GOST_EL_2012_512_NAME;

            default:
                return exchange ? JCP.GOST_EL_DH_NAME : JCP.GOST_EL_DEGREE_NAME;

        } // switch

    }

    /**
     * Определение набора параметров для ключа по алгоритму ключа.
     * Для окончательного формирования параметров необходимо имя
     * контейнера.
     *
     * @param algorithmName Алгоритм ключа.
     * @param storeName Имя контейнера.
     * @return набор параметров ключа.
     */
    protected static AlgIdSpec getKeyParametersByAlgorithm(
        String algorithmName, String storeName) {

        if (algorithmName.equalsIgnoreCase(JCP.GOST_EL_DEGREE_NAME)) {
            return new NameAlgIdSpec(storeName);
        } // if
        else if (algorithmName.equalsIgnoreCase(JCP.GOST_EL_DH_NAME)) {
            return new NameAlgIdSpec(AlgIdSpec.getDHDefault(), storeName);
        } // else
        else if (algorithmName.equalsIgnoreCase(JCP.GOST_EL_2012_256_NAME)) {
            return new NameAlgIdSpec(AlgIdSpec.OID_PARAMS_SIG_2012_256, storeName);
        } // if
        else if (algorithmName.equalsIgnoreCase(JCP.GOST_DH_2012_256_NAME)) {
            return new NameAlgIdSpec(AlgIdSpec.OID_PARAMS_EXC_2012_256, storeName);
        } // else
        else if (algorithmName.equalsIgnoreCase(JCP.GOST_EL_2012_512_NAME)) {
            return new NameAlgIdSpec(AlgIdSpec.OID_PARAMS_SIG_2012_512, storeName);
        } // if
        else if (algorithmName.equalsIgnoreCase(JCP.GOST_DH_2012_512_NAME)) {
            return new NameAlgIdSpec(AlgIdSpec.OID_PARAMS_EXC_2012_512, storeName);
        } // else

        throw new IllegalArgumentException("Invalid key algorithm name: " + algorithmName);
    }

}
