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
package ru.CryptoPro.ACSPClientApp.client.example;

import android.content.Context;
import android.util.Log;

import ru.CryptoPro.ACSPClientApp.Constants;
import ru.CryptoPro.ACSPClientApp.client.LogCallback;
import ru.CryptoPro.ACSPClientApp.client.example.interfaces.ContainerAdapter;
import ru.CryptoPro.ACSPClientApp.client.example.interfaces.IGenKeyPairData;
import ru.CryptoPro.ACSPClientApp.client.example.interfaces.IThreadExecuted;
import ru.CryptoPro.ACSPClientApp.util.KeyStoreType;

import ru.CryptoPro.JCP.KeyStore.JCPPrivateKeyEntry;
import ru.CryptoPro.JCP.params.AlgIdSpec;

import ru.CryptoPro.JCSP.JCSP;
import ru.CryptoPro.JCSP.Key.GostPrivateKey;
import ru.CryptoPro.JCSP.Key.GostPublicKey;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

/**
 * Класс GenKeyPairExample реализует пример генерации
 * ключевой пары и создания контейнера.
 * Ввод пин-кодов осуществляется в окно CSP, хотя можно
 * настроить пример для ввода пин-кода программно, используя
 * KeyStore.ProtectionParameters и KeyStore.setEntry().
 *
 * 27/06/2013
 *
 */
public class GenKeyPairExample extends IGenKeyPairData {

    /**
     * Версия УЦ.
     */
    private CAType caType = CAType.ca14;

    /**
     * Контекст приложения.
     */
    private Context context = null;

    /**
     * Конструктор. Производит создание генератора
     * чисел.
     *
     * @param adapter Настройки примера.
     * @param caType Версия УЦ.
     * @param context Контекст приложения.
     */
    public GenKeyPairExample(ContainerAdapter adapter, CAType
        caType, Context context) {

        super(adapter);

        this.caType = caType;
        this.context = context;

    }

    @Override
    public void getResult(LogCallback callback) throws Exception {
        getResult(callback, new GenKeyPairThread());
    }

    /**
     * Класс SimpleTLSThread реализует подключение
     * apache http клиента по TLS.
     *
     */
    private class GenKeyPairThread implements IThreadExecuted {

        @Override
        public void execute(LogCallback callback) {

            try {

                // Тип контейнера по умолчанию.
                String keyStoreType = KeyStoreType.currentType();
                callback.log("Default container type: " + keyStoreType);

                String keyAlgorithmName = getKeyAlgorithm(
                   containerAdapter.getProviderType(),
                   containerAdapter.isExchangeKey());

                callback.log("Create key pair generator: " + keyAlgorithmName);

                KeyPairGenerator kg = KeyPairGenerator.getInstance(
                    keyAlgorithmName, JCSP.PROVIDER_NAME);

                callback.log("Store name: " + storeName +
                    ".\nInitialize generator.");

                // Проинициализируем генератор именем. Если это
                // алгоритм DH, то следует указать параметры
                // дополнительно.

                AlgIdSpec params = getKeyParametersByAlgorithm(
                    keyAlgorithmName, storeName);

                kg.initialize(params);
                callback.log("Generate key pair.");

                // Сгенерим пару ключей.

                final KeyPair keypair = kg.generateKeyPair();

                callback.log("\tprivate key: " + keypair.getPrivate() + "\n\tparameters: " +
                    ((GostPrivateKey) keypair.getPrivate()).getSpec().getParams());

                callback.log("\n\tpublic key: " + keypair.getPublic() + "\n\tparameters: " +
                    ((GostPublicKey)keypair.getPublic()).getSpec().getParams());

                // Получение самодподписанного сертификата-заглушки.

                callback.log("Create self-signed certificate stub.");

                X509Certificate selfSignedCertStub = getSelfSignedCertStub(
                    storeAlias, keypair, callback);

                // Сохранение контейнера с сертификатом-заглушкой.

                callback.log("Open key store and load containers.");

                KeyStore keyStore = KeyStore.getInstance(keyStoreType, JCSP.PROVIDER_NAME);
                keyStore.load(null, null);

                // В случае с УЦ 2.0 в примере далее есть авторизация по сертификату
                // и получение списка сертификатов пользователя. Для этого нужен пароль
                // к контейнеру пользователя, который никак получить нельзя, разве что
                // задав его явно, как в случае setEntry.

                if (askPinInDialog && caType != CAType.ca20) {

                    // При сохранении пин-код будет запрошен в окне CSP.

                    keyStore.setKeyEntry(storeAlias, keypair.getPrivate(),
                        null, new Certificate[] {selfSignedCertStub});

                } // if
                else {

                    // Сохранение контейнера с паролем {@link #defaultPassword},
                    // чтобы он был известен далее. Используется, в частности,
                    // с примером для УЦ 2.0, так как далее есть пробная авторизация
                    // по сертификату и надо знать пароль заранее, а иначе, как указав
                    // его тут, его не узнать.

                    callback.log("NEW key store PASSWORD (CA20): " +
                        ( defaultPassword != null ? String.valueOf(defaultPassword) : null ));

                    KeyStore.ProtectionParameter protectedParam =
                        new KeyStore.PasswordProtection(defaultPassword);

                    JCPPrivateKeyEntry entry =
                        new JCPPrivateKeyEntry(keypair.getPrivate(),
                        new Certificate[] {selfSignedCertStub});

                    keyStore.setEntry(storeAlias, entry, protectedParam);

                } // else

                // Получение из УЦ и установка сертификата в контейнер,
                // если требуется.

                final String keyStorePassword =
                    ( defaultPassword != null ? String.valueOf(defaultPassword) : null );

                X509Certificate userCert = generateCertificate(caType, storeAlias,
                    keypair.getPrivate(), keypair.getPublic(), callback);

                callback.log("Retrieved certificate:\n\tsubject: " +
                    userCert.getSubjectDN() + "\n\tserial: " +
                    userCert.getSerialNumber().toString(16));

                // Пароль не используется, т.к. он был задан в окне
                // при генерации пары. При загрузке используем провайдер
                // Java CSP.

                callback.log("Install certificate to the store...");

                keyStore.setCertificateEntry(storeAlias, userCert);
                callback.log("Certificate is installed.");

                // В случае УЦ 2.0 пробуем авторизоваться по сертификату
                // и выполнить простой запрос списка сертификатов.

                if (caType == CAType.ca20) {

                    callback.log("Try to authorize by user certificate and " +
                        "load certificate list...");

                    tryToAuthorizeByCertificateAndLoadCertList(
                        keyStoreType, keyStorePassword, callback, context);

                } // if

                callback.setStatusOK();

            } catch (Exception e) {
                callback.setStatusFailed();
                Log.e(Constants.APP_LOGGER_TAG, "Operation exception", e);
            }

        }

    }
}
