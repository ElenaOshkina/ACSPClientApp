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

import ru.CryptoPro.ACSPClientApp.client.LogCallback;
import ru.CryptoPro.ACSPClientApp.util.KeyStoreType;
import ru.CryptoPro.JCP.KeyStore.StoreInputStream;
import ru.CryptoPro.JCSP.JCSP;
import ru.CryptoPro.ssl.Provider;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.security.KeyStore;

/**
 * Служебный класс ITLSData предназначен для
 * реализации примеров соединения по TLS.
 *
 * 30/05/2013
 *
 */
public abstract class ITLSData extends IEncryptDecryptData {

    /**
     * Конструктор.
     *
     * @param adapter Настройки примера.
     */
    protected ITLSData(ContainerAdapter adapter) {
        super(adapter); // ignore
    }

    /*
    * Создание SSL контекста.
    *
    * @param callback Логгер.
    * @return готовый SSL контекст.
    * @throws Exception.
    */
    protected SSLContext createSSLContext(LogCallback callback)
        throws Exception {

        containerAdapter.printConnectionInfo(callback);

        callback.log("Init trusted store.");

        /**
         * Для чтения(!) доверенного хранилища доступна
         * реализация CertStore из Java CSP. В ее случае
         * можно не использовать пароль.
         */

        KeyStore ts = KeyStore.getInstance(
            containerAdapter.getTrustStoreType(),
            containerAdapter.getTrustStoreProvider());

        ts.load(containerAdapter.getTrustStoreStream(),
            containerAdapter.getTrustStorePassword());

        KeyManagerFactory kmf = KeyManagerFactory
            .getInstance(Provider.KEYMANGER_ALG, Provider.PROVIDER_NAME);

        if (containerAdapter.isUseClientAuth()) {

            // Тип контейнера по умолчанию.
            String keyStoreType = KeyStoreType.currentType();
            callback.log("Init key store. Load containers. " +
                "Default container type: " + keyStoreType);

            KeyStore ks = KeyStore.getInstance(keyStoreType,
                JCSP.PROVIDER_NAME);

            // Явное указание контейнера.
            if (containerAdapter.getClientAlias() != null) {
                ks.load(new StoreInputStream(containerAdapter.getClientAlias()), null);
            } // if
            else {
                ks.load(null, null);
            } // else

            kmf.init(ks, containerAdapter.getClientPassword());

        } // if

        TrustManagerFactory tmf = TrustManagerFactory
            .getInstance(Provider.KEYMANGER_ALG, Provider.PROVIDER_NAME);
        tmf.init(ts);

        callback.log("Create SSL context.");

        SSLContext sslCtx = SSLContext.getInstance(Provider.ALGORITHM,
            Provider.PROVIDER_NAME);

        sslCtx.init(containerAdapter.isUseClientAuth()
            ? kmf.getKeyManagers() : null, tmf.getTrustManagers(), null);

        callback.log("SSL context completed.");

        return sslCtx;
    }

}
