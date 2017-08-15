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

import android.util.Log;

import ru.CryptoPro.ACSPClientApp.Constants;
import ru.CryptoPro.ACSPClientApp.client.LogCallback;
import ru.CryptoPro.ACSPClientApp.client.example.interfaces.ContainerAdapter;
import ru.CryptoPro.ACSPClientApp.client.example.interfaces.ISignData;
import ru.CryptoPro.ACSPClientApp.client.example.interfaces.IThreadExecuted;
import ru.CryptoPro.ACSPClientApp.util.KeyStoreType;
import ru.CryptoPro.JCSP.JCSP;

import java.io.ByteArrayInputStream;
import java.security.KeyStore;
import java.security.cert.*;
import java.util.*;

/**
 * Класс CheckCertStatusExample реализует пример проверки
 * статуса сертификата.
 *
 * 27/05/2013
 *
 */
public class CheckCertStatusExample extends ISignData {

    /**
     * Корневы сертификаты. Формируются по файлу, передаваемому
     * из ресурсов извне. Должен подходить ключам, перечисленным
     * в {@link ru.CryptoPro.ACSPClientApp.util.IContainers}.
     */
    private List<X509Certificate> rootCertList = new LinkedList<X509Certificate>();

    /**
     * Конструктор.
     *
     * @param adapter Настройки примера.
     */
    public CheckCertStatusExample(ContainerAdapter adapter) {
        super(adapter, false);
        readCertStore();
    }

    /**
     * Загрузка списка сорневых сертификатов из хранилища.
     *
     */
    private void readCertStore() {

        try {

            /**
             * Для чтения(!) доверенного хранилища доступна
             * реализация CertStore из Java CSP. В ее случае
             * можно не использовать пароль.
             */

            KeyStore keyStore = KeyStore.getInstance(
                containerAdapter.getTrustStoreType(),
                containerAdapter.getTrustStoreProvider());

            keyStore.load(containerAdapter.getTrustStoreStream(),
                containerAdapter.getTrustStorePassword());

            Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {

                String alias = aliases.nextElement();
                if (keyStore.isCertificateEntry(alias)) {

                    Certificate tmpCert = keyStore.getCertificate(alias);

                    X509Certificate cert = (X509Certificate) CERT_FACTORY.
                        generateCertificate(new ByteArrayInputStream(tmpCert.getEncoded()));

                    rootCertList.add(cert);

                } // if

            } // while

        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }

    @Override
    public void getResult(LogCallback callback) throws Exception {
        getResult(callback, new CheckCertStatusThread());
    }

    /**
     * Класс CheckCertStatusThread реализует выполнение
     * проверки статуса цепочки сертификатов в отдельном
     * потоке.
     *
     */
    private class CheckCertStatusThread implements IThreadExecuted {

        @Override
        public void execute(LogCallback callback) {

            try {

                // Тип контейнера по умолчанию.
                String keyStoreType = KeyStoreType.currentType();
                callback.log("Load key container. Default container " +
                    "type: " + keyStoreType);

                // Загрузка контейнера.
                load(true, keyStoreType, containerAdapter.getClientAlias(),
                    containerAdapter.getClientPassword(), callback);

                callback.log("Client certificate: " + getCertificate().getSubjectDN() +
                    ", public key: " + getCertificate().getPublicKey());

                // Сертификаты (в данном случае корневой и пользователя,
                // выданный УЦ).

                final Set<TrustAnchor> trust = new HashSet<TrustAnchor>(0);
                for (X509Certificate root : rootCertList) {
                    trust.add(new TrustAnchor(root, null));
                } // for

                final List<Certificate> cert = new ArrayList<Certificate>(0);
                cert.add(getCertificate()); // пользователь

                for (X509Certificate root : rootCertList) {
                    cert.add(root);
                } // for

                // Параметры цепочки.

                callback.log("Set PKIX parameters.");

                final PKIXBuilderParameters cpp =
                    new PKIXBuilderParameters(trust, null);

                // Всегда используем только провайдер JCSP.
                cpp.setSigProvider(JCSP.PROVIDER_NAME);

                final CollectionCertStoreParameters par =
                    new CollectionCertStoreParameters(cert);

                final CertStore store =
                    CertStore.getInstance("Collection", par);
                cpp.addCertStore(store);

                final X509CertSelector selector = new X509CertSelector();
                selector.setCertificate(getCertificate());
                cpp.setTargetCertConstraints(selector);

                // Построение цепочки (используем напрямую CPPKIX).

                callback.log("Build certificate chain.");

                cpp.setRevocationEnabled(false);

                CertPathBuilder builder =
                    CertPathBuilder.getInstance("CPPKIX", "RevCheck");

                PKIXCertPathBuilderResult res = null;

                try {
                    res = (PKIXCertPathBuilderResult)builder.build(cpp);
                } catch (Exception e) {
                    Log.e(Constants.APP_LOGGER_TAG, e.getMessage(), e);
                    callback.log("Building failed.");
                    callback.setStatusFailed();
                    return;
                }

                final CertPath cp = res.getCertPath();

                // Проверка цепочки (используем напрямую CPPKIX).

                callback.log("Verify certificate chain.");

                final CertPathValidator cpv =
                    CertPathValidator.getInstance("CPPKIX", "RevCheck");
                cpp.setRevocationEnabled(true);

                try {
                    cpv.validate(cp, cpp);
                } catch (Exception e) {
                    Log.e(Constants.APP_LOGGER_TAG, e.getMessage(), e);
                    callback.log("Verification failed.");
                    callback.setStatusFailed();
                    return;
                }

                callback.setStatusOK();

            } catch (Exception e) {
                callback.setStatusFailed();
                Log.e(Constants.APP_LOGGER_TAG, "Operation exception", e);
            }

        }
    }

}
