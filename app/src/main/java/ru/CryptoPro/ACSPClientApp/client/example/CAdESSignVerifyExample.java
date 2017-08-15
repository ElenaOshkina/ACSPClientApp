/**
 * $RCSfileCAdESSignVerifyExample.java,v $
 * version $Revision: 36379 $
 * created 08.09.2014 18:23 by Yevgeniy
 * last modified $Date: 2012-05-30 12:19:27 +0400 (Ср, 30 май 2012) $ by $Author: afevma $
 *
 * Copyright 2004-2014 Crypto-Pro. All rights reserved.
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
import ru.CryptoPro.CAdES.CAdESSignature;
import ru.CryptoPro.CAdES.CAdESType;
import ru.CryptoPro.JCSP.JCSP;

import java.io.ByteArrayOutputStream;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;

/**
 * Класс CAdESSignVerifyExample реализует пример CAdES-подписи.
 *
 * @author Copyright 2004-2014 Crypto-Pro. All rights reserved.
 * @.Version
 */
public class CAdESSignVerifyExample extends ISignData {

    /**
     * Служба штапов.
     */
    private static final String TSA_DEFAULT = "http://www.cryptopro.ru:80/tsp/";

    /**
     * Тип подписи.
     */
    private Integer cAdESType = CAdESType.CAdES_BES;

    /**
     * Конструктор.
     *
     * @param adapter Настройки примера.
     * @param type Тип подписи.
     */
    public CAdESSignVerifyExample(ContainerAdapter adapter, Integer type) {
        super(adapter, false);
        cAdESType = type;
    }

    @Override
    public void getResult(LogCallback callback) throws Exception {
        getResult(callback, new CAdESSignatureThread());
    }

    /**
     * Класс CAdESSignatureThread реализует создание и
     * проверку CAdES подписи в отдельном потоке.
     *
     */
    private class CAdESSignatureThread implements IThreadExecuted {

        @Override
        public void execute(LogCallback callback) {

            try {

                callback.log("Load key container to sign data.");

                // Тип контейнера по умолчанию.
                String keyStoreType = KeyStoreType.currentType();
                callback.log("Default container type: " + keyStoreType);

                // Загрузка ключа и сертификата.
                load(askPinInDialog, keyStoreType, containerAdapter.getClientAlias(),
                    containerAdapter.getClientPassword(), callback);

                if (getPrivateKey() == null) {
                    callback.log("Private key is null.");
                    return;
                } // if

                String signKeyOid = getKeySignatureOidByPrivateKeyAlgorithm(getPrivateKey().getAlgorithm());

                callback.log("Init Digest OID: " + algorithmSelector.getDigestAlgorithmOid());
                callback.log("Init Signature OID: " + signKeyOid);

                // Формируем подпись.

                Collection<X509Certificate> chain = new ArrayList<X509Certificate>();
                chain.add(getCertificate());

                CAdESSignature cAdESSignature = new CAdESSignature(false);

                callback.log("Single signature type: " +
                    (cAdESType.equals(CAdESType.CAdES_BES) ? "CAdES-BES" : "CAdES-X Long Type 1"));
                callback.log("Add one signer: " + getCertificate().getSubjectDN());

                if (cAdESType.equals(CAdESType.CAdES_BES)) {

                    cAdESSignature.addSigner(JCSP.PROVIDER_NAME,
                        algorithmSelector.getDigestAlgorithmOid(), signKeyOid,
                        getPrivateKey(), chain, cAdESType, null, false);

                } // if
                else {

                    cAdESSignature.addSigner(JCSP.PROVIDER_NAME,
                        algorithmSelector.getDigestAlgorithmOid(), signKeyOid,
                        getPrivateKey(), chain, cAdESType, TSA_DEFAULT, false);

                } // else

                ByteArrayOutputStream signatureStream =
                    new ByteArrayOutputStream();

                callback.log("Compute signature for message '" +
                    Constants.MESSAGE + "'");

                cAdESSignature.open(signatureStream);
                cAdESSignature.update(Constants.MESSAGE.getBytes());

                cAdESSignature.close();
                signatureStream.close();

                byte[] sign = signatureStream.toByteArray();
                callback.log(sign, true);

                // Проверяем подпись.

                callback.log("Verify CAdES signature of type: " +
                    (cAdESType.equals(CAdESType.CAdES_BES)
                        ? "CAdES-BES" : "CAdES-X Long Type 1"));

                cAdESSignature = new CAdESSignature(sign, null, cAdESType);
                cAdESSignature.verify(chain);

                callback.log("Verification completed (OK)");
                callback.setStatusOK();

            }
            catch (Exception e) {
                callback.setStatusFailed();
                Log.e(Constants.APP_LOGGER_TAG, "Operation exception", e);
            }

        }

    }

}
