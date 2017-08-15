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

import ru.CryptoPro.ACSPClientApp.Constants;
import ru.CryptoPro.ACSPClientApp.client.LogCallback;
import ru.CryptoPro.ACSPClientApp.client.example.interfaces.ContainerAdapter;
import ru.CryptoPro.ACSPClientApp.client.example.interfaces.ISignData;
import ru.CryptoPro.ACSPClientApp.util.KeyStoreType;
import ru.CryptoPro.JCSP.JCSP;

import java.security.Signature;

/**
 * Класс VerifyExample реализует пример проверки подписи
 * сообщения.
 *
 * 27/05/2013
 *
 */
public class VerifyExample extends ISignData {

    /**
     * Конструктор.
     *
     * @param adapter Настройки примера.
     */
    public VerifyExample(ContainerAdapter adapter) {
        super(adapter, false);
    }

    @Override
    public  void getResult(LogCallback callback) throws Exception {

        callback.log("Create signature.");

        // Создаем подпись, чтобы потом ее проверить.
        SignExample signData = new SignExample(containerAdapter);
        byte[] sign = signData.sign(callback);

        callback.log("Load key container to verify signature.");

        // Тип контейнера по умолчанию.
        String keyStoreType = KeyStoreType.currentType();
        callback.log("Default container type: " + keyStoreType);

        // Загрузка ключа и сертификата.

        load(true, keyStoreType, containerAdapter.getClientAlias(),
            containerAdapter.getClientPassword(), callback);

        if (getCertificate() == null) {
            callback.log("Certificate is null.");
            return;
        } // if

        callback.log("Init Signature: " +
            algorithmSelector.getSignatureAlgorithmName());

        // Инициализация подписи.

        Signature sn = Signature.getInstance(
            algorithmSelector.getSignatureAlgorithmName(),
            JCSP.PROVIDER_NAME);

        callback.log("Init verification by certificate: " +
            getCertificate().getSubjectDN() + ", public key:" + 
                getCertificate().getPublicKey());

        sn.initVerify(getCertificate());

        callback.log("Source data: " + Constants.MESSAGE);
        sn.update(Constants.MESSAGE.getBytes());

        callback.log("Verify signature:");
        callback.log(sign, true);

        // Проверяем подпись.

        if (sn.verify(sign)) {
            callback.setStatusOK();
        } // if
        else {
            callback.setStatusFailed();
        } // e;se
    }
}
