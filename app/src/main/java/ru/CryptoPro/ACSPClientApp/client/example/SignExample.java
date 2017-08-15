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
 * Класс SignExample реализует пример подписи
 * сообщения.
 *
 * 27/05/2013
 *
 */
public class SignExample extends ISignData {

    /**
     * Конструктор.
     *
     * @param adapter Настройки примера.
     */
    public SignExample(ContainerAdapter adapter) {
        super(adapter, false);
    }

    @Override
    public void getResult(LogCallback callback) throws Exception {
        sign(callback);
    }

    /**
     * Формирование подписи.
     *
     * @param callback Логгер.
     * @return подпись.
     * @throws Exception
     */
    public byte[] sign(LogCallback callback) throws Exception {

        callback.log("Load key container to sign data.");

        // Тип контейнера по умолчанию.
        String keyStoreType = KeyStoreType.currentType();
        callback.log("Default container type: " + keyStoreType);

        // Загрузка ключа и сертификата.

        load(askPinInDialog, keyStoreType, containerAdapter.getClientAlias(),
            containerAdapter.getClientPassword(), callback);

        if (getPrivateKey() == null) {
            callback.log("Private key is null.");
            return null;
        } // if

        callback.log("Init Signature: " +
            algorithmSelector.getSignatureAlgorithmName());

        // Инициализация подписи.

        Signature sn = Signature.getInstance(
            algorithmSelector.getSignatureAlgorithmName(),
            JCSP.PROVIDER_NAME);

        callback.log("Init signature by private key: " + getPrivateKey());

        sn.initSign(getPrivateKey());
        sn.update(Constants.MESSAGE.getBytes());

        // Формируем подпись.

        callback.log("Compute signature for message '" +
            Constants.MESSAGE + "' :");

        byte[] sign = sn.sign();

        callback.log(sign, true);
        callback.setStatusOK();

        return sign;
    }
}
