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
import ru.CryptoPro.ACSPClientApp.client.example.interfaces.IHashData;
import ru.CryptoPro.ACSPClientApp.util.AlgorithmSelector;
import ru.CryptoPro.JCSP.JCSP;

import java.security.MessageDigest;

/**
 * Класс HashExample реализует пример хеширования
 * сообщения.
 *
 * 27/05/2013
 *
 */
public class HashExample implements IHashData {

    /**
     * Алгоритмы провайдера.
     */
    private final ContainerAdapter containerAdapter;

    /**
     * Конструктор.
     *
     * @param adapter Настройки примера.
     */
    public HashExample(ContainerAdapter adapter) {
        containerAdapter = adapter;
    }

    @Override
    public void getResult(LogCallback callback) throws Exception {

        String digestAlgorithm = AlgorithmSelector.getInstance(
            containerAdapter.getProviderType()).getDigestAlgorithmName();

        callback.log("Init message digest (" + digestAlgorithm +
            ") for message '" + Constants.MESSAGE + "' :");

        MessageDigest md = MessageDigest.getInstance(digestAlgorithm,
            JCSP.PROVIDER_NAME);

        callback.log("Compute digest:");
        callback.log(md.digest(Constants.MESSAGE.getBytes()), true);

        callback.setStatusOK();
    }

}
