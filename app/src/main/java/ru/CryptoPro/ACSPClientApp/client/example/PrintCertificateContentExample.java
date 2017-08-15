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

import ru.CryptoPro.ACSPClientApp.client.LogCallback;
import ru.CryptoPro.ACSPClientApp.client.example.interfaces.ContainerAdapter;
import ru.CryptoPro.ACSPClientApp.client.example.interfaces.ISignData;
import ru.CryptoPro.ACSPClientApp.util.KeyStoreType;

/**
 * Класс PrintCertificateContentExample реализует пример
 * вывода содержимого сертификата в лог.
 *
 * 25/07/2013
 *
 */
public class PrintCertificateContentExample extends ISignData {

    /**
     * Конструктор.
     *
     * @param adapter Настройки примера.
     */
    public PrintCertificateContentExample(ContainerAdapter adapter) {
        super(adapter, false);
    }

    @Override
    public void getResult(LogCallback callback) throws Exception {

        // Тип контейнера по умолчанию.
        String keyStoreType = KeyStoreType.currentType();
        callback.log("Default container type: " + keyStoreType);
        callback.log("Load source key container.");

        load(true, keyStoreType, containerAdapter.getClientAlias(),
            containerAdapter.getClientPassword(), callback);

        if (getCertificate() == null) {
            callback.log("Source certificate is null.");
            return;
        } // if

        callback.log("*************************");
        callback.log(getCertificate().toString());

        callback.setStatusOK();
    }
}
