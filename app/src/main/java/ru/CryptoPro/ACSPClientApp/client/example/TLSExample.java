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
import ru.CryptoPro.ACSPClientApp.client.example.interfaces.ITLSData;
import ru.CryptoPro.ACSPClientApp.client.example.interfaces.IThreadExecuted;

import java.io.IOException;

/**
 * Класс TLSExample реализует пример обмена
 * по TLS 1.0.
 *
 * 27/05/2013
 *
 */
public class TLSExample extends ITLSData {

    /**
     * Конструктор.
     *
     * @param adapter Настройки примера.
     */
    protected TLSExample(ContainerAdapter adapter) {
        super(adapter);
    }

    @Override
    public void getResult(LogCallback callback) throws Exception {
        IThreadExecuted task = new SampleTLSThread();
        getResult(callback, task);
    }

    /**
     * Класс SimpleTLSThread реализует подключение
     * самописного клиента по TLS.
     *
     */
    private class SampleTLSThread implements IThreadExecuted {

        @Override
        public void execute(LogCallback callback) {

            Client client = new Client(
                containerAdapter.getConnectionInfo().getHostAddress(),
                containerAdapter.getConnectionInfo().getHostPort(),
                callback);

            client.setTimeout(MAX_CLIENT_TIMEOUT);

            try {

                if (client.get(createSSLContext(callback),
                    containerAdapter.getConnectionInfo().getHostPage()) == 0) {
                    callback.setStatusOK();
                } // if
                else {
                    throw new IOException("Couldn't get data.");
                } // else

            } catch (Exception e) {
                callback.setStatusFailed();
                Log.e(Constants.APP_LOGGER_TAG, "Operation exception", e);
            }

        }
    }

}
