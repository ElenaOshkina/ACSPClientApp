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
import ru.CryptoPro.ACSPClientApp.client.example.interfaces.IEncryptDecryptData;
import ru.CryptoPro.ACSPClientApp.util.KeyStoreType;
import ru.CryptoPro.JCSP.JCSP;

import java.security.KeyStore;
import java.util.Enumeration;
import java.util.Vector;

/**
 * Класс RemoveContainersExample реализует пример
 * удаления всех контейнеров в папке за исключением
 * тех контейнеров, которые были в ресурсах.
 *
 * 29/08/2013
 *
 */
public class RemoveContainersExample extends IEncryptDecryptData {

    /**
      * Тестовые контейнеры, которые ненужно удалять.
      */
    private static final Vector<String> testContainers = new Vector<String>() {{

        add(CLIENT_KEY_ALIAS);
        add(SERVER_KEY_ALIAS);
        add(CLIENT_KEY_2012_256_ALIAS);
        add(SERVER_KEY_2012_256_ALIAS);
        add(CLIENT_KEY_2012_512_ALIAS);
        add(SERVER_KEY_2012_512_ALIAS);

    }};

    /**
     * Конструктор-заглушка.
     *
     */
    public RemoveContainersExample(ContainerAdapter adapter) {
        super(adapter);
    }

    @Override
    public void getResult(LogCallback callback) throws Exception {
        removeContainers(callback);
    }

    /**
     * Удаление всех контейнеров за исключением копируемых
     * из ресурсов.
     *
     * @param callback Логгер.
     *
     */
    private void removeContainers(LogCallback callback) throws Exception {

        // Тип контейнера по умолчанию.
        String keyStoreType = KeyStoreType.currentType();

        callback.log("Default container type: " + keyStoreType);
        callback.log("Load containers.");

        String alias4del = containerAdapter.getClientAlias();
        if (alias4del != null) {
            callback.log("Delete one container: " + alias4del);
        } // if
        else {
            callback.log("Delete all containers.");
        } // else

        KeyStore keyStore = KeyStore.getInstance(keyStoreType,
            JCSP.PROVIDER_NAME);
        keyStore.load(null, null);

        int removedCount = 0;
        Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {

            String alias = aliases.nextElement();
            callback.log("Container: " + alias);

            // Если задан контейнер, то удаляем только его.

            if (alias4del != null) {

                if (alias.equals(alias4del)) {
                    callback.log("Deleting container: " + alias);
                    keyStore.deleteEntry(alias);
                } // if
                else {
                    callback.log("Continue...");
                    continue;
                } // else

            } // if
            // Иначе удаляем все.
            else {

                // Пропускаем контейнеры из ресурсов.
                if (testContainers.contains(alias)) {
                    callback.log("Container '" + alias + "': skipped.");
                    continue;
                } // if

                keyStore.deleteEntry(alias);

            } // else

            removedCount++;
            callback.log("Container '" + alias + "': removed.");

        } // while

        callback.log("Removed containers' count: " + removedCount);
        callback.setStatusOK();
    }
}
