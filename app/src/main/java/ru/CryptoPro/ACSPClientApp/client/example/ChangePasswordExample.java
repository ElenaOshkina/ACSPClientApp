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
import ru.CryptoPro.ACSPClientApp.client.example.interfaces.IGenKeyPairData;
import ru.CryptoPro.ACSPClientApp.client.example.interfaces.ISignData;
import ru.CryptoPro.ACSPClientApp.util.KeyStoreType;
import ru.CryptoPro.JCP.KeyStore.JCPPrivateKeyEntry;
import ru.CryptoPro.JCSP.JCSP;

import java.security.KeyStore;
import java.security.cert.Certificate;

/**
 * Класс ChangePasswordExample реализует пример смены
 * пароля на созданный контейнер путем копирования его
 * ключа и сертификата в новый контейнер с тем же именем,
 * но новым паролем, задаваемым программно, без ввода в
 * окне CSP.
 *
 * 25/07/2013
 *
 */
public class ChangePasswordExample extends ISignData {

    /**
     * Новый пароль на контейнер.
     */
    private static final char[] NEW_PASSWORD =
        "ANewPassword".toCharArray(); // 12345678

    /**
     * Конструктор.
     *
     * @param adapter Настройки примера.
     */
    public ChangePasswordExample(ContainerAdapter adapter) {
        super(adapter, false);
    }

    @Override
    public void getResult(LogCallback callback) throws Exception {

        // Создаем ключевой контейнер.

        callback.log("Create key container.");

        IGenKeyPairData genKeyPairData = new GenKeyPairExample(
            containerAdapter, IGenKeyPairData.CAType.ca14, null);

        genKeyPairData.getResult(callback);

        // Загружаем ключевой контейнер.
        callback.log("Load key container.");

        load(true, KeyStoreType.currentType(),
            genKeyPairData.getStoreAlias(), null, callback);

        // Сохраняем ключ так, чтобы не было окон для ввода
        // пин-кода.
        callback.log("Prepare protected parameters.");

        KeyStore dstKeyStore = KeyStore.getInstance(
            KeyStoreType.currentType(), JCSP.PROVIDER_NAME);
        dstKeyStore.load(null, null);

        KeyStore.ProtectionParameter protectedParamNew =
            new KeyStore.PasswordProtection(NEW_PASSWORD);

        KeyStore.Entry entry = new JCPPrivateKeyEntry(
            getPrivateKey(), new Certificate[] {getCertificate()});

        callback.log("Change a password of the container: " +
            new String(NEW_PASSWORD));

        dstKeyStore.setEntry(genKeyPairData.getStoreAlias(),
            entry, protectedParamNew);
        dstKeyStore.store(null, null);

        callback.log("Password was changed successfully.");
        callback.setStatusOK();

    }
}
