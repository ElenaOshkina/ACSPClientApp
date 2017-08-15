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
import ru.CryptoPro.ACSPClientApp.client.example.interfaces.IEncryptDecryptData;
import ru.CryptoPro.ACSPClientApp.util.KeyStoreType;
import ru.CryptoPro.JCP.JCP;
import ru.CryptoPro.JCSP.JCSP;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Класс ClassicEncryptDecryptExample реализует пример зашифрования
 * и расшифрования сообщения на ключе согласования сторон.
 *
 * 27/05/2013
 *
 */
public class ClassicEncryptDecryptExample extends IEncryptDecryptData {

    /**
     * Конструктор.
     *
     * @param adapter Настройки примера.
     */
    public ClassicEncryptDecryptExample(ContainerAdapter adapter) {
        super(adapter);
    }

    @Override
    public void getResult(LogCallback callback) throws Exception {
        encryptDecrypt(callback);
    }

    /**
     * Выполнение зашифрования и расшифрования сообщения по
     * классической схеме на симметричных ключе согласования
     * сторон.
     *
     * @param callback Логгер.
     * @throws Exception
     */
    private void encryptDecrypt(LogCallback callback) throws Exception {

        // Тип контейнера по умолчанию.
        String keyStoreType = KeyStoreType.currentType();
        callback.log("Default container type: " + keyStoreType);

        // Сторона клиента (алиса).

        callback.log("Load client parameters.");

        ClassicEncryptDecryptExample client =
            new ClassicEncryptDecryptExample(containerAdapter);

        client.load(true, keyStoreType, containerAdapter.getClientAlias(),
            containerAdapter.getClientPassword(), callback);

        callback.log("Client certificate: " + client.getCertificate().getSubjectDN() +
            ", public key: " + client.getCertificate().getPublicKey());

        // Сторона сервера (боб).

        callback.log("Load server parameters.");

        ClassicEncryptDecryptExample server =
            new ClassicEncryptDecryptExample(containerAdapter);

        server.load(true, keyStoreType, containerAdapter.getServerAlias(),
            containerAdapter.getServerPassword(), callback);

        callback.log("Server certificate: " + server.getCertificate().getSubjectDN() +
            ", public key: " + server.getCertificate().getPublicKey());

        byte[] clientPublic = client.getCertificate().getPublicKey().getEncoded();
        byte[] serverPublic = server.getCertificate().getPublicKey().getEncoded();

        // Генерация начальной синхропосылки для выработки
        // ключа согласования.

        callback.log("Generate IV.");

        byte[] data = Constants.MESSAGE.getBytes();
        byte[] sv = new byte[8];
        final String MODE = "/CNT/NoPadding";

        callback.log("Message: " + new String(data));
        callback.log("Set MODE: GOST28147" + MODE);

        SecureRandom random =
            SecureRandom.getInstance(JCP.CP_RANDOM, JCSP.PROVIDER_NAME);
        random.nextBytes(sv);

        IvParameterSpec ivSpec = new IvParameterSpec(sv);
        callback.log("Syncro for KeyAgreement was generated.");

        // Получение открытых ключей сторонами.

        KeyFactory clientKf = KeyFactory.getInstance(client.getCertificate()
            .getPublicKey().getAlgorithm(), JCSP.PROVIDER_NAME);

        X509EncodedKeySpec serverPubKeySpec = new X509EncodedKeySpec(serverPublic);
        PublicKey serverPublicKey = clientKf.generatePublic(serverPubKeySpec);

        callback.log("Client has received server's public key.");

        KeyFactory serverKf = KeyFactory.getInstance(server.getCertificate()
            .getPublicKey().getAlgorithm(), JCSP.PROVIDER_NAME);

        X509EncodedKeySpec clientPubKeySpec = new X509EncodedKeySpec(clientPublic);
        PublicKey clientPublicKey = serverKf.generatePublic(clientPubKeySpec);

        callback.log("Server has received client's public key.");

        String agreeAlgName = client.getPrivateKey().getAlgorithm();

        KeyAgreement clientKeyAgree = KeyAgreement.getInstance(
            agreeAlgName, JCSP.PROVIDER_NAME);

        clientKeyAgree.init(client.getPrivateKey(), ivSpec, null);
        clientKeyAgree.doPhase(serverPublicKey, true);

        SecretKey clientAgree = clientKeyAgree.generateSecret(JCSP.GOST_CIPHER_NAME);
        callback.log("Client's key agreement was performed.");

        // Зашифрование текста на ключе согласования клиента.

        Cipher cipher = Cipher.getInstance(JCSP.GOST_CIPHER_NAME + MODE,
            JCSP.PROVIDER_NAME);

        cipher.init(Cipher.ENCRYPT_MODE, clientAgree,
            (AlgorithmParameterSpec)null, null);

        // Передача вектора инициализации серверу.

        byte[] iv = cipher.getIV();
        byte[] encryptedText = cipher.doFinal(data, 0, data.length);

        callback.log("Client's encrypting was performed.");
        callback.log(encryptedText, true);

        // Выработка ключа согласования сервера с тем же SV.

        KeyAgreement serverKeyAgree = KeyAgreement.getInstance(
            agreeAlgName, JCSP.PROVIDER_NAME);

        serverKeyAgree.init(server.getPrivateKey(), ivSpec, null);
        serverKeyAgree.doPhase(clientPublicKey, true);

        SecretKey serverAgree = serverKeyAgree
            .generateSecret(JCSP.GOST_CIPHER_NAME);
        callback.log("Server's key agreement was performed.");

        // Расшифрование текста на ключе согласования сервера.
        // IV передан от клиента.

        cipher = Cipher.getInstance(JCSP.GOST_CIPHER_NAME + MODE,
            JCSP.PROVIDER_NAME);

        cipher.init(Cipher.DECRYPT_MODE, serverAgree,
            new IvParameterSpec(iv), null);

        byte[] decryptedText =
            cipher.doFinal(encryptedText, 0, encryptedText.length);

        callback.log("Server's decrypting was performed.");
        callback.log("Decrypted message: " + new String(decryptedText));

        // Проверка результата.

        if (decryptedText.length != data.length) {
            callback.log("Error in encrypting/decrypting. Invalid length.");
            callback.setStatusFailed();
            return;
        } // if

        for (int i = 0; i < decryptedText.length; i++) {
            if (data[i] != decryptedText[i]) {
                callback.log("Error in encrypting/decrypting. Invalid data.");
                callback.setStatusFailed();
                return;
            } // if
        } // for

        callback.setStatusOK();

    }
}
