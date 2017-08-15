/**
 * $RCSfileIACSPIntent.java,v $
 * version $Revision: 36379 $
 * created 06.05.2015 12:50 by afevma
 * last modified $Date: 2012-05-30 12:19:27 +0400 (Ср, 30 май 2012) $ by $Author: afevma $
 *
 * Copyright 2004-2015 Crypto-Pro. All rights reserved.
 * Программный код, содержащийся в этом файле, предназначен
 * для целей обучения. Может быть скопирован или модифицирован
 * при условии сохранения абзацев с указанием авторства и прав.
 *
 * Данный код не может быть непосредственно использован
 * для защиты информации. Компания Крипто-Про не несет никакой
 * ответственности за функционирование этого кода.
 */
package ru.CryptoPro.ACSPClientApp.client.example.interfaces;

/**
 * Интерфейс с набором констант для закладки ACSPIntentActivity.
 *
 * @author Copyright 2004-2015 Crypto-Pro. All rights reserved.
 * @.Version
 */
public interface IACSPIntent {

    /**
     * Интент копирования контейнера.
     */
    public static final String INTENT_NAME_COPY_CONTAINER = "ru.cprocsp.intent.COPY_CONTAINER";

    /**
     * Интент установки сертификата.
     */
    public static final String INTENT_NAME_INSTALL_CERT = "ru.cprocsp.intent.INSTALL_CERTIFICATE";

    /**
     * Интент подписи данных.
     */
    public static final String INTENT_NAME_SIGN_DATA = "ru.cprocsp.intent.SIGN_DATA";

    /**
     * Интент построения цепочки.
     */
    public static final String INTENT_NAME_BUILD_CHAIN = "ru.cprocsp.intent.BUILD_CHAIN";

    /**
     * Интент проверки подписи.
     */
    public static final String INTENT_NAME_VERIFY_SIGN = "ru.cprocsp.intent.VERIFY_SIGN";

    /**
     * Интент создания контейнера.
     */
    public static final String INTENT_NAME_CREATE_CONTAINER = "ru.cprocsp.intent.GEN_CONT";

    /**
     * Идентификатор интента копирования контейнера.
     */
    public static final int INTENT_ID_COPY_CONTAINER = 1;

    /**
     * Идентификатор кода запроса установки сертификата.
     */
    public static final int INTENT_ID_INSTALL_CERT = 2;

    /**
     * Идентификатор кода запроса построения цепочки сертификатов.
     */
    public static final int INTENT_ID_BUILD_CHAIN = 3;

    /**
     * Идентификатор кода запроса подписи данных.
     */
    public static final int INTENT_ID_SIGN_DATA = 4;

    /**
     * Идентификатор кода запроса проверки подписи.
     */
    public static final int INTENT_ID_VERIFY_SIGN = 5;

    /**
     * Идентификатор кода запроса проверки подписи.
     */
    public static final int INTENT_ID_CREATE_CONTAINER = 6;

    /**
     * Личное хранилище (контейнеры).
     */
    public static final String STORAGE_PERSONAL = "Personal";

    /**
     * Промежуточные сертификаты (хранилище сертификатов.
     */
    public static final String STORAGE_INTERMEDIATE = "Intermediate";

    /**
     * Корневые сертификаты (хранилище сертификатов.
     */
    public static final String STORAGE_TRUST = "Trust";

    /**
     * TODO: Временный файл для проверки.
     */
    /*
    public static final String TMP_CERT_FILE = "/mnt/sdcard/111.cer";
    */

    /**
     * TODO: Временный файл для проверки.
     */
    /*
    public static final String TMP_CERT_CHAIN_FILE = "/mnt/sdcard/111.p7b";
    */

}
