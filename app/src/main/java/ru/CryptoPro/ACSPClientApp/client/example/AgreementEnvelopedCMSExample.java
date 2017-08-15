/**
 * $RCSfileAgreementEnvelopedCMSExample.java,v $
 * version $Revision: 36379 $
 * created 19.02.2015 14:22 by afevma
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
package ru.CryptoPro.ACSPClientApp.client.example;

import ru.CryptoPro.ACSPClientApp.client.example.interfaces.ContainerAdapter;

/**
 * Класс EnvelopedCMSExample реализует пример
 * создания и проверки Enveloped CMS подписи
 * с key_agreement.
 *
 * @author Copyright 2004-2015 Crypto-Pro. All rights reserved.
 * @.Version
 */
public class AgreementEnvelopedCMSExample extends EnvelopedCMSExample {

    /**
     * Конструктор.
     *
     * @param adapter Настройки примера.
     */
    public AgreementEnvelopedCMSExample(ContainerAdapter adapter) {
        super(adapter, false);
    }
}
