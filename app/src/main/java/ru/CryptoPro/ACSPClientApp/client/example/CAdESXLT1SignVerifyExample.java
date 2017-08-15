/**
 * $RCSfileCAdESXLT1SignVerifyExample.java,v $
 * version $Revision: 36379 $
 * created 01.12.2014 19:29 by Yevgeniy
 * last modified $Date: 2012-05-30 12:19:27 +0400 (Ср, 30 май 2012) $ by $Author: afevma $
 *
 * Copyright 2004-2014 Crypto-Pro. All rights reserved.
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
import ru.CryptoPro.CAdES.CAdESType;

/**
 * Класс CAdESXLT1SignVerifyExample реализует пример
 * CAdES-подписи типа CAdES-X Long Type 1.
 *
 * @author Copyright 2004-2014 Crypto-Pro. All rights reserved.
 * @.Version
 */
public class CAdESXLT1SignVerifyExample extends CAdESSignVerifyExample {

    /**
     * Конструктор.
     *
     * @param adapter Настройки примера.
     */
    public CAdESXLT1SignVerifyExample(ContainerAdapter adapter) {
        super(adapter, CAdESType.CAdES_X_Long_Type_1);
    }

}
