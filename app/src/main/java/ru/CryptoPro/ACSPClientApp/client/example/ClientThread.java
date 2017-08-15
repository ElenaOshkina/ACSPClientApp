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

import android.os.Looper;

import ru.CryptoPro.ACSPClientApp.client.LogCallback;
import ru.CryptoPro.ACSPClientApp.client.example.interfaces.IThreadExecuted;

/**
 * Служебный класс ClientThread выполняет задачу
 * в отдельном потоке.
 *
 * 29/05/2013
 *
 */
public class ClientThread extends Thread {

    /**
     * Выполняемая задача.
     */
    private IThreadExecuted executedTask = null;

    /**
     * Логгер.
     */
    private LogCallback logCallback = null;

    /**
     * Конструктор.
     *
     * @param task Выполняемая задача.
     */
    public ClientThread(LogCallback callback,
        IThreadExecuted task) {

        logCallback = callback;
        executedTask = task;
    }

    /**
     * Поточная функция. Запускает выполнение
     * задания. В случае ошибки пишет сообщение
     * в лог.
     *
     */
    @Override
    public void run() {

        /**
         * Обязательно зададим, т.к. может потребоваться
         * ввод пин-кода в окне.
         */
        Looper.getMainLooper().prepare();

        /**
         * Выполняем задачу.
         */
        executedTask.execute(logCallback);

    }

}
