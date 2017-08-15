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
package ru.CryptoPro.ACSPClientApp.util;

import android.os.AsyncTask;
import android.os.Looper;
import android.util.Log;

import ru.CryptoPro.ACSPClientApp.Constants;
import ru.CryptoPro.ACSPClientApp.client.LogCallback;
import ru.CryptoPro.JCP.JCP;
import ru.CryptoPro.JCP.tools.Array;
import ru.CryptoPro.JCSP.JCSP;

import java.security.MessageDigest;
import java.util.Calendar;

/**
 * Служебный класс ProcessorWideLoader предназначен
 * для создания нагрузки на процессор.
 *
 * 17/09/2013
 *
 */
public class ProcessorWideLoader extends
    AsyncTask<Void, Integer, Void> {

    /**
     * Логгер.
     */
    private LogCallback logCallback = null;

    /**
     * Текущая итерация.
     */
    private long currentIteration = 0;

    /**
     * Задержка между timeoutEveryNIteration задач, мсек.
     */
    private long sleepTimeout = 0;

    /**
     * Количество задач, междку которыми следует
     * выполнять задержку.
     */
    private long timeoutEveryNIteration = 0;

    /**
     * Дата запуска.
     */
    private long startTime = Calendar.getInstance()
        .getTimeInMillis();

    /**
     * Флаг состояния потока выполнения.
     * False - активный.
     */
    private volatile boolean cancelled = false;

    /**
     * Конструктор.
     *
     * @param logger Логгер.
     * @param timeout Задержка между howOftenSleep задачами (мсек).
     * @param howOftenSleep Количество задач, между которыми
     * следует выполнять задержку timeout.
     */
    public ProcessorWideLoader(LogCallback logger, long timeout,
        long howOftenSleep) {
        logCallback = logger;
        sleepTimeout = timeout;
        timeoutEveryNIteration = howOftenSleep;
    }

    @Override
    protected Void doInBackground(Void... voids) {

        Looper.getMainLooper().prepare();

        while (!cancelled) {

            if (isCancelled()) {
                break;
            } // if

            digestIteration();
            publishProgress();

            // Засыпаем каждые N итераций.
            if (timeoutEveryNIteration > 0 && sleepTimeout > 0
                && (currentIteration % timeoutEveryNIteration == 0)) {
                try {
                    Thread.sleep(sleepTimeout);
                } catch (InterruptedException e) {
                    ;
                }
            } // if

            currentIteration++;

        } // while

        return null;
    }

    /**
     * Операция хеширования.
     *
     */
    private void digestIteration() {

        Log.i(Constants.APP_LOGGER_TAG, "*** Iteration # " +
            currentIteration + " ***");

        try {

            Log.i(Constants.APP_LOGGER_TAG, "Init digest.");
            MessageDigest md = MessageDigest.getInstance(
                JCP.GOST_DIGEST_NAME, JCSP.PROVIDER_NAME);

            Log.i(Constants.APP_LOGGER_TAG, "Compute digest.");
            byte[] digestValue = md.digest(Constants.MESSAGE.getBytes());

            Log.i(Constants.APP_LOGGER_TAG, "Convert digest to hex.");
            String hexDigestValue = Array.toHexString(digestValue);
            Log.i(Constants.APP_LOGGER_TAG, hexDigestValue);

            /* Постоянно спрашивает пароли на ключи.
            IEncryptDecryptData edExample = new ClassicEncryptDecryptExample();
            edExample.getResult(logCallback);
            */

        } catch (Exception e) {
            Log.e(Constants.APP_LOGGER_TAG, e.getMessage(), e);
        }
    }

    @Override
    protected void onCancelled() {
        cancelled = false;
    }

    @Override
    protected void onCancelled(Void result) {
        cancelled = false;
    }

    @Override
    protected void onProgressUpdate(final Integer... values) {
        long diff = (Calendar.getInstance().getTimeInMillis() - startTime);
        Log.i(Constants.APP_LOGGER_TAG, "\nIteration: " + currentIteration +
            "; after start: " + (diff / 1000));
    }

    @Override
    protected void onPostExecute(final Void result) {
        Log.i(Constants.APP_LOGGER_TAG, "Task is finished.");
    }

}
