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
package ru.CryptoPro.ACSPClientApp;

import android.app.Activity;
import android.os.Bundle;
import android.support.v4.app.Fragment;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;
import android.widget.RadioGroup;

import java.security.KeyStore;
import java.util.Enumeration;

import ru.CryptoPro.ACSPClientApp.R;
import ru.CryptoPro.JCSP.JCSP;
import ru.CryptoPro.ACSPClientApp.client.example.ChangePasswordExample;
import ru.CryptoPro.ACSPClientApp.client.example.GenKeyPairExample;
import ru.CryptoPro.ACSPClientApp.client.example.RemoveContainersExample;
import ru.CryptoPro.ACSPClientApp.client.example.interfaces.ContainerAdapter;
import ru.CryptoPro.ACSPClientApp.client.example.interfaces.IEncryptDecryptData;
import ru.CryptoPro.ACSPClientApp.client.example.interfaces.IGenKeyPairData;
import ru.CryptoPro.ACSPClientApp.client.example.interfaces.IHashData;
import ru.CryptoPro.ACSPClientApp.util.KeyStoreType;
import ru.CryptoPro.ACSPClientApp.util.ProviderServiceInfo;
import ru.CryptoPro.ACSPClientApp.util.ProviderType;

/**
 * Вкладка для примеров обращения с контейнерами.
 *
 */
public class ContainerActivity extends Fragment {

    /**
     * Поле ввода имени контейнера.
     */
    private EditText etContainerAlias = null;

    @Override
    public View onCreateView(LayoutInflater inflater,
        ViewGroup container, Bundle savedInstanceState) {

        View page = inflater.inflate(R.layout.container,
            container, false);

        etContainerAlias = (EditText) page.findViewById(R.id.etContainerName);

        // initGenKeyPairButton(page);
        initGenKeyPairButtonDH(page);
        initCreateAndChangePasswordButton(page);
        initRemoveContainerButton(page);
        initRemoveContainersButton(page);

        MainActivity.setupUI(page.findViewById(R.id.llContainerMain));

        return page;
    }

    @Override
    public void onSaveInstanceState(Bundle outState) {
        // first saving my state, so the bundle wont be empty.
        outState.putString("WORKAROUND_FOR_BUG_19917_KEY",
            "WORKAROUND_FOR_BUG_19917_VALUE");
        super.onSaveInstanceState(outState);
    }

    /**
     * Добавление обработчика в кнопку генерации пары
     * ключей на алгоритме ГОСТ 34.10-2001.
     *
     */
    /*
    private void initGenKeyPairButton(View view) {

        Button btGenKeyPair =
            (Button) view.findViewById(R.id.btGenKeyPair);

        // Генерация пары ключей.
        btGenKeyPair.setOnClickListener(new View.OnClickListener() {

            @Override
            public void onClick(View v) {

                MainActivity.getLogCallback().clear();
                MainActivity.getLogCallback().log("*** Generating key pair ***");

                // Анализ ДСЧ.
                // AsyncTask<Void, Integer, Void> processorLoader =
                //    new ProcessorWideLoader(new LogCallback(getResources(),
                //        null, null), 0, 0);
                // processorLoader.execute();

                String alias = checkContainerAlias(v, true);
                if (alias == null) {
                    return;
                } // if

                ContainerAdapter adapter = new ContainerAdapter(alias, false);
                adapter.setProviderType(ProviderType.currentProviderType());

                try {
                    ISignData genKeyPairExample = new GenKeyPairExample(adapter);
                    genKeyPairExample.getResult(MainActivity.getLogCallback());
                } catch (Exception e) {
                    MainActivity.getLogCallback().setStatusFailed();
                    Log.e(Constants.APP_LOGGER_TAG, e.getMessage(), e);
                }

                // Анализ ДСЧ.
                // processorLoader.cancel(true);

                // Выводим список контейнеров.
                ProviderServiceInfo.logKeyStoreInfo(
                    MainActivity.getLogCallback());

            }

        });
    }
    */

    /**
     * Добавление обработчика в кнопку генерации пары
     * ключей на алгоритме ГОСТ 34.10-2001 DH.
     *
     */
    private void initGenKeyPairButtonDH(View view) {

        final RadioGroup rbCAVersion = (RadioGroup) view.findViewById(R.id.rgContainerCAVersion);

        Button btGenKeyPairDH =
            (Button) view.findViewById(R.id.btGenKeyPairDH);

        // Генерация пары ключей.
        btGenKeyPairDH.setOnClickListener(new View.OnClickListener() {

            @Override
            public void onClick(View v) {

                MainActivity.getLogCallback().clear();
                MainActivity.getLogCallback().log("*** Generating key pair (DH) ***");

                String alias = checkContainerAlias(v, true);
                if (alias == null) {
                    return;
                } // if

                ContainerAdapter adapter = new ContainerAdapter(alias, true);
                adapter.setProviderType(ProviderType.currentProviderType());

                IGenKeyPairData.CAType caType = IGenKeyPairData.CAType.ca14;

                switch (rbCAVersion.getCheckedRadioButtonId()) {
                    case R.id.rbContainerCA15: caType = IGenKeyPairData.CAType.ca15; break;
                    /** JCP-387: пока нет внещнего тестового УЦ 2.0 - заблокировано!
                    case R.id.rbContainerCA20: caType = IGenKeyPairData.CAType.ca20; break;
                    */
                } // if

                try {

                    IGenKeyPairData genKeyPairDhExample = new GenKeyPairExample(
                        adapter, caType, ContainerActivity.this.getActivity());

                    genKeyPairDhExample.setDefaultPassword("123".toCharArray()); // Для УЦ 2.0
                    genKeyPairDhExample.getResult(MainActivity.getLogCallback());

                } catch (Exception e) {
                    MainActivity.getLogCallback().setStatusFailed();
                    Log.e(Constants.APP_LOGGER_TAG, e.getMessage(), e);
                }

                // Выводим список контейнеров.
                ProviderServiceInfo.logKeyStoreInfo(
                    MainActivity.getLogCallback());

            }

        });
    }

    /**
     * Добавление обработчика в кнопку смены пароля
     * путем копирования созданного контейнера.
     *
     */
    private void initCreateAndChangePasswordButton(View view) {

        Button btChangePassAndCopy =
            (Button) view.findViewById(R.id.btCopyContainer);

        // Копирование контейнера.
        btChangePassAndCopy.setOnClickListener(new View.OnClickListener() {

            @Override
            public void onClick(View v) {

                MainActivity.getLogCallback().clear();
                MainActivity.getLogCallback().log("*** Creating container, changing " +
                    "password by copying ***");

                String alias = checkContainerAlias(v, true);
                if (alias == null) {
                    return;
                } // if

                ContainerAdapter adapter = new ContainerAdapter(alias, true);
                adapter.setProviderType(ProviderType.currentProviderType());

                try {
                    IHashData changePasswordExample = new ChangePasswordExample(adapter);
                    changePasswordExample.getResult(MainActivity.getLogCallback());
                } catch (Exception e) {
                    MainActivity.getLogCallback().setStatusFailed();
                    Log.e(Constants.APP_LOGGER_TAG, e.getMessage(), e);
                }

                // Выводим список контейнеров.
                ProviderServiceInfo.logKeyStoreInfo(
                    MainActivity.getLogCallback());
            }

        });
    }

    /**
     * Добавление обработчика в кнопку удаления
     * созданного ранее контейнера (кроме контейнеров
     * из ресурсов).
     *
     */
    private void initRemoveContainerButton(View view) {

        Button btRemoveContainer =
            (Button) view.findViewById(R.id.btRemoveContainer);

        // Удаление сгенерированного ранее контейнера.
        btRemoveContainer.setOnClickListener(new View.OnClickListener() {

            @Override
            public void onClick(View v) {

                String alias = checkContainerAlias(v, false);
                if (alias == null) {
                    return;
                } // if

                MainActivity.getLogCallback().clear();
                MainActivity.getLogCallback().log("*** Removing one container '" +
                    alias + "' ***");

                ContainerAdapter adapter = new ContainerAdapter(alias, false);
                adapter.setProviderType(ProviderType.currentProviderType());

                try {

                    IEncryptDecryptData removeContainersExample = new RemoveContainersExample(adapter);
                    removeContainersExample.getResult(MainActivity.getLogCallback());

                } catch (Exception e) {
                    MainActivity.getLogCallback().setStatusFailed();
                    Log.e(Constants.APP_LOGGER_TAG, e.getMessage(), e);
                }

                // Выводим список контейнеров.
                ProviderServiceInfo.logKeyStoreInfo(
                    MainActivity.getLogCallback());

            }

        });

    }

    /**
     * Добавление обработчика в кнопку удаления
     * созданных ранее контейнеров (кроме контейнеров
     * из ресурсов).
     *
     */
    private void initRemoveContainersButton(View view) {

        Button btRemoveContainers =
            (Button) view.findViewById(R.id.btRemoveContainers);

        // Удаление сгенерированных ранее контейнеров.
        btRemoveContainers.setOnClickListener(new View.OnClickListener() {

            @Override
            public void onClick(View v) {

                MainActivity.getLogCallback().clear();
                MainActivity.getLogCallback().log("*** Removing all containers ***");

                ContainerAdapter adapter = new ContainerAdapter(null, false);
                adapter.setProviderType(ProviderType.currentProviderType());

                try {

                    IEncryptDecryptData removeContainersExample = new RemoveContainersExample(adapter);
                    removeContainersExample.getResult(MainActivity.getLogCallback());

                } catch (Exception e) {
                    MainActivity.getLogCallback().setStatusFailed();
                    Log.e(Constants.APP_LOGGER_TAG, e.getMessage(), e);
                }

                // Выводим список контейнеров.
                ProviderServiceInfo.logKeyStoreInfo(
                    MainActivity.getLogCallback());

            }

        });

    }

    /**
     * Проверка алиаса, существования контейнера с таким аласом.
     *
     * @param v Источник события.
     * @param checkExistence True, если нужно проверить существование
     * алиаса.
     * @return алиас в случае успешной проверки, null в обратном случае.
     */
    private String checkContainerAlias(View v, boolean checkExistence) {

        // Проверка алиаса.
        CharSequence aliasSequence = etContainerAlias.getText();
        if (aliasSequence == null || aliasSequence.length() == 0) {
            MainActivity.errorMessage((Activity)v.getContext(),
                getString(R.string.ContainerContainerNameIsNull), false, false);
            return null;
        } // if

        // Проверка существования алиаса.
        if (checkExistence) {

            try {

                KeyStore keyStore = KeyStore.getInstance(
                    KeyStoreType.currentType(), JCSP.PROVIDER_NAME);
                keyStore.load(null, null);

                Enumeration<String> aliases = keyStore.aliases();
                while (aliases.hasMoreElements()) {

                    String alias = aliases.nextElement();

                    // Если существует, то выход с ошибкой.
                    if (alias.equals(aliasSequence.toString())) {
                        MainActivity.errorMessage((Activity) v.getContext(),
                        getString(R.string.ContainerContainerNameExists), false, false);
                        return null;
                    } // if

                } // while

            } catch (Exception e) {
                Log.e(Constants.APP_LOGGER_TAG, e.getMessage(), e);
                return null;
            }

        } // if

        return aliasSequence.toString();

    }

}
