/**
 * $RCSfileExamplesActivity.java,v $
 * version $Revision: 36379 $
 * created 01.12.2014 18:41 by Yevgeniy
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
package ru.CryptoPro.ACSPClientApp;

import android.os.Bundle;
import android.support.v4.app.Fragment;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.Spinner;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.File;
import java.io.FileInputStream;
import java.lang.reflect.Constructor;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;
import java.util.Observable;
import java.util.Observer;

import ru.CryptoPro.ACSPClientApp.R;
import ru.CryptoPro.JCP.JCP;
import ru.CryptoPro.JCSP.JCSP;
import ru.CryptoPro.JCSP.support.BKSTrustStore;
import ru.CryptoPro.ACSPClientApp.client.example.InstallCAdESTestTrustCertExample;
import ru.CryptoPro.ACSPClientApp.client.example.interfaces.ContainerAdapter;
import ru.CryptoPro.ACSPClientApp.client.example.interfaces.ICAdESData;
import ru.CryptoPro.ACSPClientApp.client.example.interfaces.IHashData;
import ru.CryptoPro.ACSPClientApp.client.example.interfaces.RemoteConnectionInfo;
import ru.CryptoPro.ACSPClientApp.util.AlgorithmSelector;
import ru.CryptoPro.ACSPClientApp.util.KeyStoreType;
import ru.CryptoPro.ACSPClientApp.util.ProviderType;

/**
 *  Вкладка для выполнения всех примеров с использованием
 *  контейнеров.
 *
 * @author Copyright 2004-2014 Crypto-Pro. All rights reserved.
 * @.Version
 */
public class ExamplesActivity extends Fragment implements
    AdapterView.OnItemSelectedListener, Observer {

    /**
     * Пакет с примерами.
     */
    private static final String EXAMPLE_PACKAGE = "ru.CryptoPro.ACSPClientApp.client.example.";

    /**
     * Флаг, означающий, установлены ли программно корневые
     * сертификаты для примеров CAdES подписи.
     */
    private boolean cAdESCAInstalled = false;

    /**
     * Список имен классов примеров.
     */
    private String[] exampleClassesToBeExecuted = null;

    /**
     * Адаптер списка алиасов контейнеров.
     */
    private ArrayAdapter<String> containerAliasAdapter = null;

    /**
     * Список алиасов контейнеров.
     */
    private List<String> aliasesList = new ArrayList<String>();

    /**
     * Список примеров, требующих записанный в поле пароль.
     */
    private String[] examplesRequireWrittenPin = null;

    /**
     * Список примеров, требующих контейнер получателя/сервера.
     */
    private String[] examplesRequireServerContainer = null;

    /**
     * Списки примеров и контейнеров.
     */
    private Spinner spExamplesList = null, spClientList = null, spServerList = null;

    /**
     * Поле для ввода пина к контейнеру с ключом подписи или обмена.
     */
    private EditText etClientPin = null;

    /**
     * Управление установкой сертификатов УЦ.
     */
    private CheckBox cbInstallCA = null;

    @Override
    public View onCreateView(LayoutInflater inflater,
        ViewGroup container, Bundle savedInstanceState) {

        View page = inflater.inflate(R.layout.examples, container, false);

        examplesRequireWrittenPin = getResources().getStringArray(R.array.ExampleRequireWrittenPin);
        examplesRequireServerContainer = getResources().getStringArray(R.array.ExampleRequireServerContainer);
        exampleClassesToBeExecuted = getResources().getStringArray(R.array.ExampleClasses);

        // Список примеров.

        spExamplesList = (Spinner) page.findViewById(R.id.spExamplesList);

        // Создаем ArrayAdapter для использования строкового массива
        // и способа отображения объекта.
        ArrayAdapter<CharSequence> examplesAdapter =
            ArrayAdapter.createFromResource(page.getContext(),
                R.array.ExamplesDescription, android.R.layout.simple_spinner_item);

        // Способ отображения.

        examplesAdapter.setDropDownViewResource(
            android.R.layout.simple_spinner_dropdown_item);

        spExamplesList.setAdapter(examplesAdapter);
        spExamplesList.setOnItemSelectedListener(this);

        // Список клиентских алиасов.

        spClientList = (Spinner) page.findViewById(R.id.spExamplesClientList);

        // Создаем ArrayAdapter для использования строкового массива
        // и способа отображения объекта.

        aliasesList = aliases(KeyStoreType.currentType(),
            ProviderType.currentProviderType());

        containerAliasAdapter = new ArrayAdapter<String>(
            page.getContext(), android.R.layout.simple_spinner_item, aliasesList);

        // Способ отображения.

        containerAliasAdapter.setDropDownViewResource(
            android.R.layout.simple_spinner_dropdown_item);

        spClientList.setAdapter(containerAliasAdapter);
        spClientList.setOnItemSelectedListener(this);

        // Список серверных алиасов.

        spServerList = (Spinner) page.findViewById(R.id.spExamplesServerList);
        spServerList.setAdapter(containerAliasAdapter);
        spServerList.setOnItemSelectedListener(this);

        // Поле ввода пинов.

        etClientPin = (EditText) page.findViewById(R.id.etExamplesClientPassword);

        // Кнопка выполнения.

        initExecuteButton(page);

        // Управление устновкой сертификатов УЦ.

        cbInstallCA = (CheckBox) page.findViewById(R.id.cbExamplesInstallCA);
        MainActivity.setupUI(page.findViewById(R.id.llExamplesMain));

        return page;
    }

    /**
     * Установка сертификатов для CAdES путем выполнения примера
     * установки. Необходима, т.к. неизвестно, установил ли клиент
     * сертификаты в Settings->Security (android >= 4.0).
     *
     */
    private void checkCAdESCACertsAndInstall() {

        // Установка корневых сертификатов для CAdES примеров.
        if (!cAdESCAInstalled) {

            String message = String.format(getString(R.string.ExamplesInstallCAdESCAWarning),
                "InstallCAdESTestTrustCertExample");

            ContainerAdapter adapter = new ContainerAdapter(null, false);
            adapter.setProviderType(ProviderType.currentProviderType());
            adapter.setResources(getResources());

            try {

                ICAdESData installRootCert = new InstallCAdESTestTrustCertExample(adapter);

                // Если сертификаты не установлены, сообщаем об
                // этом и устанавливаем их.
                if (!installRootCert.isAlreadyInstalled()) {

                    // Предупреждение о выполнении установки.
                    MainActivity.errorMessage(getActivity(), message, false, false);

                    MainActivity.getLogCallback().clear();
                    MainActivity.getLogCallback().log("*** Forced installation of CA certificates (CAdES) ***");

                    // Установка.
                    installRootCert.getResult(MainActivity.getLogCallback());

                } // if

                cAdESCAInstalled = true;

            } catch (Exception e) {
                MainActivity.getLogCallback().setStatusFailed();
                Log.e(Constants.APP_LOGGER_TAG, e.getMessage(), e);
            }

        }

    }

    @Override
    public void onItemSelected(AdapterView<?> adapterView, View view, int i, long l) {

        ProviderType.currentProviderType();

        switch (adapterView.getId()) {

            case R.id.spExamplesList: {

                // Выбранный пример.
                int selectedExample = adapterView.getSelectedItemPosition();
                String exampleClass = exampleClassesToBeExecuted[selectedExample];

                // Если пример не требует ввода пина, то блокируем поле ввода пина.
                // Большинство примеров вообще не нуждается в указании пароля, т.к.
                // он будет запрошен в специальном окне. Только TLS примеры требуют
                // клиентский пароль.
                List<String> exampleRWPClasses = Arrays.asList(examplesRequireWrittenPin);

                if (!exampleRWPClasses.contains(exampleClass)) {
                    etClientPin.setText("");
                    etClientPin.setEnabled(false);
                } // if
                else {
                    etClientPin.setEnabled(true);
                    etClientPin.setSelected(true);
                    etClientPin.requestFocus();
                } // else

                // Если пример требует указания алиаса и пина получателя, то
                // разблокируем поле ввода алиаса и пина получателя. Например,
                // примеры шифрования нуждаются в них.

                List<String> exampleRSCClasses = Arrays.asList(examplesRequireServerContainer);
                if (!exampleRSCClasses.contains(exampleClass)) {
                    spServerList.setEnabled(false);
                } // if
                else {
                    spServerList.setEnabled(true);
                } // else

                // Флаг, означающий, что выполняется CAdES пример.
                boolean isCAdESExampleExecuting =
                    exampleClass.contains("CAdESBES") ||
                    exampleClass.contains("CAdESXLT1");

                // Выполняем установку корневых сертификатов для CAdES
                // примеров, если она не была уже произведена. Фактически,
                // перед каждым первым выполнением CAdES примера после запуска
                // приложения.

                if (cbInstallCA.isChecked() && isCAdESExampleExecuting) {
                    checkCAdESCACertsAndInstall();
                } // if

            }
            break;

            case R.id.spExamplesClientList: {
                etClientPin.setText(""); // очистка
            }
            break;

        } // switch

    }

    @Override
    public void onNothingSelected(AdapterView<?> adapterView) {
        ;
    }

    /**
     * Выполнение примера.
     *
     * @param i Номер примера.
     */
    private void executeExample(int i) {

        String exampleDescription = (String) spExamplesList.getItemAtPosition(i);
        String exampleClassName = exampleClassesToBeExecuted[i];

        MainActivity.getLogCallback().clear();
        MainActivity.getLogCallback().log("*** " + exampleDescription + " (" + exampleClassName + ") ***");

        try {

            // Поиск примера.

            final String fullExampleClassName = EXAMPLE_PACKAGE + exampleClassName;
            Class exampleClass = Class.forName(fullExampleClassName);
            Constructor exampleConstructor = exampleClass.getConstructor(ContainerAdapter.class);

            // Сборка универсального ContainerAdapter.

            // Клиентский контейнер (подписант, отправитель, TLS).
            String clientAlias = (String) spClientList.getSelectedItem();
            CharSequence clientPasswordSequence = etClientPin.getText();
            char[] clientPassword = null;

            if (clientPasswordSequence != null) {
                clientPassword = clientPasswordSequence.toString().toCharArray();
            } // if

            // Контейнер получателя.
            String serverAlias = (String) spServerList.getSelectedItem();

            // Настройки примера.

            ContainerAdapter adapter = new ContainerAdapter(clientAlias, clientPassword,
                serverAlias, null);

            adapter.setProviderType(ProviderType.currentProviderType());
            adapter.setResources(getResources()); // для примера установки сертификатов

            boolean clientAuth = Arrays.asList(examplesRequireWrittenPin).contains(exampleClassName); // для TLS примеров

            // Используется общее для всех хранилище корневых
            // сертификатов cacerts.

            final String trustStorePath = getActivity().getApplicationInfo().dataDir +
                File.separator + BKSTrustStore.STORAGE_DIRECTORY + File.separator +
                    BKSTrustStore.STORAGE_FILE_TRUST;

            MainActivity.getLogCallback().log("Example trust store: " + trustStorePath);

            adapter.setTrustStoreProvider(BouncyCastleProvider.PROVIDER_NAME);
            adapter.setTrustStoreType(BKSTrustStore.STORAGE_TYPE);

            adapter.setTrustStoreStream(new FileInputStream(trustStorePath));
            adapter.setTrustStorePassword(BKSTrustStore.STORAGE_PASSWORD);

            // Настройки для подключения к удаленному хосту в зависимости
            // от алгоритма (чтобы охватить по возможности все алгоритмы)
            // для TLS примеров, примера построения цепочки и т.п.

            switch (adapter.getProviderType()) {

                case pt2001: {

                    // Для TLS примеров.

                    if (clientAuth) {
                        adapter.setConnectionInfo(RemoteConnectionInfo.host2001ClientAuth);
                    } // if
                    else {
                        adapter.setConnectionInfo(RemoteConnectionInfo.host2001NoAuth);
                    } // else

                }
                break;

                case pt2012Short: {

                    // Для TLS примеров.

                    if (clientAuth) {
                        adapter.setConnectionInfo(RemoteConnectionInfo.host2012256ClientAuth);
                    } // if
                    else {
                        adapter.setConnectionInfo(RemoteConnectionInfo.host2012256NoAuth);
                    } // else

                }
                break;

                case pt2012Long: {

                    // Для TLS примеров.

                    if (clientAuth) {
                        adapter.setConnectionInfo(RemoteConnectionInfo.host2012512ClientAuth);
                    } // if
                    else {
                        adapter.setConnectionInfo(RemoteConnectionInfo.host2012512NoAuth);
                    } // else

                }
                break;

            } // switch

            // Выполнение примера.

            IHashData exampleImpl = (IHashData) exampleConstructor.newInstance(adapter);
            exampleImpl.getResult(MainActivity.getLogCallback());

        } catch (Exception e) {
            MainActivity.getLogCallback().setStatusFailed();
            Log.e(Constants.APP_LOGGER_TAG, e.getMessage(), e);
        }

    }

    /**
     * Загрузка тех алиасов, которые находятся в хранилище storeType
     * с алгоритмом, сооветствующим типу providerType.
     *
     * @param storeType Тип контейнера.
     * @param providerType Тип провайдера.
     */
    private static List<String> aliases(String storeType,
        AlgorithmSelector.DefaultProviderType providerType) {

        List<String> aliasesList = new ArrayList<String>();

        try {

            KeyStore keyStore = KeyStore.getInstance(storeType, JCSP.PROVIDER_NAME);
            keyStore.load(null, null);

            Enumeration<String> aliases = keyStore.aliases();

            // Подбор алиасов.
            while (aliases.hasMoreElements()) {

                String alias = aliases.nextElement();
                PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, null);

                String privateKeyAlgorithm = privateKey.getAlgorithm();

                if (providerType.equals(AlgorithmSelector.DefaultProviderType.pt2001) &&
                    (privateKeyAlgorithm.equalsIgnoreCase(JCP.GOST_EL_DEGREE_NAME) ||
                    privateKeyAlgorithm.equalsIgnoreCase(JCP.GOST_EL_DH_NAME))) {
                    aliasesList.add(alias);
                } // if
                else if (providerType.equals(AlgorithmSelector.DefaultProviderType.pt2012Short) &&
                    (privateKeyAlgorithm.equalsIgnoreCase(JCP.GOST_EL_2012_256_NAME) ||
                    privateKeyAlgorithm.equalsIgnoreCase(JCP.GOST_DH_2012_256_NAME))) {
                    aliasesList.add(alias);
                } // else
                else if (providerType.equals(AlgorithmSelector.DefaultProviderType.pt2012Long) &&
                    (privateKeyAlgorithm.equalsIgnoreCase(JCP.GOST_EL_2012_512_NAME) ||
                    privateKeyAlgorithm.equalsIgnoreCase(JCP.GOST_DH_2012_512_NAME))) {
                    aliasesList.add(alias);
                } // else

            } // while

        }
        catch (Exception e) {
            Log.e(Constants.APP_LOGGER_TAG, e.getMessage(), e);
        }

        return aliasesList;

    }

    /**
     * Обновление списков контейнеров.
     *
     * @param observable null.
     * @param data null.
     */
    @Override
    public void update(Observable observable, Object data) {

        // Обновляем список контейнеров.

        aliasesList = aliases(KeyStoreType.currentType(),
            ProviderType.currentProviderType());

        containerAliasAdapter.clear();
        containerAliasAdapter.addAll(aliasesList);
        containerAliasAdapter.notifyDataSetChanged();

    }

    /**
     * Добавление обработчика в кнопку выполнения примера.
     *
     */
    private void initExecuteButton(View view) {

        Button btExecuteButton =
            (Button) view.findViewById(R.id.btExamplesExecute);

        // Выполнение примера.
        btExecuteButton.setOnClickListener(new View.OnClickListener() {

            @Override
            public void onClick(View v) {
                int exampleIndex = spExamplesList.getSelectedItemPosition();
                executeExample(exampleIndex);
            }

        });
    }

}
