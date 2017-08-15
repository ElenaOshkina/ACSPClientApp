/**
 * Copyright 2004-2015 Crypto-Pro. All rights reserved.
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
import android.content.Intent;
import android.os.Bundle;
import android.support.v4.app.Fragment;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.RadioGroup;
import android.widget.Spinner;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import ru.CryptoPro.ACSPClientApp.R;
import ru.CryptoPro.CAdES.CAdESType;
import ru.CryptoPro.JCP.tools.Array;
import ru.CryptoPro.ACSPClientApp.client.example.interfaces.IACSPIntent;

/**
 * Вкладка для вызова различных интентов из Android
 * CSP провайдера.
 */
public class ACSPIntentActivity extends Fragment implements IACSPIntent {

    /**
     * Путь к файлу подписи для интента проверки подписи.
     */
    private static String FILE_SIGNATURE = null;

    @Override
    public View onCreateView(final LayoutInflater inflater,
        ViewGroup container, Bundle savedInstanceState) {

        View page = inflater.inflate(R.layout.acsp_intent, container, false);

        // Временный файл с подписью для создания и последующей проверки.
        FILE_SIGNATURE = getActivity().getFilesDir().getAbsolutePath() +
            File.separator + "signature.bin";

        // 1. Список возможных источников сертификатов (путь
        // к файлу, содержимое).

        final ArrayAdapter<CharSequence> certificateSourceAdapter =
            ArrayAdapter.createFromResource(getActivity(), R.array.IntentsIntentCertSourceList,
                    android.R.layout.simple_list_item_1);

        final Spinner spCertificateSource = (Spinner) page.findViewById(R.id.spIntentsCertificateSource);
        spCertificateSource.setAdapter(certificateSourceAdapter);

        // 2. Список видов хранилищ (Personal, Intermediate,
        // Trust, AddressBook).

        final ArrayAdapter<CharSequence> storageTypeAdapter =
            ArrayAdapter.createFromResource(getActivity(), R.array.IntentsStorageList,
                android.R.layout.simple_list_item_1);

        final Spinner spStorage = (Spinner) page.findViewById(R.id.spIntentsStorage);
        spStorage.setAdapter(storageTypeAdapter);

        // 3. Алиас объекта при построении цепочки.

        final EditText etObjectAlias = (EditText) page.findViewById(R.id.etIntentsObjectAlias);

        /*
        // 4. Чекбокс для использования цепочки сертификатов
        // вместо единичного сертификата.
        // TODO: временная проверка
        final CheckBox cbUseCertChain = (CheckBox) page.findViewById(R.id.cbIntentsUseCertChain);
        */

        // 5. Кнопка копирования контейнера с диска.

        final Button btCopyContainer = (Button) page.findViewById(R.id.btIntentsCopyContainer);
        btCopyContainer.setOnClickListener(new View.OnClickListener() {

            @Override
            public void onClick(View view) {

                MainActivity.getLogCallback().clear();
                logCalling(INTENT_NAME_COPY_CONTAINER);

                final Intent intent = new Intent(INTENT_NAME_COPY_CONTAINER);
                startActivityForResult(intent, INTENT_ID_COPY_CONTAINER);

            }

        });

        // 6. Класс обработки нажатия на кнопку установки
        // сертификата (цепочки) в контейнер или хранилище.

        class ButtonOnClickListener implements View.OnClickListener {

            @Override
            public void onClick(View view) {

                final String storage = (String) spStorage.getSelectedItem();
                final int storageIndex = spStorage.getSelectedItemPosition() + 1000;

                final int selectedItem = spCertificateSource.getSelectedItemPosition();

                switch (selectedItem) {

                    /*
                    // TODO: временная проверка
                    // Установка сертификата (цепочки) из буфера (например,
                    // прочитали из ресурса).
                    case 1: { // certificate content

                        // Какой-то файл сертификата или цепочки.
                        final InputStream certContentStream = cbUseCertChain.isChecked()
                            ? getResources().openRawResource(R.raw.tmp_cert_chain)
                            : getResources().openRawResource(R.raw.tmp_cert);

                        final byte[] certContentBin = readDataFromStream(certContentStream);
                        if (certContentBin.length > 0) {
                            installCertificate(storage, certContentBin, null, null,
                                INTENT_ID_INSTALL_CERT + storageIndex);
                        } // if
                        else {
                            MainActivity.getLogCallback().log("Certificate content not found!");
                        } // else

                    }
                    break;
                    */

                    /*
                    // TODO: временная проверка
                    // Установка сертификата (цепочки) по известному пути.
                    case 2: { // certificate path

                        // Какой-то файл сертификата или цепочки.
                        final String certPath = cbUseCertChain.isChecked()
                            ? TMP_CERT_CHAIN_FILE : TMP_CERT_FILE;

                        installCertificate(storage, null, certPath, null, INTENT_ID_INSTALL_CERT + storageIndex);

                    }
                    break;
                    */

                    // Установка сертификата (цепочки) с выбором файла
                    // в самой activity.
                    default: {
                        installCertificate(storage, null, null, null, INTENT_ID_INSTALL_CERT + storageIndex);
                    }

                } // switch

            }

        }

        // 7. Кнопка установки сертификата в контейнер или
        // хранилище сертификатов.

        final Button btInstallCert =
            (Button) page.findViewById(R.id.btIntentsInstallCert);
        btInstallCert.setOnClickListener(new ButtonOnClickListener());

        // 8. Параметры подписи (CAdES-BES, CAdES-X Long Type 1):
        // данные для подписи (совмещенной), тип подписи,
        // совмещенная или отделенная, метод проверки.

        final EditText etBuildContainerAlias = (EditText) page.findViewById(R.id.etIntentsBuildContainerAlias);
        final EditText etDataToSign = (EditText) page.findViewById(R.id.etIntentsDataToSign);

        final CheckBox cbDetached = (CheckBox) page.findViewById(R.id.cbIntentsDetached);
        final CheckBox cbCAdESLong = (CheckBox) page.findViewById(R.id.cbIntentsCadesLong);

        final CheckBox cbVerifyAsDefault = (CheckBox) page.findViewById(R.id.cbIntentsVerifyAsDefault);

        // 9. Кнопка подписи данных.

        final Button btSignData = (Button) page.findViewById(R.id.btIntentsSignData);

        btSignData.setOnClickListener(new View.OnClickListener() {

            @Override
            public void onClick(View view) {

                MainActivity.getLogCallback().clear();
                logCalling(INTENT_NAME_SIGN_DATA);

                final Intent intent = new Intent(INTENT_NAME_SIGN_DATA);

                // 1. Алиас контейнера.

                final String containerAlias = String.valueOf(etBuildContainerAlias.getText());

                // Если не передать, то будет предложено указать в самой activity.
                if (containerAlias != null && !containerAlias.isEmpty()) {
                    intent.putExtra("containerAlias", containerAlias); // проверка на поиск
                } // if

                // 2. Совмещенная ли подпись.

                final boolean attached = !cbDetached.isChecked();

                // Если не передать, то будет предложено указать в самой activity.
                intent.putExtra("attached", attached); // проверка на attached

                // 3. Данные для подписи.

                final String dataToSign = String.valueOf(etDataToSign.getText());

                // Если не передать, то будет предложено указать файл
                // с данными в самой activity.
                if (dataToSign != null && !dataToSign.isEmpty()) {
                    intent.putExtra("data", dataToSign.getBytes()); // проверка на передачу данных
                } // if

                // 4. Тип подписи (CAdES-BES и CAdES-X Long Type 1).

                final boolean cAdESLong = cbCAdESLong.isChecked();

                // Если не передать, то будет предложено указать в самой activity.
                intent.putExtra("type", cAdESLong
                    ? CAdESType.CAdES_X_Long_Type_1
                    : CAdESType.CAdES_BES);

                startActivityForResult(intent, INTENT_ID_SIGN_DATA);

            }

        });

        // 10. Кнопка построения цепочки сертификатов (в
        // зависимости от вида хранилища).

        final Button btBuildChain = (Button) page.findViewById(R.id.btIntentsBuildChain);

        btBuildChain.setOnClickListener(new View.OnClickListener() {

            @Override
            public void onClick(View view) {

                MainActivity.getLogCallback().clear();
                logCalling(INTENT_NAME_BUILD_CHAIN);

                final String objectAlias = String.valueOf(etObjectAlias.getText());
                final String storage = (String) spStorage.getSelectedItem(); // вид хранилища

                final Intent intent = new Intent(INTENT_NAME_BUILD_CHAIN);

                // Если не передать, то будет использоваться Personal.
                intent.putExtra("storage", storage);

                // Если не передать, то будет предложено указать в самой activity.
                if (objectAlias != null && !objectAlias.isEmpty()) {
                    intent.putExtra("objectAlias", objectAlias); // проверка на выбор по алиасу
                } // if

                startActivityForResult(intent, INTENT_ID_BUILD_CHAIN);

            }

        });

        // 11. Кнопка проверки подписи (как PKCS7 с проверкой цепочки,
        // CAdES-BES или CAdES-X Long Type 1).

        final Button btVerifySign = (Button) page.findViewById(R.id.btIntentsVerifySignature);

        btVerifySign.setOnClickListener(new View.OnClickListener() {

            @Override
            public void onClick(View view) {

                MainActivity.getLogCallback().clear();
                logCalling(INTENT_NAME_VERIFY_SIGN);

                byte[] signature = null;

                try {
                    signature = Array.readFile(FILE_SIGNATURE);
                } catch (IOException e) {
                    Log.e(Constants.APP_LOGGER_TAG, e.getMessage(), e);
                }

                final Intent intent = new Intent(INTENT_NAME_VERIFY_SIGN);

                // 1. Передача подписи для проверки.

                // Если не передать, то будет предложено указать файл
                // с подписью в самой activity.
                if (signature != null) {
                    intent.putExtra("signature", signature);
                } // if

                // 2. Совмещенная ли подпись.

                final boolean attached = !cbDetached.isChecked();

                // Если не передать, то будет предложено указать в самой activity.
                intent.putExtra("attached", attached); // проверка на attached

                // 3. Данные для подписи.

                final String dataToSign = String.valueOf(etDataToSign.getText());

                // Если не передать, то будет предложено указать файл с
                // данными в самой activity.
                if (dataToSign != null && !dataToSign.isEmpty()) {
                    intent.putExtra("data", dataToSign.getBytes()); // проверка на передачу данных
                } // if

                // 4. Тип подписи.

                final boolean cAdESLong = cbCAdESLong.isChecked();

                // Если не провеверяем по умолчанию, то задаем тип.
                if (!cbVerifyAsDefault.isChecked()) {

                    // Если не передать, то будет предложено указать в самой activity.
                    intent.putExtra("type", cAdESLong
                        ? CAdESType.CAdES_X_Long_Type_1
                        : CAdESType.CAdES_BES);

                } // if

                startActivityForResult(intent, INTENT_ID_VERIFY_SIGN);

            }

        });

        // 12. Параметры создания контейнера.

        final EditText etContainerType = (EditText) page.findViewById(R.id.etIntentsContainerType);
        final EditText etGenContainerAlias = (EditText) page.findViewById(R.id.etIntentsGenContainerAlias);

        final RadioGroup rgKeyAlgorithmGroup = (RadioGroup) page.findViewById(R.id.rgIntentsKeyAlgorithm);
        final CheckBox cbKeyExchange = (CheckBox) page.findViewById(R.id.cbIntentsExchange);

        final CheckBox cbCertSelfSigned = (CheckBox) page.findViewById(R.id.cbIntentsSelfSigned);

        // Версии УЦ.
        final ArrayAdapter<CharSequence> caVersionAdapter =
            ArrayAdapter.createFromResource(getActivity(), R.array.IntentsCAVersionList,
                android.R.layout.simple_list_item_1);

        final Spinner spCAVersion = (Spinner) page.findViewById(R.id.spIntentsCAVersion);
        spCAVersion.setAdapter(caVersionAdapter);

        // Адреса УЦ.
        final ArrayAdapter<CharSequence> caAddressAdapter =
            ArrayAdapter.createFromResource(getActivity(), R.array.IntentsCAAddressList,
                android.R.layout.simple_list_item_1);

        final Spinner spCAAddress = (Spinner) page.findViewById(R.id.spIntentsCAAddress);
        spCAAddress.setAdapter(caAddressAdapter);

        // 12. Кнопка создания контейнера.

        final Button btGenerate = (Button) page.findViewById(R.id.btIntentsGenerate);

        btGenerate.setOnClickListener(new View.OnClickListener() {

            @Override
            public void onClick(View view) {

                MainActivity.getLogCallback().clear();
                logCalling(INTENT_NAME_CREATE_CONTAINER);

                final Intent intent = new Intent(INTENT_NAME_CREATE_CONTAINER);

                // Параметры будущего контейнера. Если не передать какие-то
                // данные, то будет предложено указать их в самой activity.

                final String containerType = String.valueOf(etContainerType.getText());
                final String containerAlias = String.valueOf(etGenContainerAlias.getText());

                int keyAlgorithmIndex;
                switch (rgKeyAlgorithmGroup.getCheckedRadioButtonId()) {

                    case R.id.rbIntentsKA2012256: keyAlgorithmIndex = 1; break;
                    case R.id.rbIntentsKA2012512: keyAlgorithmIndex = 2; break;
                    default: keyAlgorithmIndex = 0; break;

                } // switch

                final boolean isExchange = cbKeyExchange.isChecked();
                final boolean isSelfSigned = cbCertSelfSigned.isChecked();

                final int caVersionIndex = spCAVersion.getSelectedItemPosition();
                final String caAddress = String.valueOf(spCAAddress.getSelectedItem());

                if (containerType != null && !containerType.isEmpty()) {
                    intent.putExtra("containerType", containerType);
                } // if

                if (containerAlias != null && !containerAlias.isEmpty()) {
                    intent.putExtra("containerAlias", containerAlias);
                } // if

                intent.putExtra("keyAlgorithm", keyAlgorithmIndex);
                intent.putExtra("exchange", isExchange);

                if (!isSelfSigned) {

                    if (caAddress != null && !caAddress.isEmpty()) {
                        intent.putExtra("caVersion", caVersionIndex);
                        intent.putExtra("caAddress", caAddress);
                    } // if

                } // if

                startActivityForResult(intent, INTENT_ID_CREATE_CONTAINER);


            }

        });

        return page;

    }

    /**
     * Установка сертификата (цепочки) в контейнер или хранилище
     * сертификатов с возможностью передачи сертификата разными
     * способами.
     *
     * @param storage Вид хранилища (контейнер, хранилище сертификатов).
     * @param certContent Содержимое сертификата. Может быть null.
     * @param certPath Путь к файлу сертификата. Может быть null.
     * @param alias Алиас контейнера или сертификата в хранилище.
     * Может быть null.
     * @param requestCode Код запроса.
     */
    private void installCertificate(String storage, byte[] certContent,
        String certPath, String alias, int requestCode) {

        MainActivity.getLogCallback().clear();
        logCalling(INTENT_NAME_INSTALL_CERT);

        final Intent intent = new Intent(INTENT_NAME_INSTALL_CERT);

        // Вид хранилища:
        // 1) Personal - личные (контейнеры) (он же по умолчанию,
        // если не передать ничего), для контейнеров;
        // 2) Intermediate - промежуточные сертификаты;
        // 3) Trust - корневые сертификаты;
        // 4) AddressBook - получатели.

        intent.putExtra("storage", storage);

        // I. ИСПОЛЬЗОВАНИЕ АЛИАСА (контейнера или сертификата)
        // Можно передать алиас containerAlias:
        // алиас некоего выбранного контейнера для установки в него
        // сертификата (цепочки), если необходимо выбрать его -
        // контейнер - в списке контейнеров. Если не передать
        // ничего, то алиас кнтейнера можно будет выбрать вручную.
        //
        // Можно передать алиас certAlias:
        // алиас будущего сертификата в хранилище сертификатов.
        // Сертификат будет сохранен в хранилище под этим алиасом,
        // либо цепочка сертификатов. Если не передать ничего, то
        // алиас сертификата можно будет ввести.

        if (alias != null) {

            if (storage.equalsIgnoreCase(STORAGE_PERSONAL)) {
                intent.putExtra("containerAlias", alias);
            } // if
            else {
                intent.putExtra("certAlias", alias);
            } // else

        } // if

        // II. ИСПОЛЬЗОВАНИЕ ЗАРАНЕЕ ИЗВЕСТНОГО ПУТИ К ФАЙЛУ
        // Передача пути к файлу сертификата (цепочки). Его можно не
        // передавать, тогда его нужно будет указать в специальном
        // поле в окне.
        // Если передать содержимое, то кнопка "Установить" будет
        // сразу доступна, без необходимости выбирать файл.

        if (certPath != null) {
            intent.putExtra("certPath", certPath);
        } // if

        // III. ПЕРЕДАЧА СОДЕРЖИМОГО
        // Передача содержимого файла сертификата (цепочки),
        // взятого, например, из своих ресурсов. Его можно не
        // передавать, тогда файл сертификата (цепочки) нужно будет
        // указать в специальном поле в окне.
        // Если передать содержимое, то кнопка "Установить" будет
        // сразу доступна, без необходимости выбирать файл.

        if (certContent != null) {
            intent.putExtra("certContent", certContent);
        } // if

        startActivityForResult(intent, requestCode);

    }

    @Override
    public void onActivityResult(int requestCode, int resultCode, Intent data) {

        final boolean success = (resultCode == Activity.RESULT_OK);

        if (success) {
            MainActivity.getLogCallback().setStatusOK();
        } // if
        else {
            MainActivity.getLogCallback().setStatusFailed();
        } // else

        switch (requestCode) {

            // Копирование контейнера.
            case INTENT_ID_COPY_CONTAINER: {

                MainActivity.getLogCallback().log("Copying of container " +
                    (success ? "completed." : "failed!"));

            }
            break;

            // Установка сертификата (цепочки) в контейнер.
            case INTENT_ID_INSTALL_CERT + 1000: {

                MainActivity.getLogCallback().log("Install of certificate in container " +
                    (success ? "completed." : "failed!"));

            }
            break;

            // Установка сертификата (цепочки) в хранилище сертификатов.
            case INTENT_ID_INSTALL_CERT + 1001:
            case INTENT_ID_INSTALL_CERT + 1002:
            case INTENT_ID_INSTALL_CERT + 1003: {

                MainActivity.getLogCallback().log("Install of certificate in certificate store " +
                    (success ? "completed." : "failed!"));

            }
            break;

            // Построение цепочки.
            case INTENT_ID_BUILD_CHAIN: {

                MainActivity.getLogCallback().log("Building of certificate chain " +
                    (success ? "completed." : "failed!"));

            }
            break;

            case INTENT_ID_SIGN_DATA: {

                if (resultCode == Activity.RESULT_OK) {

                    // Подпись будет получена в signature, тип - в type и
                    // совмещенная или нет - в attached.

                    final byte[] signature = data.getByteArrayExtra("signature");
                    final int signatureType = data.getIntExtra("type", -1);
                    final boolean attached = data.getBooleanExtra("attached", true);

                    try {
                        Array.writeFile(FILE_SIGNATURE, signature);
                    } catch (IOException e) {
                        Log.e(Constants.APP_LOGGER_TAG, e.getMessage(), e);
                    }

                    MainActivity.getLogCallback().log("--- SIGNATURE (type: " +
                        signatureType + ", attached: " + attached + ") ---");

                    MainActivity.getLogCallback().log(signature, true);

                } // if
                else {
                    MainActivity.getLogCallback().log("Signing of data failed!");
                } // else

            }
            break;

            case INTENT_ID_VERIFY_SIGN: {

                if (resultCode == Activity.RESULT_OK) {

                    // Тип проверенной подписи будет получен в type и
                    // совмещенная или нет - в attached.

                    final int signatureType = data.getIntExtra("type", -1);
                    final boolean attached = data.getBooleanExtra("attached", true);

                    MainActivity.getLogCallback().log("Signature (type: " +
                        signatureType + ", attached: " + attached + ") verifying completed.");


                } // if
                else {
                    MainActivity.getLogCallback().log("Signature verifying failed!");
                } // else

            }
            break;

            // Создание контейнера.
            case INTENT_ID_CREATE_CONTAINER: {

                if (resultCode == Activity.RESULT_OK) {

                    // Тип контейнера будет получен в containerType, алиас
                    // контейнера - в containerAlias, тип ключа - в isExchangeKey,
                    // содержимое сформированного сертификата, помещенного в
                    // контейнер - в encodedCertContent, адрес УЦ, где был выпущен
                    // сертификат (если есть) - в caAddress.

                    final String containerType = data.getStringExtra("containerType");
                    final String containerAlias = data.getStringExtra("containerAlias");

                    final boolean isExchange = data.getBooleanExtra("exchange", true);

                    final byte[] encodedReqContent = data.getByteArrayExtra("requestContent");
                    final byte[] encodedCertContent = data.getByteArrayExtra("certContent");

                    X509Certificate certificate = null;

                    try {

                        certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
                            .generateCertificate(new ByteArrayInputStream(encodedCertContent));

                    } catch (CertificateException e) {
                        Log.e(Constants.APP_LOGGER_TAG, e.getMessage(), e);
                        MainActivity.getLogCallback().log("Error occurred during " +
                            "converting certificate: " + e.getMessage());
                    }

                    final String caAddress = data.getStringExtra("caAddress");

                    MainActivity.getLogCallback().log(
                        "Creating of container [" +
                        "type: " + containerType + ", " +
                        "alias: " + containerAlias + ", " +
                        "key type: " + (isExchange ? "exchange" : "signature") + ", " +
                        "certificate: " + (certificate != null ? certificate.getSubjectDN() : null) +
                        ((caAddress != null) ? (", CA: " + caAddress) : "") + "] completed.");

                    MainActivity.getLogCallback().log("$$ Certificate Request $$");
                    MainActivity.getLogCallback().log(encodedReqContent, true);

                } // if
                else {
                    MainActivity.getLogCallback().log("Creating of container failed!");
                } // else

            }
            break;

        } // switch

    }

    /**
     * Запись в лог имени запускаемого интента.
     *
     * @param intentName Имя интента.
     */
    private static void logCalling(String intentName) {
        MainActivity.getLogCallback().log("*** Intent " + intentName + " ***");
    }

    /**
     * Чтение данных из потока.
     *
     * @param inStream Поток.
     * @return прочитанные данные.
     */
    /*
    private static byte[] readDataFromStream(InputStream inStream) {

        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        final int bufferSize = 1024;

        byte[] buffer = new byte[bufferSize];
        int read;

        try {

            while ((read = inStream.read(buffer, 0, bufferSize)) != -1) {
                outputStream.write(buffer, 0, read);
            } // while

        } catch (Exception e) {
            Log.e(Constants.APP_LOGGER_TAG, e.getMessage(), e);
        } finally {

            try {
                inStream.close();
            } catch (IOException e) {
                // ignore
            }

            try {
                outputStream.close();
            } catch (IOException e) {
                // ignore
            }

        }

        return outputStream.toByteArray();

    }
    */
}