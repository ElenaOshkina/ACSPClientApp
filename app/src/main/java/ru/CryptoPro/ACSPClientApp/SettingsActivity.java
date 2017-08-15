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

import android.os.Bundle;
import android.support.v4.app.Fragment;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Spinner;

import java.io.File;
import java.util.List;

import ru.CryptoPro.ACSPClientApp.R;
import ru.cprocsp.ACSP.tools.common.CSPTool;
import ru.cprocsp.ACSP.tools.common.RawResource;
import ru.CryptoPro.ACSPClientApp.util.KeyStoreType;
import ru.CryptoPro.ACSPClientApp.util.ProviderType;

/**
 * Вкладка для отображения настроек.
 */
public class SettingsActivity extends Fragment
    implements AdapterView.OnItemSelectedListener {

    /**
     * Номер выбранного типа хранилища в списке.
     */
    private int keyStoreTypeIndex = 0;

    /**
     * Номер выбранного типа провайдера в списке.
     */
    private int providerTypeIndex = 0;

    @Override
    public View onCreateView(LayoutInflater inflater,
        ViewGroup container, Bundle savedInstanceState) {

        View page = inflater.inflate(R.layout.settings,
            container, false);

        initCopyContainersButton(page);

        // Тип контейнера.

        Spinner spKeyStoreType = (Spinner) page.findViewById(R.id.spKeyStore);

        // Получение списка поддерживаемых типов хранилищ.
        List<String> keyStoreTypeList = KeyStoreType.getKeyStoreTypeList();

        // Создаем ArrayAdapter для использования строкового массива
        // и способа отображения объекта.
        ArrayAdapter<String> keyStoreTypeAdapter = new ArrayAdapter<String>(
            page.getContext(), android.R.layout.simple_spinner_item,
                keyStoreTypeList);

        // Способ отображения.
        keyStoreTypeAdapter.setDropDownViewResource(
            android.R.layout.simple_spinner_dropdown_item);

        spKeyStoreType.setAdapter(keyStoreTypeAdapter);
        spKeyStoreType.setOnItemSelectedListener(this);

        // Выбираем сохраненный ранее тип.
        keyStoreTypeIndex = keyStoreTypeAdapter.getPosition(KeyStoreType.currentType());
        spKeyStoreType.setSelection(keyStoreTypeIndex);

        // Тип провайдера.

        Spinner spProviderType = (Spinner) page.findViewById(R.id.spProviderType);

        // Создаем ArrayAdapter для использования строкового массива
        // и способа отображения объекта.
        ArrayAdapter<CharSequence> providerTypeAdapter =
            ArrayAdapter.createFromResource(page.getContext(),
                R.array.providerTypes, android.R.layout.simple_spinner_item);

        // Способ отображения.
        providerTypeAdapter.setDropDownViewResource(
            android.R.layout.simple_spinner_dropdown_item);

        spProviderType.setAdapter(providerTypeAdapter);
        spProviderType.setOnItemSelectedListener(this);

        // Выбираем сохраненный ранее тип.
        providerTypeIndex = providerTypeAdapter.getPosition(ProviderType.currentType());
        spProviderType.setSelection(providerTypeIndex);

        return page;
    }

    @Override
    public void onSaveInstanceState(Bundle outState) {
        // first saving my state, so the bundle wont be empty.
        outState.putString("WORKAROUND_FOR_BUG_19917_KEY",
            "WORKAROUND_FOR_BUG_19917_VALUE");
        super.onSaveInstanceState(outState);
    }

    @Override
    public void onItemSelected(AdapterView<?> adapterView, View view, int i, long l) {

        switch (adapterView.getId()) {

            case R.id.spKeyStore: {
                if (keyStoreTypeIndex != i) {
                    KeyStoreType.saveCurrentType((String) adapterView.getItemAtPosition(i));
                    keyStoreTypeIndex = i;
                } // if
            }
            break;

            case R.id.spProviderType: {
                if (providerTypeIndex != i) {

                    ProviderType.saveCurrentType((String) adapterView.getItemAtPosition(i));
                    providerTypeIndex = i;

                } // if
            }
            break;

        } // switch

    }

    @Override
    public void onNothingSelected(AdapterView<?> adapterView) {
        ;
    }

    /**
     * Добавление обработчика в кнопку копирования контейнеров
     * пиз папки на карте.
     *
     */
    private void initCopyContainersButton(final View view) {

        Button btCopyContainers =
            (Button) view.findViewById(R.id.btMoveContainers);

        // Копирование контейнера.
        btCopyContainers.setOnClickListener(new View.OnClickListener() {

            @Override
            public void onClick(View v) {

                MainActivity.getLogCallback().clear();
                MainActivity.getLogCallback().log("*** Copy containers to the " +
                    "application store ***");

                EditText etContainerFolder =
                    (EditText) view.findViewById(R.id.etContainerFolder);

                // Получаем исходную папку с контейнерами.

                final String containerFolder = String.valueOf(etContainerFolder.getText());
                if (containerFolder == null || containerFolder.isEmpty()) {
                    MainActivity.getLogCallback().log("Containers' directory is undefined.");
                    return;
                } // if

                try {

                    MainActivity.getLogCallback().log("Source directory: " +
                        containerFolder);

                    // Проверяем наличие контейнеров.

                    File sourceDirectory = new File(containerFolder);
                    if (!sourceDirectory.exists()) {
                        MainActivity.getLogCallback().log("Source directory is empty " +
                            "or doesn't exist.");
                        return;
                    } // if

                    File[] srcContainers = sourceDirectory.listFiles();
                    if (srcContainers == null || srcContainers.length == 0) {
                        MainActivity.getLogCallback().log("Source directory is empty.");
                        return;
                    } // if

                    // Определяемся с папкой назначения в кататоге
                    // приложения.

                    CSPTool cspTool = new CSPTool(v.getContext());
                    final String dstPath =
                        cspTool.getAppInfrastructure().getKeysDirectory() +
                            File.separator + MainActivity.userName2Dir(v.getContext());

                    MainActivity.getLogCallback().log("Destination directory: " + dstPath);

                    // Копируем папки контейнеров.

                    for (int i = 0; i < srcContainers.length; i++) {

                        File srcCurrentContainer = srcContainers[i];

                        if (srcCurrentContainer.getName().equals(".")
                            || srcCurrentContainer.getName().equals("..")) {
                            continue;
                        } // if

                        MainActivity.getLogCallback().log("Copy container: " +
                            srcCurrentContainer.getName());

                        // Создаем папку контейнера в каталоге приложения.

                        File dstContainer = new File(dstPath, srcCurrentContainer.getName());
                        dstContainer.mkdirs();

                        // Копируем файлы из контейнера.

                        File[] srcContainer = srcCurrentContainer.listFiles();
                        if (srcContainer != null) {

                            for (int j = 0; j < srcContainer.length; j++) {

                                File srcCurrentContainerFile = srcContainer[j];

                                if (srcCurrentContainerFile.getName().equals(".")
                                    || srcCurrentContainerFile.getName().equals("..")) {
                                    continue;
                                } // if

                                MainActivity.getLogCallback().log("\tCopy file: " +
                                    srcCurrentContainerFile.getName());

                                // Копирование единичного файла.

                                if (!RawResource.writeStreamToFile(
                                    srcCurrentContainerFile,
                                    dstContainer.getPath(), srcCurrentContainerFile.getName())) {
                                    MainActivity.getLogCallback().log("\tCouldn't copy file: " +
                                        srcCurrentContainerFile.getName());
                                } // if
                                else {
                                    MainActivity.getLogCallback().log("\tFile " +
                                        srcCurrentContainerFile.getName() +
                                            " was copied successfully.");
                                } // else

                            } // for

                        } // if

                    } // for

                } catch (Exception e) {
                    Log.e(Constants.APP_LOGGER_TAG, e.getMessage(), e);
                }
            }

        });

    }

}
