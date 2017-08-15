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

import android.app.ActionBar;
import android.app.Activity;
import android.app.AlertDialog;
import android.app.FragmentTransaction;
import android.content.Context;
import android.content.DialogInterface;
import android.content.pm.ApplicationInfo;
import android.os.Bundle;
import android.support.v4.app.Fragment;
import android.support.v4.app.FragmentActivity;
import android.support.v4.app.FragmentManager;
import android.support.v4.app.FragmentPagerAdapter;
import android.support.v4.view.ViewPager;
import android.util.Log;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.inputmethod.InputMethodManager;
import android.widget.EditText;
import android.widget.TextView;

import java.io.File;
import java.security.Provider;
import java.security.Security;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Observer;
import java.util.Set;

import ru.CryptoPro.ACSPClientApp.client.LogCallback;
import ru.CryptoPro.ACSPClientApp.client.example.interfaces.IEncryptDecryptData;
import ru.CryptoPro.ACSPClientApp.util.KeyStoreType;
import ru.CryptoPro.ACSPClientApp.util.ProviderServiceInfo;
import ru.CryptoPro.ACSPClientApp.util.ProviderType;
import ru.CryptoPro.CAdES.CAdESConfig;
import ru.CryptoPro.JCPxml.XmlInit;
import ru.CryptoPro.JCSP.CSPConfig;
import ru.CryptoPro.JCSP.JCSP;
import ru.CryptoPro.JCSP.support.BKSTrustStore;
import ru.CryptoPro.reprov.RevCheck;
import ru.CryptoPro.ssl.util.cpSSLConfig;
import ru.cprocsp.ACSP.tools.common.CSPTool;
import ru.cprocsp.ACSP.tools.common.Constants;
import ru.cprocsp.ACSP.tools.common.RawResource;

/**
 * Главная activity приложения. Выполнение инициализации CSP,
 * создание вкладок с примерами, копирования тестовых контейнеров
 * и др.
 *
 */
public class MainActivity extends FragmentActivity implements
    ActionBar.TabListener {

    /**
     * Объект для вывода логов и смены статуса.
     */
    private static LogCallback logCallback = null;

    /**
     * Java-провайдер Java CSP.
     */
    private static Provider defaultKeyStoreProvider = null;

    /**
     * Элемент для отображения вкладки.
     */
    private ViewPager viewPager = null;

    /**
     * Список закладок.
     */
    private Map<Fragment, String> fragments = new LinkedHashMap<Fragment, String>(4);

    /**
     * Called when the activity is first created.
     */
    @Override
    public void onCreate(Bundle savedInstanceState) {

        super.onCreate(savedInstanceState);
        setContentView(R.layout.main);

        Log.i(Constants.APP_LOGGER_TAG, "Load application: " +
            getPackageName());

        // 1. Управление вкладками и панелями (Графика).

        initNavigation();

        // 2. Инициализация провайдеров: CSP и java-провайдеров
        // (Обязательная часть).

        if (!initCSPProviders()) {
            Log.i(Constants.APP_LOGGER_TAG, "Couldn't initialize CSP.");
            return;
        } // if

        initJavaProviders();

        // 3. Копирование тестовых контейнеров для подписи,
        // проверки подписи, шифрования и TLS (Примеры и вывод
        // в лог).

        initLogger();
        installContainers();

        // 4. Инициируем объект для управления выбором типа
        // контейнера (Настройки).

        KeyStoreType.init(this);

        // 5. Инициируем объект для управления выбором типа
        // провайдера (Настройки).

        ProviderType.init(this);

        // 6. Вывод информации о тестовых контейнерах.

        logTestContainers();

        // 7. Вывод информации о провайдере и контейнерах
        // (Пример).

        logJCspServices(defaultKeyStoreProvider = new JCSP());

        // Для логирования: CSPConfig.setNeedLogBioStatistics(true);

    }

    @Override
    public void onTabUnselected(ActionBar.Tab tab,
        FragmentTransaction fragmentTransaction) {
        ;
    }

    @Override
    public void onTabSelected(ActionBar.Tab tab,
        FragmentTransaction fragmentTransaction) {
        viewPager.setCurrentItem(tab.getPosition());
    }

    @Override
    public void onTabReselected(ActionBar.Tab tab,
        FragmentTransaction fragmentTransaction) {
        ;
    }

    /**
     * Создание вкладок и меню.
     *
     */
    private void initNavigation() {

        fragments.put(new ContainerActivity(), getString(R.string.ContainerTab).toUpperCase());
        fragments.put(new ExamplesActivity(), getString(R.string.ExamplesTab).toUpperCase());
        fragments.put(new ACSPIntentActivity(), getString(R.string.IntentsTab).toUpperCase());
        fragments.put(new SettingsActivity(), getString(R.string.SettingsTab).toUpperCase());

        SectionsPagerAdapter sectionsPagerAdapter =
            new SectionsPagerAdapter(getSupportFragmentManager());

        final ActionBar actionBar = getActionBar();
        actionBar.setNavigationMode(ActionBar.NAVIGATION_MODE_TABS);

        viewPager = (ViewPager) findViewById(R.id.pager);
        viewPager.setAdapter(sectionsPagerAdapter);
        viewPager.setOffscreenPageLimit(2);
        viewPager.setVerticalScrollBarEnabled(true);

        // Смена вкладок.
        viewPager.setOnPageChangeListener(
            new ViewPager.SimpleOnPageChangeListener() {

                @Override
                public void onPageSelected(int position) {

                    actionBar.setSelectedNavigationItem(position);

                    final Set<Fragment> fragmentSet = fragments.keySet();
                    final Fragment[] fragmentArray = fragmentSet.toArray(new Fragment[fragmentSet.size()]);

                    if (fragmentArray[position] instanceof Observer) {
                        ((Observer)fragmentArray[position]).update(null, null);
                    } // if

                }

            });

        // Заголовки вкладок.
        for (int i = 0; i < sectionsPagerAdapter.getCount(); i++) {
            actionBar.addTab(actionBar.newTab()
                .setText(sectionsPagerAdapter.getPageTitle(i))
                .setTabListener(this));
        } // for

    }

    /************************ Инициализация провайдера ************************/

    /**
     * Инициализация CSP провайдера.
     *
     * @return True в случае успешной инициализации.
     */
    private boolean initCSPProviders() {

        // Инициализация провайдера CSP. Должна выполняться
        // один раз в главном потоке приложения, т.к. использует
        // статические переменные.
        //
        // 1. Создаем инфраструктуру CSP и копируем ресурсы
        // в папку. В случае ошибки мы, например, выводим окошко
        // (или как-то иначе сообщаем) и завершаем работу.

        int initCode = CSPConfig.init(this);
        boolean initOk = initCode == CSPConfig.CSP_INIT_OK;

        // Если инициализация не удалась, то сообщим об ошибке.
        if (!initOk) {

            switch (initCode) {

                // Не передан контекст приложения (null). Он необходим,
                // чтобы произвести копирование ресурсов CSP, создание
                // папок, смену директории CSP и т.п.
                case CSPConfig.CSP_INIT_CONTEXT:
                    errorMessage(this, "Couldn't initialize context.");
                break;

                /**
                 * Не удается создать инфраструктуру CSP (папки): нет
                 * прав (нарушен контроль целостности) или ошибки.
                 * Подробности в logcat.
                 */
                case CSPConfig.CSP_INIT_CREATE_INFRASTRUCTURE:
                    errorMessage(this, "Couldn't create CSP infrastructure.");
                break;

                /**
                 * Не удается скопировать все или часть ресурсов CSP -
                 * конфигурацию, лицензию (папки): нет прав (нарушен
                 * контроль целостности) или ошибки.
                 * Подробности в logcat.
                 */
                case CSPConfig.CSP_INIT_COPY_RESOURCES:
                    errorMessage(this, "Couldn't copy CSP resources.");
                break;

                /**
                 * Не удается задать рабочую директорию для загрузки
                 * CSP. Подробности в logcat.
                 */
                case CSPConfig.CSP_INIT_CHANGE_WORK_DIR:
                    errorMessage(this, "Couldn't change CSP working directory.");
                break;

                /**
                 * Неправильная лицензия.
                 */
                case CSPConfig.CSP_INIT_INVALID_LICENSE:
                    errorMessage(this, "Invalid CSP serial number.");
                break;

                /**
                 * Не удается создать хранилище доверенных сертификатов
                 * для CAdES API.
                 */
                case CSPConfig.CSP_TRUST_STORE_FAILED:
                    errorMessage(this, "Couldn't create trust store for CAdES API.");
                    break;

            } // switch

        } // if

        return initOk;
    }

    @Override
    public void onResume() {

        super.onResume();

        // Необходимо для отображения диалоговых окон
        // ДСЧ, ввода пин-кода и сообщений.
        CSPConfig.registerActivityContext(this);
    }

    /**
     * Добавление нативного провайдера JCSP, SSL-провайдера
     * и Revocation-провайдера в список Security.
     * Инициализируется JCPxml, CAdES.
     *
     * Происходит один раз при инициализации.
     * Возможно только после инициализации в CSPConfig!
     *
     */
    private void initJavaProviders() {

        // Загрузка Java CSP (хеш, подпись, шифрование, генерация контейнеров).

        if (Security.getProvider(JCSP.PROVIDER_NAME) == null) {
            Security.addProvider(new JCSP());
        } // if

        // Загрузка JTLS (TLS).

        // Необходимо переопределить свойства, чтобы использовались
        // менеджеры из cpSSL, а не Harmony.

        Security.setProperty("ssl.KeyManagerFactory.algorithm",
            ru.CryptoPro.ssl.Provider.KEYMANGER_ALG);
        Security.setProperty("ssl.TrustManagerFactory.algorithm",
            ru.CryptoPro.ssl.Provider.KEYMANGER_ALG);

        Security.setProperty("ssl.SocketFactory.provider",
            "ru.CryptoPro.ssl.SSLSocketFactoryImpl");
        Security.setProperty("ssl.ServerSocketFactory.provider",
            "ru.CryptoPro.ssl.SSLServerSocketFactoryImpl");

        if (Security.getProvider(ru.CryptoPro.ssl.Provider.PROVIDER_NAME) == null) {
            Security.addProvider(new ru.CryptoPro.ssl.Provider());
        } // if

        // Провайдер хеширования, подписи, шифрования по умолчанию.
        cpSSLConfig.setDefaultSSLProvider(JCSP.PROVIDER_NAME);

        // Загрузка Revocation Provider (CRL, OCSP).

        if (Security.getProvider(RevCheck.PROVIDER_NAME) == null) {
            Security.addProvider(new RevCheck());
        } // if

        // Инициализация XML DSig (хеш, подпись).

        XmlInit.init();

        // Параметры для Java TLS и CAdES API.

        // Провайдер CAdES API по умолчанию.
        CAdESConfig.setDefaultProvider(JCSP.PROVIDER_NAME);

        // Включаем возможность онлайновой проверки статуса сертификата.
        System.setProperty("com.sun.security.enableCRLDP", "true");
        System.setProperty("com.ibm.security.enableCRLDP", "true");

        // Настройки TLS для генерации контейнера и выпуска сертификата
        // в УЦ 2.0, т.к. обращение к УЦ 2.0 будет выполняться по протоколу
        // HTTPS и потребуется авторизация по сертификату. Указываем тип
        // хранилища с доверенным корневым сертификатом, путь к нему и пароль.

        final String trustStorePath = getApplicationInfo().dataDir + File.separator +
            BKSTrustStore.STORAGE_DIRECTORY + File.separator + BKSTrustStore.STORAGE_FILE_TRUST;

        final String trustStorePassword = String.valueOf(BKSTrustStore.STORAGE_PASSWORD);
        Log.d(Constants.APP_LOGGER_TAG, "Default trust store: " + trustStorePath);

        System.setProperty("javax.net.ssl.trustStoreType", BKSTrustStore.STORAGE_TYPE);
        System.setProperty("javax.net.ssl.trustStore", trustStorePath);
        System.setProperty("javax.net.ssl.trustStorePassword", trustStorePassword);

    }

    /************************ Поле для вывода логов *************************/

    /**
     * Инициализация объекта для отображения логов.
     *
     */
    private void initLogger() {

        // Поле для вывода логов и метка для отображения
        // статуса.

        EditText etLog = (EditText) findViewById(R.id.etLog);
        etLog.setMinLines(10);

        TextView tvOpStatus = (TextView) findViewById(R.id.tvOpStatus);

        logCallback = new LogCallback(getResources(), etLog, tvOpStatus);
        logCallback.clear();

    }

    /******************************** Адаптер для фрагментов ********************************/

    /**
     * Класс SectionsPagerAdapter предназначен для управления
     * вкладками и их активации.
     *
     */
    public class SectionsPagerAdapter extends FragmentPagerAdapter {

        /**
         * Список фрагментов.
         */
        private Fragment[] fragmentArray = null;

        /**
         * Список заголовков фрагментов.
         */
        private String[] fragmentTitleArray = null;

        /**
         * Конструктор.
         *
         * @param fm Менеджер фрагментов.
         */
        public SectionsPagerAdapter(FragmentManager fm) {

            super(fm);

            final Set<Fragment> fragmentSet =  fragments.keySet();
            fragmentArray = fragmentSet.toArray(new Fragment[fragmentSet.size()]);

            final Collection<String> fragmentTitles =  fragments.values();
            fragmentTitleArray = fragmentTitles.toArray(new String[fragmentTitles.size()]);

        }

        @Override
        public Fragment getItem(int i) {
            return fragmentArray[i];
        }

        @Override
        public int getCount() {
            return fragments.size();
        }

        @Override
        public CharSequence getPageTitle(int position) {
            return fragmentTitleArray[position];
        }

    }

    /************************** Служебные функции ****************************/

    /**
     * Получение объекта для вывода логов и смены статуса.
     *
     * @return объект.
     */
    public static LogCallback getLogCallback() {
        return logCallback;
    }

    /**
     * Получение объекта провайдера Java CSP.
     *
     * @return провайдер Java CSP.
     */
    public static Provider getDefaultKeyStoreProvider() {
        return defaultKeyStoreProvider;
    }

    /**
     * Отображение окна с сообщением.
     *
     * @param activity Рабочая форма.
     * @param message Сообщение.
     */
    public static void errorMessage(final Activity activity,
        String message) {
        errorMessage(activity, message, false, true);
    }

    /**
     * Отображение окна с сообщением.
     *
     * @param activity Рабочая форма.
     * @param message Сообщение.
     * @param finish True, если следует закрыть окно.
     */
    public static void errorMessage(final Activity activity,
        String message, boolean cancellable, final boolean finish) {

        // Окно с сообщением.
        AlertDialog.Builder dialog = new AlertDialog.Builder(activity);
        dialog.setMessage(message);
        dialog.setCancelable(cancellable);

        // Закрытие окна.
        dialog.setPositiveButton(android.R.string.ok,
                new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int whichButton) {
                        if (finish) {
                            activity.finish();
                        } // if
                        else {
                            ; // nothing
                        } // else
                    }
                });

        dialog.show();
    }

    /**
     * Вывод списка поддерживаемых алгоритмов.
     *
     * @param provider Провайдер.
     */
    private void logJCspServices(Provider provider) {
        ProviderServiceInfo.logKeyStoreInfo(logCallback, provider);
        ProviderServiceInfo.logServiceInfo(logCallback, provider);
    }

    /**
     * Формируем имя папки в формате [uid].[uid] для
     * дальнейшего помещения в нее ключевого контейнера.
     *
     * @param context Контекст формы.
     * @return имя папки.
     * @throws Exception
     */
    public static String userName2Dir(Context context)
        throws Exception {

        ApplicationInfo appInfo = context.getPackageManager()
            .getPackageInfo(context.getPackageName(), 0)
                .applicationInfo;

        return String.valueOf(appInfo.uid) + "." +
            String.valueOf(appInfo.uid);
    }

    /**
     * Информация о тестовых контейнерах.
     *
     */
    private void logTestContainers() {

        // Список алиасов контейнеров.
        final String[] aliases = {
            IEncryptDecryptData.CLIENT_CONTAINER_NAME,          // ГОСТ 34.10-2001
            IEncryptDecryptData.SERVER_CONTAINER_NAME,          // ГОСТ 34.10-2001
            IEncryptDecryptData.CLIENT_CONTAINER_2012_256_NAME, // ГОСТ 34.10-2012 (256)
            IEncryptDecryptData.SERVER_CONTAINER_2012_256_NAME, // ГОСТ 34.10-2012 (256)
            IEncryptDecryptData.CLIENT_CONTAINER_2012_512_NAME, // ГОСТ 34.10-2012 (512)
            IEncryptDecryptData.SERVER_CONTAINER_2012_512_NAME  // ГОСТ 34.10-2012 (512)
        };

        // Список паролей контейнеров.
        final char[][] passwords = {
            IEncryptDecryptData.CLIENT_KEY_PASSWORD,
            IEncryptDecryptData.SERVER_KEY_PASSWORD,
            IEncryptDecryptData.CLIENT_KEY_2012_256_PASSWORD,
            IEncryptDecryptData.CLIENT_KEY_2012_256_PASSWORD,
            IEncryptDecryptData.CLIENT_KEY_2012_512_PASSWORD,
            IEncryptDecryptData.CLIENT_KEY_2012_512_PASSWORD
        };

        final String format = getString(R.string.ContainerAboutTestContainer);
        logCallback.log("$$$ About test containers $$$");

        for (int i = 0; i < aliases.length; i++) {
            final String aboutTestContainer = String.format(format, aliases[i], String.valueOf(passwords[i]));
            logCallback.log("** " + i + ") " + aboutTestContainer);
        } // for

    }

    /**
     * Копирование тестовых контейнеров для подписи, шифрования,
     * обмена по TLS в папку keys.
     *
     */
    private void installContainers() {

        // Имена файлов в контейнере.
        final String[] pseudos = {
                "header.key",
                "masks.key",
                "masks2.key",
                "name.key",
                "primary.key",
                "primary2.key"
        };

        // Список алиасов контейнеров.
        final String[] aliases = {
                IEncryptDecryptData.CLIENT_CONTAINER_NAME,          // ГОСТ 34.10-2001
                IEncryptDecryptData.SERVER_CONTAINER_NAME,          // ГОСТ 34.10-2001
                IEncryptDecryptData.CLIENT_CONTAINER_2012_256_NAME, // ГОСТ 34.10-2012 (256)
                IEncryptDecryptData.SERVER_CONTAINER_2012_256_NAME, // ГОСТ 34.10-2012 (256)
                IEncryptDecryptData.CLIENT_CONTAINER_2012_512_NAME, // ГОСТ 34.10-2012 (512)
                IEncryptDecryptData.SERVER_CONTAINER_2012_512_NAME  // ГОСТ 34.10-2012 (512)
        };

        // Список контейнеров и файлов внутри.
        final Integer[][] containers = {
                {R.raw.clienttls_header, R.raw.clienttls_masks, R.raw.clienttls_masks2, R.raw.clienttls_name, R.raw.clienttls_primary, R.raw.clienttls_primary2},
                {R.raw.servertls_header, R.raw.servertls_masks, R.raw.servertls_masks2, R.raw.servertls_name, R.raw.servertls_primary, R.raw.servertls_primary2},
                {R.raw.cli12256_header,  R.raw.cli12256_masks,  R.raw.cli12256_masks2,  R.raw.cli12256_name,  R.raw.cli12256_primary,  R.raw.cli12256_primary2 },
                {R.raw.ser12256_header,  R.raw.ser12256_masks,  R.raw.ser12256_masks2,  R.raw.ser12256_name,  R.raw.ser12256_primary,  R.raw.ser12256_primary2 },
                {R.raw.cli12512_header,  R.raw.cli12512_masks,  R.raw.cli12512_masks2,  R.raw.cli12512_name,  R.raw.cli12512_primary,  R.raw.cli12512_primary2 },
                {R.raw.ser12512_header,  R.raw.ser12512_masks,  R.raw.ser12512_masks2,  R.raw.ser12512_name,  R.raw.ser12512_primary,  R.raw.ser12512_primary2 }
        };

        // Копирование контейнеров.

        try {

            for (int i = 0; i < containers.length; i++) {

                final Integer[] container = containers[i];
                final Map<Integer, String> containerFiles = new HashMap<Integer, String>();

                for (int j = 0; j < container.length; j++) {
                    containerFiles.put(container[j], pseudos[j]);
                } // for

                installContainer(aliases[i], containerFiles);

            } // for

        } catch (Exception e) {
            Log.e(Constants.APP_LOGGER_TAG, e.getMessage(), e);
        }

    }

    /**
     * Копирование файлов контейнера в папку согласно названию
     * контейнера.
     *
     * @param containerName Имя папки контейнера.
     * @param containerFiles Список и ссылки на файлы контейнера.
     * @throws Exception
     */
    private void installContainer(String containerName,
        Map<Integer, String> containerFiles) throws Exception {

        String resourceDirectory = userName2Dir(this) + File.separator + containerName;
        Log.i(Constants.APP_LOGGER_TAG, "Install container: " +
            containerName + " to resource directory: " + resourceDirectory);

        CSPTool cspTool = new CSPTool(this);

        // Копируем ресурсы  в папку keys.
        RawResource resource = cspTool.createRawResource(
            Constants.CSP_SOURCE_TYPE_CONTAINER, resourceDirectory);

        Iterator<Integer> iterator = containerFiles.keySet().iterator();

        while (iterator.hasNext()) {
            Integer index = iterator.next();
            String fileName = containerFiles.get(index);
            if (!resource.copy(index, fileName)) {
                throw new Exception("Couldn't copy " + fileName);
            } // if
        } // while
    }

    /**
     * Сокрытие клавиатуры.
     *
     * @param activity Форма.
     */
    private static void hideSoftKeyboard(Activity activity) {

        InputMethodManager inputMethodManager = (InputMethodManager)
            activity.getSystemService(Activity.INPUT_METHOD_SERVICE);

        inputMethodManager.hideSoftInputFromWindow(
            activity.getCurrentFocus().getWindowToken(), 0);

    }

    /**
     * Применение процедуры сокрытия клавиатуры.
     *
     * @param view Панель элементов.
     */
    public static void setupUI(View view) {

        // Set up touch listener for non-text box views to hide keyboard.
        if(!(view instanceof EditText)) {

            view.setOnTouchListener(new View.OnTouchListener() {
                public boolean onTouch(View v, MotionEvent event) {
                    //hideSoftKeyboard((Activity) (v.getContext()));
                    return false;
                }
            });
        } // if

        // If a layout container, iterate over children and seed recursion.
        if (view instanceof ViewGroup) {

            for (int i = 0; i < ((ViewGroup) view).getChildCount(); i++) {
                View innerView = ((ViewGroup) view).getChildAt(i);
                setupUI(innerView);
            } // for

        } // if

    }

}
