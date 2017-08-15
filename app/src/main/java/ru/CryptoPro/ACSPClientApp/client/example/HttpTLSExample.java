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

import android.util.Log;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.ClientConnectionManager;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.scheme.SchemeRegistry;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.conn.SingleClientConnManager;
import org.apache.http.params.BasicHttpParams;
import org.apache.http.params.HttpConnectionParams;
import org.apache.http.params.HttpParams;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.security.KeyStore;

import ru.CryptoPro.ACSPClientApp.Constants;
import ru.CryptoPro.ACSPClientApp.client.LogCallback;
import ru.CryptoPro.ACSPClientApp.client.example.interfaces.ContainerAdapter;
import ru.CryptoPro.ACSPClientApp.client.example.interfaces.IThreadExecuted;
import ru.CryptoPro.ACSPClientApp.util.KeyStoreType;
import ru.CryptoPro.JCSP.JCSP;
import ru.CryptoPro.ssl.Provider;

/**
 * Класс HttpTLSExample реализует пример обмена
 * по TLS 1.0 с помощью apache http client.
 *
 * 30/05/2013
 *
 */
public class HttpTLSExample extends TLSExample {

    /**
     * Конструктор.
     *
     * @param adapter Настройки примера.
     */
    protected HttpTLSExample(ContainerAdapter adapter) {
        super(adapter);
    }

    @Override
    public void getResult(LogCallback callback) throws Exception {
        getResult(callback, new HttpTLSThread());
    }

    /**
     * Класс SimpleTLSThread реализует подключение
     * apache http клиента по TLS.
     *
     */
    private class HttpTLSThread implements IThreadExecuted {

        @Override
        public void execute(LogCallback callback) {

            containerAdapter.printConnectionInfo(callback);

            HttpClient httpClient = null;

            try {

                callback.log("Init Apache Http Client Example.");

                final String httpAddress = containerAdapter
                    .getConnectionInfo().toUrl();

                URI url = new URI(httpAddress);

                // Хранилища для подключения.

                callback.log("Load trusted stores.");

                /**
                 * Для чтения(!) доверенного хранилища доступна
                 * реализация CertStore из Java CSP. В ее случае
                 * можно не использовать пароль.
                 */

                KeyStore ts = KeyStore.getInstance(
                    containerAdapter.getTrustStoreType(),
                    containerAdapter.getTrustStoreProvider());

                ts.load(containerAdapter.getTrustStoreStream(),
                    containerAdapter.getTrustStorePassword());

                KeyStore ks = null;
                if (containerAdapter.isUseClientAuth()) {

                    // Тип контейнера по умолчанию.
                    String keyStoreType = KeyStoreType.currentType();
                    callback.log("Load key stores. Default container " +
                        "type: " + keyStoreType);

                    ks = KeyStore.getInstance(keyStoreType, JCSP.PROVIDER_NAME);
                    ks.load(null, null);

                } // if

                String keyStorePasswordValue =
                    containerAdapter.getClientPassword() == null
                    ? null : String.valueOf(containerAdapter.getClientPassword());

                callback.log("Create socket factory.");

                /*javax.net.ssl.SSLSocketFactory sslFactory = (javax.net.ssl.SSLSocketFactory) javax.net.ssl.SSLSocketFactory.getDefault();
                SSLSocket socket = (SSLSocket) sslFactory.createSocket("cpca.cryptopro.ru", 443);
                String pickedCipher[] = {Provider.ALGORITHM};
                socket.setEnabledCipherSuites(pickedCipher);
                String[] suites = socket.getEnabledCipherSuites();

                OkHttpClient okHttpClient;
                okHttpClient = new OkHttpClient();
                okHttpClient.setFollowSslRedirects(true);
                okHttpClient.setSslSocketFactory(sslFactory);
                okHttpClient.setHostnameVerifier(new AllowAllHostnameVerifier());*/

                SSLSocketFactory socketFactory = new SSLSocketFactory(
                    Provider.ALGORITHM, ks, keyStorePasswordValue, ts, null, null);

                socketFactory.setHostnameVerifier(
                    SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);

                callback.log("Register https scheme.");

                // Регистрируем HTTPS схему.
                Scheme httpsScheme = new Scheme("https", socketFactory,
                    containerAdapter.getConnectionInfo().getHostPort());

                SchemeRegistry schemeRegistry = new SchemeRegistry();
                schemeRegistry.register(httpsScheme);

                callback.log("Set connection options.");

                // Параметры соединения.
                HttpParams params = new BasicHttpParams();
                HttpConnectionParams.setSoTimeout(params, MAX_CLIENT_TIMEOUT);
                ClientConnectionManager cm = new SingleClientConnManager(params, schemeRegistry);
                httpClient = new DefaultHttpClient(cm, params);

                callback.log("Execute GET request.");

                // GET-запрос.
                HttpGet httpget = new HttpGet(url);
                HttpResponse response = httpClient.execute(httpget);
                HttpEntity entity = response.getEntity();

                callback.log("Response status: " + response.getStatusLine());

                int status = response.getStatusLine().getStatusCode();
                if (status  != 200) {
                    callback.log("Bad http response status: " + status);
                    callback.setStatusFailed();
                    return;
                } // if

                if (entity != null) {

                    // Получаем размер заголовка.
                    InputStream is = entity.getContent();

                    BufferedReader in = new BufferedReader(
                        new InputStreamReader(is, Constants.DEFAULT_ENCODING));

                    callback.log("Read response:");

                    // Выводим ответ.
                    String line;
                    while((line = in.readLine()) != null) {
                        callback.log(line);
                    } // while

                    if (in != null) {
                        in.close();
                    } // if

                    callback.setStatusOK();

                } // if

            } catch (Exception e) {
                callback.setStatusFailed();
                Log.e(Constants.APP_LOGGER_TAG, "Operation exception", e);
            } finally {
                if (httpClient != null) {

                    callback.log("Shutdown http connection.");
                    Log.i(Constants.APP_LOGGER_TAG, "Shutdown http connection.");

                    // Важно закрыть соединение, т.к. HeapWorker может убить jvm
                    // из-за возможных задержек в finalize.
                    httpClient.getConnectionManager().shutdown();
                } // if
            }

        }

    }
}
