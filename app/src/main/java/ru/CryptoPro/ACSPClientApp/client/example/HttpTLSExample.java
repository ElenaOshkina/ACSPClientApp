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

import org.apache.http.client.HttpClient;
import org.apache.http.conn.ssl.SSLSocketFactory;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.security.KeyStore;
import java.util.Collections;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import okhttp3.ConnectionSpec;
import okhttp3.OkHttpClient;
import okhttp3.ResponseBody;
import retrofit2.Retrofit;
import ru.CryptoPro.ACSPClientApp.Constants;
import ru.CryptoPro.ACSPClientApp.client.LogCallback;
import ru.CryptoPro.ACSPClientApp.client.example.interfaces.ContainerAdapter;
import ru.CryptoPro.ACSPClientApp.client.example.interfaces.IThreadExecuted;
import ru.CryptoPro.ACSPClientApp.util.KeyStoreType;
import ru.CryptoPro.JCSP.JCSP;
import ru.CryptoPro.ssl.Provider;
import rx.Subscriber;

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

        retrofit2.Response<ResponseBody> retrofitResponse = null;
        Subscriber<ResponseBody> subscription = null;

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

                SSLContext sslCtx = SSLContext.getInstance(Provider.ALGORITHM, Provider.PROVIDER_NAME);

                TrustManagerFactory tmf = TrustManagerFactory.getInstance(Provider.KEYMANGER_ALG, Provider.PROVIDER_NAME);
                tmf.init(ts);

                sslCtx.init(null, tmf.getTrustManagers(), null);

                javax.net.ssl.SSLSocketFactory sslFactory = sslCtx.getSocketFactory();

                X509TrustManager tm = (X509TrustManager) tmf.getTrustManagers()[0];

                ConnectionSpec spec = new ConnectionSpec.Builder(ConnectionSpec.COMPATIBLE_TLS)
                        .tlsVersions(Provider.ALGORITHM)
                        .cipherSuites(Provider.KEYMANGER_ALG)
                        .allEnabledTlsVersions()
                        .supportsTlsExtensions(false)
                        .allEnabledCipherSuites()
                        .build();

                OkHttpClient.Builder builder;
                builder = new OkHttpClient.Builder();
                builder.sslSocketFactory(sslFactory, tm);
                builder.hostnameVerifier(SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);
                builder.connectTimeout(MAX_CLIENT_TIMEOUT, TimeUnit.MILLISECONDS);
                builder.readTimeout(MAX_CLIENT_TIMEOUT, TimeUnit.MILLISECONDS);
                builder.connectionSpecs(Collections.singletonList(spec));
                OkHttpClient okHttpClient = builder.build();

                Retrofit.Builder retrofitBuilder = new Retrofit.Builder()
                        .baseUrl("https://cpca.cryptopro.ru:443")
                        .callFactory(okHttpClient);

                Retrofit retrofit = retrofitBuilder.build();

                CryptoApi cryptoApi = retrofit.create(CryptoApi.class);
                retrofitResponse = cryptoApi.getData().execute();

                int status = retrofitResponse.raw().code();

                if (retrofitResponse.raw().code() != 200) {
                    callback.log("Bad http response status: " + status);
                    callback.setStatusFailed();
                    return;
                } // if

                if (retrofitResponse.body().source() != null) {

                    // Получаем размер заголовка.
                    InputStream is = retrofitResponse.body().source().inputStream();

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
