/**
 * $RCSfile$
 * version $Revision: 36737 $
 * created 03.07.2007 10:07:20 by kunina
 * last modified $Date: 2013-04-17 16:30:35 +0400 (Ср, 17 апр 2013) $ by $Author: afevma $
 * (C) ООО Крипто-Про 2004-2007.
 *
 * Программный код, содержащийся в этом файле, предназначен
 * для целей обучения. Может быть скопирован или модифицирован 
 * при условии сохранения абзацев с указанием авторства и прав.
 *
 * Данный код не может быть непосредственно использован
 * для защиты информации. Компания Крипто-Про не несет никакой
 * ответственности за функционирование этого кода.
 */
package ru.CryptoPro.ACSPClientApp.client.example;

import ru.CryptoPro.ACSPClientApp.Constants;
import ru.CryptoPro.ACSPClientApp.client.LogCallback;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

/**
 * Пример клиента. Переделан на явное получение контекста, т.к. есть глюки при
 * а) использовании ключей с одинаковым паролем для сервера и клиента (может
 * быть выбран серверный ключ для клиента и для сервера, даже если рядом лежит
 * клиентский с таким же паролем)
 * б) т.к. при создании контекста используется getDefault(), то есть вероятность
 * получить ранее созданный контекст, не имеющий контейнеров с доверенными сертификатами).
 *
 * @author Copyright 2004-2007 Crypto-Pro. All rights reserved.
 * @.Version
 */
public class Client {

 /**/
public static final String http_header_separator = "\r\n\r\n";
 /**/
public static final int DEFAULT_TIMEOUT = 1000;
 /**/
private int timeout = DEFAULT_TIMEOUT;
 /**/
private String host;
 /**/
private int port;
 /**/
private LogCallback logCallback = null;


/**
 * Создание сокета по заданному порту и хосту.
 *
 * @param hostname хост
 * @param p порт
 */
public Client(String hostname, int p, LogCallback callback) {
    host = hostname;
    port = p;
    logCallback = callback;
}

/**
 * Функция устанавливает timeout на чтение.
 *
 * @param t timeout
 */
public void setTimeout(int t) {
    timeout = t;
}

/**
 * Основная функция работы клинета.
 *
 * @param sslContext Контекст для подключения.
 * @param fileName имя файла
 * @return код ошибки или 0 в случае успеха
 * @throws IOException ошибки ввода-вывода
 */
public int get(SSLContext sslContext, String fileName) throws Exception {

    logCallback.log("Client initiates a socket factory.");

    SSLSocket soc = null;

    try {
        // вариант 1
        // final SSLSocketFactory sslFact = (SSLSocketFactory) SSLSocketFactory.getDefault();

        //вариант 2
        // final SSLSocketFactoryImpl sslFact = new SSLSocketFactoryImpl();

        //вариант 3
        final SSLSocketFactory sslFact = sslContext.getSocketFactory();

        logCallback.log("Client creates a socket.");
        soc = (SSLSocket) sslFact.createSocket(host, port);
        soc.setSoTimeout(timeout);

        logCallback.log("Client sends a request.");
        return proc(soc, fileName);

    } finally {
        if (soc != null)
            soc.close();
    }
}

/**
 * Выполнение обмена данными с сервером.
 *
 * @param soc сокет
 * @param file имя файла
 * @return код ошибки или 0 в случае успеха
 * @throws IOException ошибки ввода-вывода
 */
public int proc(Socket soc, String file)
        throws IOException {

    final InputStream in = soc.getInputStream();
    final OutputStream out = soc.getOutputStream();

    // отправка запроса
    final String req = "GET /" + file + " HTTP/1.0\r\n\r\n";
    logCallback.log("Client's request: " + req);
    out.write(req.getBytes());
    out.flush();

    SSLSession session = ((SSLSocket)soc).getSession();
    logCallback.log("Chosen cipher suite: " + session.getCipherSuite());

    // разбор ответа
    logCallback.log("Client parses answer.");
    final String answer =
        new String(readHeader(in, http_header_separator.getBytes()));
    logCallback.log(answer);

    int fileLength = 0;
    try {
        fileLength = parseAnswer(answer);
    } catch (IOException e) {
        logCallback.log(e.getMessage());
        return -1;
    }

    final byte[] body = readBody(in, fileLength);
    final String bodyStr = new String(body, Constants.DEFAULT_ENCODING);

    logCallback.log(bodyStr);
    return 0;
}

/**
 * Чтение потока до конца заголовка.Может быть вызвано с new byte[] {(byte)' '}
 *
 * @param in входной поток
 * @param end конец заголовка
 * @return буфер (байтовый массив)
 * @throws IOException ошибки ввода-вывода
 */
public byte[] readHeader(InputStream in, byte[] end) throws IOException {
    final ByteArrayOutputStream baos = new ByteArrayOutputStream();
    int conformity = 0;
    int next;
    logCallback.log("Try reading (Client.readHeader)");
    do {
        next = in.read();
        if (next == -1)
            throw new IOException(" Client: Error reading HTTP header");
        baos.write(next);
        if (next == end[conformity])
            conformity++;
        else
            conformity = 0;
    } while (conformity != end.length);
    return baos.toByteArray();
}

/**
 * Чтение известного количества байтов.
 *
 * @param in InputStream
 * @param len length
 * @return буфер
 * @throws IOException ошибки ввода-вывода
 */
public static byte[] readBody(InputStream in, int len) throws IOException {

    // Если есть размер сообщения (прочитан из хидеров),
    // то используем его.
    if (len > 0) {

        final byte[] buf = new byte[len];
        int next;
        int pos = 0;

        while (pos != len) {

            next = in.read();

            if (next == -1) {
                throw new IOException(" Error reading HTTP body");
            } // if

            buf[pos++] = (byte) next;
        } // while

        return buf;
    } // if
    // Если размера нет (такое бывает), то читаем, пока не получим
    // конец файла.
    else {

        ByteArrayOutputStream buf = new ByteArrayOutputStream();

        while (true) {

            int next = in.read();

            if (next == -1) {

                // Ничего не прочитали, сразу конец файла.
                if (buf.size() == 0) {
                    throw new IOException(" Error reading HTTP body");
                } // if

                break;
            } // if

            buf.write((byte) next);
        } // while

        return buf.toByteArray();
    } // else
}

/**
 * Разбор ответа сервера и извлечение длины файла
 *
 * @param str строка ответа
 * @return длина файла
 * @throws IOException ошибки ввода-вывода
 */
public static int parseAnswer(String str) throws IOException {
    final String[] split = str.split("\r\n");
    if (!split[0].equalsIgnoreCase("HTTP/1.0 200 OK") &&
            !split[0].equalsIgnoreCase("HTTP/1.1 200 OK"))
        throw new IOException(split[0]);
    //throw new IOException("Unknown answer");
    int len = -1;
    for (int i = 1; i < split.length; i++)
        if (split[i].startsWith("Content-Length:")) {
            final String ss =
                    split[i].substring("Content-Length:".length()).trim();
            len = Integer.parseInt(ss);
            break;
        }
    return len;
}
}
