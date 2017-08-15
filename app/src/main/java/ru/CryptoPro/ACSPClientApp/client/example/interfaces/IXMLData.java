/**
 * $RCSfileIXMLData.java,v $
 * version $Revision: 36379 $
 * created 26.08.2014 11:16 by afevma
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
package ru.CryptoPro.ACSPClientApp.client.example.interfaces;

import org.w3c.dom.Document;
import ru.CryptoPro.ACSPClientApp.client.LogCallback;
import ru.CryptoPro.ACSPClientApp.util.AlgorithmSelector;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/**
 * Служебный класс IXMLData предназначен для
 * релизации примеров работы с подписью XML документов.
 *
 * @author Copyright 2004-2014 Crypto-Pro. All rights reserved.
 * @.Version
 */
public abstract class IXMLData extends ISignData {

    /**
     * Тип провайдера для выбора алгоритмов хеширования
     * и подписи XML документа.
     */
    protected AlgorithmSelector.DefaultProviderType providerType = null;

    /**
     * Конструктор.
     *
     * @param adapter настройки примера.
     */
    protected IXMLData(ContainerAdapter adapter) {
        super(adapter, false);
        providerType = adapter.getProviderType();
    }

    /**
     * Создание фабрики XML документа.
     *
     * @return фабрика XML документа.
     */
    protected DocumentBuilderFactory createDocFactory() {

        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();

        dbf.setIgnoringElementContentWhitespace(true);
        dbf.setCoalescing(true);
        dbf.setNamespaceAware(true);

        return dbf;
    }

    /**
     * Вывод содержимого XML документа в лог.
     *
     * @param doc XML документ.
     * @return содержимое документа.
     * @throws Exception
     */
    protected byte[] prepareLogXML(Document doc) throws Exception {

        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        PrintStream stream = new PrintStream(byteStream);

        writeDoc(doc, stream);

        stream.close();
        byteStream.close();

        return byteStream.toByteArray();

    }

    /**
     * Вывод в поток XML документа.
     *
     * @param doc XML документ.
     * @param out Поток для вывода.
     * @throws javax.xml.transform.TransformerException
     */
    private void writeDoc(Document doc, OutputStream out)
        throws TransformerException {
        Transformer transformer = TransformerFactory.newInstance().newTransformer();
        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
        transformer.transform(new DOMSource(doc), new StreamResult(out));
    }

    /**
     * Создание экземпляра XML документа.
     *
     * @return XML документ.
     * @throws javax.xml.parsers.ParserConfigurationException
     */
    abstract protected Document createSampleDocument() throws Exception;

    /**
     * Подпись XML документа.
     *
     * @param doc XML документ.
     * @param privateKey Закрытый ключ для подписи.
     * @param cert Сертификат для добавления в подпись (KeyInfo).
     * @param signMethod Алгоритм подписи.
     * @param digestMethod Алгоритм хеширования.
     * @throws Exception
     */
    abstract protected void signDoc(Document doc, PrivateKey privateKey,
        X509Certificate cert, String signMethod, String digestMethod,
        LogCallback callback) throws Exception;

    /**
     * Проверка подписи XML документа.
     *
     * @param doc Подписанный XML документ.
     * @return результат проверки.
     * @throws Exception
     */
    abstract protected boolean verifyDoc(Document doc,
        LogCallback callback) throws Exception;

}
