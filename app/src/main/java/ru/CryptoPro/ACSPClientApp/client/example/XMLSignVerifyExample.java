/**
 * $RCSfileXMLSignExample.java,v $
 * version $Revision: 36379 $
 * created 18.08.2014 12:02 by afevma
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
package ru.CryptoPro.ACSPClientApp.client.example;

/**
 * Класс XMLSignVerifyExample реализует пример
 * создания и проверки XML подписи.
 *
 * @author Copyright 2004-2014 Crypto-Pro. All rights reserved.
 * @.Version
 */
public class XMLSignVerifyExample /*extends IXMLData*/ {

    /**
     * Конструктор.
     *
     * @param adapter Настройки примера.
     */
    /*public XMLSignVerifyExample(ContainerAdapter adapter) {
        super(adapter);
    }

    @Override
    public void getResult(LogCallback callback) throws Exception {

        callback.log("Load key container to sign XML data.");

        // Тип контейнера по умолчанию.
        String keyStoreType = KeyStoreType.currentType();
        callback.log("Default container type: " + keyStoreType);

        // Загрузка ключа и сертификата.
        load(askPinInDialog, keyStoreType, containerAdapter.getClientAlias(),
            containerAdapter.getClientPassword(), callback);

        if (getPrivateKey() == null) {
            callback.log("Private key is null.");
            return;
        } // if

        // Создание документа.
        callback.log("Creating of XML document.");
        Document doc = createSampleDocument();

        // Вывод в лог.
        byte[] docContent = prepareLogXML(doc);
        callback.log(docContent, false);

        // Определение алгоритмов.
        String defaultSignAlgUrn = Consts.URN_GOST_SIGN;
        String defaultDigestAlgUrn = Consts.URN_GOST_DIGEST;

        if (providerType.equals(AlgorithmSelector.DefaultProviderType.pt2012Short)) {
            defaultSignAlgUrn = Consts.URN_GOST_SIGN_2012_256;
            defaultDigestAlgUrn = Consts.URN_GOST_DIGEST_2012_256;
        } // if
        else if (providerType.equals(AlgorithmSelector.DefaultProviderType.pt2012Long)) {
            defaultSignAlgUrn = Consts.URN_GOST_SIGN_2012_512;
            defaultDigestAlgUrn = Consts.URN_GOST_DIGEST_2012_512;
        } // else

        // Подпись документа.
        callback.log("Signing of XML document.");
        signDoc(doc, getPrivateKey(), getCertificate(),
            defaultSignAlgUrn, defaultDigestAlgUrn,callback);

        // Вывод в лог подписанного документа.
        callback.log("Signed XML document:");
        byte[] docSignedContent = prepareLogXML(doc);
        callback.log(docSignedContent, false);

        // Проверка подписи документа.
        callback.log("Verifying of XML document.");
        if (!verifyDoc(doc, callback)) {
            throw new Exception("Invalid XML signature.");
        } // if

        callback.setStatusOK();

    }

    @Override
    protected Document createSampleDocument()
        throws ParserConfigurationException {

        DocumentBuilderFactory dbf = createDocFactory();
        Document document = dbf.newDocumentBuilder().newDocument();

        Element root = document.createElementNS("http://www.apache.org/ns/#app1",
            "apache:RootElement");
        root.setAttributeNS(Constants.NamespaceSpecNS, "xmlns:apache",
            "http://www.apache.org/ns/#app1");

        document.appendChild(root);
        root.appendChild(document.createTextNode("\n"));

        Element childElement = document.createElementNS(
            "http://www.apache.org/ns/#app1", "apache:foo");
        childElement.appendChild(document.createTextNode("Some simple text"));

        root.appendChild(childElement);
        root.appendChild(document.createTextNode("\n"));

        return document;
    }

    @Override
    protected void signDoc(Document doc, PrivateKey privateKey,
        X509Certificate cert, String signMethod, String digestMethod,
        LogCallback callback) throws Exception {

        XMLSignature sig = new XMLSignature(doc, "", signMethod);
        Element anElement = doc.getDocumentElement();

        callback.log("Add signature element.");
        anElement.appendChild(sig.getElement());

        callback.log("Apply transformations.");
        Transforms transforms = new Transforms(doc);

        transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
        transforms.addTransform(Transforms.TRANSFORM_C14N_WITH_COMMENTS);

        sig.addDocument("", transforms, digestMethod);
        sig.addKeyInfo(cert);

        sig.sign(privateKey);
        callback.log("XML document is signed.");

    }

    /**
     * Извлечение узла подписи.
     *
     * @param doc Подписанный XML документ.
     * @return узел подписи.
     * @throws Exception
     */
    /*private Element getSignature(Document doc) throws Exception {
        Element context = doc.createElementNS(null, "namespaceContext");
        context.setAttributeNS(Constants.NamespaceSpecNS, "xmlns:" + "ds",
            Constants.SignatureSpecNS);
        return Element XPathAPI.selectSingleNode(doc, "//ds:Signature[1]", context);

    }

    @Override
    protected boolean verifyDoc(Document doc, LogCallback callback)
        throws Exception {

        callback.log("Search for signature element.");
        Element sigElement = getSignature(doc);
        XMLSignature signature = new XMLSignature(sigElement, "");

        callback.log("Search for key information.");
        KeyInfo ki = signature.getKeyInfo();
        X509Certificate certKey = ki.getX509Certificate();

        if (certKey == null) {
            throw new Exception("There are no information about public key.");
        } // if

        callback.log("Check signature.");
        return signature.checkSignatureValue(certKey);

    }*/

}
