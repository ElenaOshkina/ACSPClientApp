/**
 * $RCSfileXMLDSigRISignVerifyExample.java,v $
 * version $Revision: 36379 $
 * created 26.08.2014 11:13 by afevma
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

import org.apache.xml.security.transforms.Transforms;

import org.w3c.dom.Document;
import org.w3c.dom.Node;

import org.w3c.dom.NodeList;
import ru.CryptoPro.ACSPClientApp.client.LogCallback;
import ru.CryptoPro.ACSPClientApp.client.example.interfaces.ContainerAdapter;
import ru.CryptoPro.ACSPClientApp.client.example.interfaces.IXMLData;
import ru.CryptoPro.ACSPClientApp.util.AlgorithmSelector;
import ru.CryptoPro.ACSPClientApp.util.KeyStoreType;
import ru.CryptoPro.JCP.JCP;
import ru.CryptoPro.JCPxml.Consts;
import ru.CryptoPro.JCSP.JCSP;

import javax.xml.crypto.*;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;

import java.io.ByteArrayInputStream;
import java.security.Key;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

/**
 * Класс XMLSignVerifyExample реализует пример
 * создания и проверки XML подписи с помощью XMLDSigRI.
 *
 * @author Copyright 2004-2014 Crypto-Pro. All rights reserved.
 * @.Version
 */
public class XMLDSigRISignVerifyExample extends IXMLData {

    /**
     * Идентификатор узла в XML документе для подписи.
     */
    private static final String ID = "acct";

    /**
     * Пример XML документа для подписи.
     */
    private static final String XML_DATA =
        "<?xml version=\"1.0\"?>\n" +
            "<PatientRecord>\n" +
                "<Name>John Doe</Name>\n" +
                "<Account id=\"" + ID + "\">123456</Account>\n" +
                "<Visit date=\"10pm March 10, 2002\">\n" +
                "<Diagnosis>Broken second metacarpal</Diagnosis>\n" +
                "</Visit>\n" +
            "</PatientRecord>";

    /**
     * Класс XMLDSigRI провайдера.
     */
    private static final String XML_PROVIDER = "ru.CryptoPro.JCPxml.dsig.internal.dom.XMLDSigRI";

    /**
     * Переменная для задания провайдера подписи.
     */
    private static final String XML_CONTEXT_PROVIDER = "org.jcp.xml.dsig.internal.dom.SignatureProvider";

    /**
     * Конструктор.
     *
     * @param adapter Настройки примера.
     */
    public XMLDSigRISignVerifyExample(ContainerAdapter adapter) {
        super(adapter);
    }

    @Override
    public void getResult(LogCallback callback) throws Exception {

        callback.log("Load key container to sign XML data using XMLDSigRI.");

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

        signDoc(doc, getPrivateKey(), getCertificate(),
            defaultSignAlgUrn, defaultDigestAlgUrn, callback);

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
    protected Document createSampleDocument() throws Exception {
        DocumentBuilderFactory dbf = createDocFactory();
        return dbf.newDocumentBuilder().parse(
            new ByteArrayInputStream(XML_DATA.getBytes()));
    }

    @Override
    protected void signDoc(Document doc, PrivateKey privateKey,
        X509Certificate cert, String signMethod, String digestMethod,
        LogCallback callback) throws Exception {

        callback.log("Prepare signature factory.");
        final XMLSignatureFactory sigFactory = XMLSignatureFactory.getInstance(
            "DOM", (Provider) Class.forName(XML_PROVIDER).newInstance());

        Node sigParent = doc.getDocumentElement();
        String referenceURI = ""; // Пустая строка означает весь документ.

        callback.log("Prepare transformations.");
        List transforms = new ArrayList<Transform>() {{
            add(sigFactory.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null));
            add(sigFactory.newTransform(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS, (XMLStructure) null));
        }};

        callback.log("Create signature reference.");
        Reference ref = sigFactory.newReference(referenceURI,
            sigFactory.newDigestMethod(digestMethod, null),
                transforms, null, null);

        callback.log("Add new signed information.");
        SignedInfo signedInfo = sigFactory.newSignedInfo(
            sigFactory.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE,
            (C14NMethodParameterSpec) null),
            sigFactory.newSignatureMethod(signMethod, null),
            Collections.singletonList(ref)
        );

        callback.log("Prepare key information.");
        KeyInfoFactory keyInfoFactory = sigFactory.getKeyInfoFactory();
        X509Data x509d = keyInfoFactory.newX509Data(Collections.singletonList(cert));
        KeyInfo keyInfo = keyInfoFactory.newKeyInfo(Collections.singletonList(x509d));

        callback.log("Create signature context.");
        DOMSignContext sigCtx = new DOMSignContext(privateKey, sigParent);
        sigCtx.setProperty(XML_CONTEXT_PROVIDER, JCSP.PROVIDER_NAME); // по умолчанию используется JCP

        XMLSignature signature = sigFactory.newXMLSignature(signedInfo, keyInfo);
        signature.sign(sigCtx);
        callback.log("XML document is signed.");

    }

    @Override
    protected boolean verifyDoc(Document doc, LogCallback callback)
        throws Exception {

        callback.log("Search for signature element.");
        NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");

        if (nl.getLength() == 0) {
            throw new Exception("Cannot find Signature element");
        } // if

        callback.log("Prepare signature factory.");
        XMLSignatureFactory sigFactory = XMLSignatureFactory.getInstance("DOM",
            (Provider) Class.forName(XML_PROVIDER).newInstance());

        callback.log("Check all signatures.");
        boolean result = true;

        for (int i = 0; i < nl.getLength(); i++) {

            callback.log("Load signature #" + i);
            DOMValidateContext valCtx = new DOMValidateContext(
                new X509CertificateSelector(), nl.item(i));
            valCtx.setProperty(XML_CONTEXT_PROVIDER, JCSP.PROVIDER_NAME); // по умолчанию используется JCP

            callback.log("Decode and validate signature.");
            XMLSignature signature = sigFactory.unmarshalXMLSignature(valCtx);

            boolean coreValidity = signature.validate(valCtx);
            result = result && coreValidity;
            callback.log("Validated: " + coreValidity);

            if (!coreValidity) {

                callback.log(String.format("Signature %s failed core validation", i));

                boolean sv = signature.getSignatureValue().validate(valCtx);
                callback.log(String.format("Signature %s validation status: %s", i, sv));

                Iterator it = signature.getSignedInfo().getReferences().iterator();
                for (int j = 0; it.hasNext(); j++) {
                    boolean refValid = ((Reference) it.next()).validate(valCtx);
                    callback.log(String.format("Signature %s ref['%s'] validity status: %s", i, j, refValid));
                } // for
            } // if
            else {
                callback.log(String.format("Signature %s passed core validation", i));
            } // else
        } // for

        return result;
    }

    /**
     * Класс для хранения открытого ключа для
     * проверки подписи.
     *
     */
    private static class SimpleKeySelectorResult implements KeySelectorResult {

        private PublicKey pk;

        SimpleKeySelectorResult(PublicKey pk) {
            this.pk = pk;
        }

        public Key getKey() {
            return pk;
        }
    }

    /**
     * X509CertificateSelector возвращает открытый ключ из элемента
     * X509Certificate(X509Data).
     * NOTE: если алгоритм ключа не соответствует алгоритму подписи,
     * то открытый ключ не получим.
     */
    private static class X509CertificateSelector extends KeySelector {

        public KeySelectorResult select(KeyInfo keyInfo, KeySelector.Purpose purpose,
            AlgorithmMethod method, XMLCryptoContext context) throws KeySelectorException {

            if (keyInfo == null) {
                throw new KeySelectorException("Null KeyInfo object!");
            } // if

            SignatureMethod sm = (SignatureMethod) method;
            List list = keyInfo.getContent();

            for (int i = 0; i < list.size(); i++) {

                XMLStructure xmlStructure = (XMLStructure) list.get(i);

                if (xmlStructure instanceof X509Data) {

                    X509Data data = (X509Data)xmlStructure;
                    X509Certificate cert = (X509Certificate) data.getContent().get(0);
                    PublicKey pk = cert.getPublicKey();

                    if (algEquals(sm.getAlgorithm(), pk.getAlgorithm())) {
                        return new SimpleKeySelectorResult(pk);
                    } // if
                } // if
            } // for

            throw new KeySelectorException("No KeyValue element found!");

        }

        /**
         * Функция проверки алгоритма ключа.
         *
         * @param algURI Алгоритм подписи.
         * @param algName Алгоритм ключа.
         * @return True, если алгоритмы сопостовимы.
         */
        static boolean algEquals(String algURI, String algName) {

            if (algName.equalsIgnoreCase("DSA") &&
                algURI.equalsIgnoreCase(SignatureMethod.DSA_SHA1)) {
                return true;
            } // if
            else if (algName.equalsIgnoreCase("RSA") &&
                algURI.equalsIgnoreCase(SignatureMethod.RSA_SHA1)) {
                return true;
            } // else
            else if ((algName.equalsIgnoreCase(JCP.GOST_EL_DEGREE_NAME)) &&
                (algURI.equalsIgnoreCase(Consts.URI_GOST_SIGN) ||
                 algURI.equalsIgnoreCase(Consts.URN_GOST_SIGN))) {
                return true;
            } // else
            else if (algName.equalsIgnoreCase(JCP.GOST_EL_2012_256_NAME) &&
                algURI.equalsIgnoreCase(Consts.URN_GOST_SIGN_2012_256)) {
                return true;
            } // else
            else if (algName.equalsIgnoreCase(JCP.GOST_EL_2012_512_NAME) &&
                algURI.equalsIgnoreCase(Consts.URN_GOST_SIGN_2012_512)) {
                return true;
            } // else
            else {
                return false;
            } // else

        }
    }

}
