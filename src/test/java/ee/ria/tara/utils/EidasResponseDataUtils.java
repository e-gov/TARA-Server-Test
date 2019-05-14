package ee.ria.tara.utils;

import ee.ria.tara.model.OpenIdConnectFlow;
import io.restassured.path.xml.XmlPath;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.security.credential.CredentialSupport;
import org.opensaml.security.x509.X509Credential;
import org.opensaml.security.x509.X509Support;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureValidator;

import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.util.Base64;

import static ee.ria.tara.config.TaraTestStrings.*;
import static ee.ria.tara.config.TaraTestStrings.DEFATTR_GENDER;

public class EidasResponseDataUtils {
    public static String getBase64SamlResponseMinimalAttributes(OpenIdConnectFlow flow, String requestBody, String givenName, String familyName, String personIdentifier, String dateOfBirth, String loa) {
        XmlPath xmlPath = getDecodedSamlRequestBodyXml(requestBody);
        if (loa == null) {
            loa = xmlPath.getString("AuthnRequest.RequestedAuthnContext.AuthnContextClassRef");
        }
        org.opensaml.saml.saml2.core.Response response = new ResponseBuilderUtils().buildAuthnResponse(flow.getSignatureCredential(), flow.getEncryptionCredential(), xmlPath.getString("AuthnRequest.@ID"),
                flow.getTestProperties().getEidasNodeUrl() + flow.getTestProperties().getEidasNodeResponseUrl(), loa, givenName, familyName, personIdentifier, dateOfBirth, flow.getTestProperties().getEidasNodeUrl() + flow.getTestProperties().getEidasNodeServiceMetadataUrl(), 5, flow.getTestProperties().getEidasNodeUrl() + flow.getTestProperties().getEidasNodeConnectorMetadataUrl());
        String stringResponse = OpenSAMLUtils.getXmlString(response);
        validateSamlResponseSignature(stringResponse);
        return new String(Base64.getEncoder().encode(stringResponse.getBytes()));
    }
    public static String getBase64SamlResponseDefaultMaximalAttributes(OpenIdConnectFlow flow, String requestBody) {
        XmlPath xmlPath = getDecodedSamlRequestBodyXml(requestBody);
        String loa = xmlPath.getString("AuthnRequest.RequestedAuthnContext.AuthnContextClassRef");
        org.opensaml.saml.saml2.core.Response response = new ResponseBuilderUtils().buildAuthnResponseWithMaxAttributes(flow.getSignatureCredential(), flow.getEncryptionCredential(), xmlPath.getString("AuthnRequest.@ID"),
                flow.getTestProperties().getEidasNodeUrl() + flow.getTestProperties().getEidasNodeResponseUrl(), loa, DEFATTR_FIRST, DEFATTR_FAMILY, DEFATTR_PNO, DEFATTR_DATE, DEFATTR_BIRTH_NAME, DEFATTR_BIRTH_PLACE, DEFATTR_ADDR, DEFATTR_GENDER, flow.getTestProperties().getEidasNodeUrl() + flow.getTestProperties().getEidasNodeServiceMetadataUrl(), 5, flow.getTestProperties().getEidasNodeUrl() + flow.getTestProperties().getEidasNodeConnectorMetadataUrl());
        String stringResponse = OpenSAMLUtils.getXmlString(response);
        validateSamlResponseSignature(stringResponse);
        return new String(Base64.getEncoder().encode(stringResponse.getBytes()));
    }

    public static String getBase64SamlResponseWithErrors(OpenIdConnectFlow flow, String requestBody, String error) {
        XmlPath xmlPath = getDecodedSamlRequestBodyXml(requestBody);
        org.opensaml.saml.saml2.core.Response response = new ResponseBuilderUtils().buildAuthnResponseWithError(flow.getSignatureCredential(), xmlPath.getString("AuthnRequest.@ID"),
                flow.getTestProperties().getEidasNodeUrl() + flow.getTestProperties().getEidasNodeResponseUrl(), error, flow.getTestProperties().getEidasNodeUrl() + flow.getTestProperties().getEidasNodeServiceMetadataUrl(), 5, flow.getTestProperties().getEidasNodeUrl() + flow.getTestProperties().getEidasNodeConnectorMetadataUrl(), LOA_LOW);
        String stringResponse = OpenSAMLUtils.getXmlString(response);
        validateSamlResponseSignature(stringResponse);
        return new String(Base64.getEncoder().encode(stringResponse.getBytes()));
    }
    
    public static XmlPath getDecodedSamlRequestBodyXml(String body) {
        XmlPath html = new XmlPath(XmlPath.CompatibilityMode.HTML, body);
        String SAMLRequestString = html.getString("**.findAll { it.@name == 'SAMLRequest' }[0].@value");
        String decodedRequest = new String(Base64.getDecoder().decode(SAMLRequestString), StandardCharsets.UTF_8);
        XmlPath decodedSAMLrequest = new XmlPath(decodedRequest);
        return decodedSAMLrequest;
    }
    public static Boolean validateSamlResponseSignature(String body) {
        XmlPath metadataXml = new XmlPath(body);
        try {
            java.security.cert.X509Certificate x509 = X509Support.decodeCertificate(metadataXml.getString("Response.Signature.KeyInfo.X509Data.X509Certificate"));
            validateSignature(body, x509);
            return true;
        } catch (CertificateException e) {
            throw new RuntimeException("Certificate parsing in validateSignature() failed:" + e.getMessage(), e);
        }
    }
    public static void validateSignature(String body, java.security.cert.X509Certificate x509) {
        try {
            x509.checkValidity();
            SignableSAMLObject signableObj = XmlUtils.unmarshallElement(body);
            X509Credential credential = CredentialSupport.getSimpleCredential(x509, null);
            SignatureValidator.validate(signableObj.getSignature(), credential);
        } catch (SignatureException e) {
            throw new RuntimeException("Signature validation in validateSignature() failed: " + e.getMessage(), e);
        } catch (CertificateNotYetValidException e) {
            //Expired certificates are used in test environment
            return;
        } catch (CertificateExpiredException e) {
            //Expired certificates are used in test environment
            return;
        }
    }
}
