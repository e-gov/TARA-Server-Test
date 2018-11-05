package ee.ria.tara;

import com.nimbusds.jose.jwk.JWKSet;
import ee.ria.tara.config.IntegrationTest;
import ee.ria.tara.config.TestConfiguration;
import ee.ria.tara.config.TestTaraProperties;
import ee.ria.tara.utils.OpenSAMLUtils;
import ee.ria.tara.utils.ResponseBuilderUtils;
import ee.ria.tara.utils.SystemPropertyActiveProfileResolver;
import ee.ria.tara.utils.XmlUtils;
import io.restassured.path.xml.XmlPath;
import io.restassured.response.Response;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.Criterion;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.CredentialSupport;
import org.opensaml.security.credential.impl.KeyStoreCredentialResolver;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.security.x509.X509Credential;
import org.opensaml.security.x509.X509Support;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ResourceLoader;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;

import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import static ee.ria.tara.config.TaraTestStrings.*;
import static io.restassured.RestAssured.config;
import static io.restassured.RestAssured.given;
import static io.restassured.config.EncoderConfig.encoderConfig;

@RunWith(SpringRunner.class)
@Category(IntegrationTest.class)
@ContextConfiguration(classes = TestConfiguration.class)
@ActiveProfiles(profiles = {"dev"}, resolver = SystemPropertyActiveProfileResolver.class)
public abstract class TestsBase {

    @Autowired
    protected TestTaraProperties testTaraProperties;

    @Autowired
    private ResourceLoader resourceLoader;

    protected static JWKSet jwkSet;
    protected static String tokenIssuer;

    protected static Credential signatureCredential;
    protected static Credential encryptionCredential;

    protected Credential getCredential(KeyStore keystore, String keyPairId, String privateKeyPass) {
        try {
            Map<String, String> passwordMap = new HashMap<>();
            passwordMap.put(keyPairId, privateKeyPass);
            KeyStoreCredentialResolver resolver = new KeyStoreCredentialResolver(keystore, passwordMap);

            Criterion criterion = new EntityIdCriterion(keyPairId);
            CriteriaSet criteriaSet = new CriteriaSet();
            criteriaSet.add(criterion);

            return resolver.resolveSingle(criteriaSet);
        } catch (ResolverException e) {
            throw new RuntimeException("Something went wrong reading credentials", e);
        }
    }

    protected String getMetadataBody() {
        return given()
                .config(config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8")))
                .when()
                .get(testTaraProperties.getEidasNodeUrl() + testTaraProperties.getEidasNodeConnectorMetadataUrl())
                .then()
                .log().ifError()
                .statusCode(200)
                .extract()
                .body().asString();
    }

    String getIssuer(String url) {
        return given()
                .when()
                .get(url)
                .then()
                .extract().response().getBody().jsonPath().getString("issuer");
    }

    //TODO: Do not use, move to EidasResponseDataUtils in progress
    protected String getBase64SamlResponseMinimalAttributes(String requestBody, String givenName, String familyName, String personIdentifier, String dateOfBirth, String loa) {
        XmlPath xmlPath = getDecodedSamlRequestBodyXml(requestBody);
        if (loa == null) {
            loa = xmlPath.getString("AuthnRequest.RequestedAuthnContext.AuthnContextClassRef");
        }
        org.opensaml.saml.saml2.core.Response response = new ResponseBuilderUtils().buildAuthnResponse(signatureCredential, encryptionCredential, xmlPath.getString("AuthnRequest.@ID"),
                testTaraProperties.getEidasNodeUrl() + testTaraProperties.getEidasNodeResponseUrl(), loa, givenName, familyName, personIdentifier, dateOfBirth, testTaraProperties.getEidasNodeUrl() + testTaraProperties.getEidasNodeServiceMetadataUrl(), 5, testTaraProperties.getEidasNodeUrl() + testTaraProperties.getEidasNodeConnectorMetadataUrl());
        String stringResponse = OpenSAMLUtils.getXmlString(response);
        validateSamlResponseSignature(stringResponse);
        return new String(Base64.getEncoder().encode(stringResponse.getBytes()));
    }

    protected String getBase64SamlResponseDefaultMaximalAttributes(String requestBody) {
        XmlPath xmlPath = getDecodedSamlRequestBodyXml(requestBody);
        String loa = xmlPath.getString("AuthnRequest.RequestedAuthnContext.AuthnContextClassRef");
        org.opensaml.saml.saml2.core.Response response = new ResponseBuilderUtils().buildAuthnResponseWithMaxAttributes(signatureCredential, encryptionCredential, xmlPath.getString("AuthnRequest.@ID"),
                testTaraProperties.getEidasNodeUrl() + testTaraProperties.getEidasNodeResponseUrl(), loa, DEFATTR_FIRST, DEFATTR_FAMILY, DEFATTR_PNO, DEFATTR_DATE, DEFATTR_BIRTH_NAME, DEFATTR_BIRTH_PLACE, DEFATTR_ADDR, DEFATTR_GENDER, testTaraProperties.getEidasNodeUrl() + testTaraProperties.getEidasNodeServiceMetadataUrl(), 5, testTaraProperties.getEidasNodeUrl() + testTaraProperties.getEidasNodeConnectorMetadataUrl());
        String stringResponse = OpenSAMLUtils.getXmlString(response);
        validateSamlResponseSignature(stringResponse);
        return new String(Base64.getEncoder().encode(stringResponse.getBytes()));
    }

    protected String getBase64SamlResponseLegalMaximalAttributes(String requestBody) {
        XmlPath xmlPath = getDecodedSamlRequestBodyXml(requestBody);
        org.opensaml.saml.saml2.core.Response response = new ResponseBuilderUtils().buildAuthnResponseWithMaxLegalAttributes(signatureCredential, encryptionCredential, xmlPath.getString("AuthnRequest.@ID"),
                testTaraProperties.getEidasNodeUrl() + testTaraProperties.getEidasNodeResponseUrl(), xmlPath.getString("AuthnRequest.RequestedAuthnContext.AuthnContextClassRef"), DEFATTR_FIRST, DEFATTR_FAMILY, DEFATTR_PNO,
                DEFATTR_DATE, DEFATTR_LEGAL_NAME, DEFATTR_LEGAL_PNO, testTaraProperties.getEidasNodeUrl() + testTaraProperties.getEidasNodeServiceMetadataUrl(), 5, testTaraProperties.getEidasNodeUrl() + testTaraProperties.getEidasNodeConnectorMetadataUrl(),
                DEFATTR_LEGAL_ADDRESS, DEFATTR_LEGAL_VATREGISTRATION, DEFATTR_LEGAL_TAXREFERENCE, DEFATTR_LEGAL_LEI, DEFATTR_LEGAL_EORI, DEFATTR_LEGAL_SEED, DEFATTR_LEGAL_SIC, DEFATTR_LEGAL_D201217EUIDENTIFIER);
        String stringResponse = OpenSAMLUtils.getXmlString(response);
        validateSamlResponseSignature(stringResponse);
        return new String(Base64.getEncoder().encode(stringResponse.getBytes()));
    }

    protected String getBase64SamlResponseWithErrors(String requestBody, String error) {
        XmlPath xmlPath = getDecodedSamlRequestBodyXml(requestBody);
        org.opensaml.saml.saml2.core.Response response = new ResponseBuilderUtils().buildAuthnResponseWithError(signatureCredential, xmlPath.getString("AuthnRequest.@ID"),
                testTaraProperties.getEidasNodeUrl() + testTaraProperties.getEidasNodeResponseUrl(), error, testTaraProperties.getEidasNodeUrl() + testTaraProperties.getEidasNodeServiceMetadataUrl(), 5, testTaraProperties.getEidasNodeUrl() + testTaraProperties.getEidasNodeConnectorMetadataUrl(), LOA_LOW);
        String stringResponse = OpenSAMLUtils.getXmlString(response);
        validateSamlResponseSignature(stringResponse);
        return new String(Base64.getEncoder().encode(stringResponse.getBytes()));
    }

    protected XmlPath getDecodedSamlRequestBodyXml(String body) {
        XmlPath html = new XmlPath(XmlPath.CompatibilityMode.HTML, body);
        String SAMLRequestString = html.getString("**.findAll { it.@name == 'SAMLRequest' }[0].@value");
        String decodedRequest = new String(Base64.getDecoder().decode(SAMLRequestString), StandardCharsets.UTF_8);
        XmlPath decodedSAMLrequest = new XmlPath(decodedRequest);
        return decodedSAMLrequest;
    }

    protected Credential getEncryptionCredentialFromMetaData(String body) throws CertificateException {
        java.security.cert.X509Certificate x509Certificate = getEncryptionCertificate(body);
        BasicX509Credential encryptionCredential = new BasicX509Credential(x509Certificate);
        return encryptionCredential;
    }

    protected java.security.cert.X509Certificate getEncryptionCertificate(String body) throws CertificateException {
        XmlPath metadataXml = new XmlPath(body);
        java.security.cert.X509Certificate x509 = X509Support.decodeCertificate(metadataXml.getString("**.findAll {it.@use == 'encryption'}.KeyInfo.X509Data.X509Certificate"));
        return x509;
    }

    protected Boolean validateSamlResponseSignature(String body) {
        XmlPath metadataXml = new XmlPath(body);
        try {
            java.security.cert.X509Certificate x509 = X509Support.decodeCertificate(metadataXml.getString("Response.Signature.KeyInfo.X509Data.X509Certificate"));
            validateSignature(body, x509);
            return true;
        } catch (CertificateException e) {
            throw new RuntimeException("Certificate parsing in validateSignature() failed:" + e.getMessage(), e);
        }
    }

    protected void validateSignature(String body, java.security.cert.X509Certificate x509) {
        try {
            x509.checkValidity();
            SignableSAMLObject signableObj = XmlUtils.unmarshallElement(body);
            X509Credential credential = CredentialSupport.getSimpleCredential(x509, null);
            SignatureValidator.validate(signableObj.getSignature(), credential);
        } catch (SignatureException e) {
            throw new RuntimeException("Signature validation in validateSignature() failed: " + e.getMessage(), e);
        } catch (CertificateNotYetValidException e) {
            throw new RuntimeException("Certificate is not yet valid: " + e.getMessage(), e);
        } catch (CertificateExpiredException e) {
            throw new RuntimeException("Certificate is expired: " + e.getMessage(), e);
        }
    }

    protected Boolean isEidasPresent(Response response) {
        String thisValue = response.htmlPath().getString("**.findAll { it.@id == 'collapseEidas' }.@aria-labelledby");
        if (thisValue.equals("methodEidas")) {
            return true;
        } else {
            return false;
        }
    }

    protected Boolean isMidPresent(Response response) {
        String thisValue = response.htmlPath().getString("**.findAll { it.@id == 'collapseMob' }.@aria-labelledby");
        if (thisValue.equals("methodMobID")) {
            return true;
        } else {
            return false;
        }
    }

    protected Boolean isIdCardPresent(Response response) {
        String thisValue = response.htmlPath().getString("**.findAll { it.@id == 'collapseOne' }.@aria-labelledby");
        if (thisValue.equals("methodIDCard")) {
            return true;
        } else {
            return false;
        }
    }

    protected Boolean isBankPresent(Response response) {
        String thisValue = response.htmlPath().getString("**.findAll { it.@id == 'collapseBank' }.@aria-labelledby");
        if (thisValue.equals("methodBank")) {
            return true;
        } else {
            return false;
        }
    }

    protected Boolean isSmartIdPresent(Response response) {
        String thisValue = response.htmlPath().getString("**.findAll { it.@id == 'collapseSmartIdForm' }.@aria-labelledby");
        if (thisValue.equals("methodSmartID")) {
            return true;
        } else {
            return false;
        }
    }

}
