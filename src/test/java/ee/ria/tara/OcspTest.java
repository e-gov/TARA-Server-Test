package ee.ria.tara;


import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWTClaimsSet;
import ee.ria.tara.config.IntegrationTest;
import ee.ria.tara.config.TestTaraProperties;
import ee.ria.tara.model.OpenIdConnectFlow;
import ee.ria.tara.steps.IdCard;
import ee.ria.tara.steps.OcspMock;
import ee.ria.tara.steps.Requests;
import ee.ria.tara.steps.Steps;
import ee.ria.tara.utils.OpenIdConnectUtils;
import io.qameta.allure.Feature;
import io.restassured.response.Response;
import org.apache.commons.lang3.RandomUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.ResourceLoader;

import java.io.IOException;
import java.net.URL;
import java.security.Security;
import java.text.ParseException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import static ee.ria.tara.config.TaraTestStrings.OIDC_DEF_SCOPE;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.startsWith;

@SpringBootTest(classes = OcspTest.class)
@Category(IntegrationTest.class)
public class OcspTest extends TestsBase {
    @Autowired
    private ResourceLoader resourceLoader;
    private static boolean setupComplete = false;
    private OpenIdConnectFlow flow;


    @Before
    public void setUp() throws IOException, ParseException {
        if (!setupComplete) {
            initialize();
            setupComplete = true;
        }
        flow = new OpenIdConnectFlow();
        setupFlow(flow, testTaraProperties);
    }

    void setupFlow(OpenIdConnectFlow flow, TestTaraProperties properties) throws IOException, ParseException {
        flow.getOpenIDProvider().setJwkSet(jwkSet);
        flow.getOpenIDProvider().setIssuer(tokenIssuer);
        flow.setResourceLoader(resourceLoader);
        flow.setup(properties);
        flow.getOpenIDProvider().setJwksUrl(properties.getOcspTargetUrl() + properties.getJwksUrl());
        flow.getOpenIDProvider().setAuthorizeUrl(properties.getOcspTargetUrl() + properties.getAuthorizeUrl());
        flow.getOpenIDProvider().setTokenUrl(properties.getOcspTargetUrl() + properties.getTokenUrl());
        flow.getOpenIDProvider().setLoginUrl(properties.getOcspTargetUrl() + properties.getLoginUrl());
        flow.getOpenIDProvider().setBackendUrl(properties.getOcspBackendUrl());
    }

    public void initialize() throws IOException, ParseException {
        jwkSet = JWKSet.load(new URL(testTaraProperties.getFullJwksUrl()));
        tokenIssuer = getIssuer(testTaraProperties.getOcspTargetUrl() + testTaraProperties.getConfigurationUrl());
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    @Feature("OCSP-1")
    @Ignore("Needs TARA with mock OCSP")
    public void ocspStatusGood() throws Exception {
        Map<String, String> ocspResponseData = new HashMap<>();
        ocspResponseData.put("status", "good");
        OcspMock.setStatus(flow, "141811770701420873040773020899829622874", ocspResponseData);

        Response oidcResponse = IdCard.authenticateWithIdCard(flow, "141811770701420873040773020899829622874.pem", OIDC_DEF_SCOPE, "et");
        String token = Requests.getIdToken(flow, OpenIdConnectUtils.getCode(flow, oidcResponse.getHeader("location")));
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, token).getJWTClaimsSet();
        assertThat(claims.getSubject(), equalTo("EE37101010021"));
    }

    @Test
    @Feature("OCSP-1")
    @Ignore
    public void ocspStatusUnknown() throws Exception {
        Map<String, String> ocspResponseData = new HashMap<>();
        ocspResponseData.put("status", "unknown");
        OcspMock.setStatus(flow, "141811770701420873040773020899829622874", ocspResponseData);

        String errorMessage = IdCard.extractError(IdCard.authenticateWithIdAndReceiveError(flow, "141811770701420873040773020899829622874.pem", OIDC_DEF_SCOPE, "et"));
        assertThat(errorMessage, startsWith("Sertifikaadi küsimine ei õnnestunud. Palun proovige mõne aja pärast uuesti."));
    }

    @Test
    @Feature("OCSP-1")
    @Ignore
    public void ocspStatusRevoked() throws Exception {
        Map<String, String> ocspResponseData = new HashMap<>();
        ocspResponseData.put("status", "revoked");
        ocspResponseData.put("revoked_at", "2012-04-23T18:25:43.511Z");
        OcspMock.setStatus(flow, "141811770701420873040773020899829622874", ocspResponseData);

        String errorMessage = IdCard.extractError(IdCard.authenticateWithIdAndReceiveError(flow, "141811770701420873040773020899829622874.pem", OIDC_DEF_SCOPE, "et"));
        assertThat(errorMessage, startsWith("Sertifikaadi küsimine ei õnnestunud. Palun proovige mõne aja pärast uuesti."));
    }

    @Test
    @Feature("OCSP-1")
    @Ignore
    public void ocspProducedAtNotChecked() throws Exception {
        Map<String, Object> ocspResponseData = new HashMap<>();
        ocspResponseData.put("status", "good");
        ocspResponseData.put("produced_at", -905); //default allowed value is 900 seconds
        OcspMock.setStatus(flow, "141811770701420873040773020899829622874", ocspResponseData);

        String errorMessage = IdCard.extractError(IdCard.authenticateWithIdAndReceiveError(flow, "141811770701420873040773020899829622874.pem", OIDC_DEF_SCOPE, "et"));
        assertThat(errorMessage, startsWith("Sertifikaadi küsimine ei õnnestunud. Palun proovige mõne aja pärast uuesti."));
    }

    @Test
    @Feature("OCSP-1")
    @Ignore
    public void ocspThisUpdateInFuture() throws Exception {
        Map<String, Object> ocspResponseData = new HashMap<>();
        ocspResponseData.put("status", "good");
        ocspResponseData.put("this_update", 5); //Default clock skew is 2 seconds
        OcspMock.setStatus(flow, "141811770701420873040773020899829622874", ocspResponseData);

        String errorMessage = IdCard.extractError(IdCard.authenticateWithIdAndReceiveError(flow, "141811770701420873040773020899829622874.pem", OIDC_DEF_SCOPE, "et"));
        assertThat(errorMessage, startsWith("Sertifikaadi küsimine ei õnnestunud. Palun proovige mõne aja pärast uuesti."));
    }

    @Test
    @Feature("OCSP-1")
    @Ignore
    public void ocspThisUpdateTooOld() throws Exception {
        Map<String, Object> ocspResponseData = new HashMap<>();
        ocspResponseData.put("status", "good");
        ocspResponseData.put("this_update", -905); //default allowed value is 900 seconds
        OcspMock.setStatus(flow, "141811770701420873040773020899829622874", ocspResponseData);

        String errorMessage = IdCard.extractError(IdCard.authenticateWithIdAndReceiveError(flow, "141811770701420873040773020899829622874.pem", OIDC_DEF_SCOPE, "et"));
        assertThat(errorMessage, startsWith("Sertifikaadi küsimine ei õnnestunud. Palun proovige mõne aja pärast uuesti."));
    }

    @Test
    @Feature("OCSP-1")
    @Ignore
    public void ocspThisUpdateGoodEnough() throws Exception {
        Map<String, Object> ocspResponseData = new HashMap<>();
        ocspResponseData.put("status", "good");
        ocspResponseData.put("this_update", -895); //default allowed value is 900 seconds
        OcspMock.setStatus(flow, "141811770701420873040773020899829622874", ocspResponseData);

        Response oidcResponse = IdCard.authenticateWithIdCard(flow, "141811770701420873040773020899829622874.pem", OIDC_DEF_SCOPE, "et");
        String token = Requests.getIdToken(flow, OpenIdConnectUtils.getCode(flow, oidcResponse.getHeader("location")));
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, token).getJWTClaimsSet();
        assertThat(claims.getSubject(), equalTo("EE37101010021"));
    }

    @Test
    @Feature("OCSP-1")
    @Ignore
    public void ocspNonceMissing() throws Exception {
        Map<String, Object> ocspResponseData = new HashMap<>();
        ocspResponseData.put("status", "good");
        ocspResponseData.put("include_nonce", false);
        OcspMock.setStatus(flow, "141811770701420873040773020899829622874", ocspResponseData);

        String errorMessage = IdCard.extractError(IdCard.authenticateWithIdAndReceiveError(flow, "141811770701420873040773020899829622874.pem", OIDC_DEF_SCOPE, "et"));
        assertThat(errorMessage, startsWith("Sertifikaadi küsimine ei õnnestunud. Palun proovige mõne aja pärast uuesti."));
    }

    @Test
    @Feature("OCSP-1")
    @Ignore
    public void ocspNonceInvalid() throws Exception {
        Map<String, Object> ocspResponseData = new HashMap<>();
        ocspResponseData.put("status", "good");
        ocspResponseData.put("nonce", Base64.getEncoder().encodeToString((RandomUtils.nextBytes(20))));
        OcspMock.setStatus(flow, "141811770701420873040773020899829622874", ocspResponseData);

        String errorMessage = IdCard.extractError(IdCard.authenticateWithIdAndReceiveError(flow, "141811770701420873040773020899829622874.pem", OIDC_DEF_SCOPE, "et"));
        assertThat(errorMessage, startsWith("Sertifikaadi küsimine ei õnnestunud. Palun proovige mõne aja pärast uuesti."));
    }
}
