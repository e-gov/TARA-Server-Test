package ee.ria.tara;


import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWTClaimsSet;
import ee.ria.tara.config.IntegrationTest;
import ee.ria.tara.config.TestConfiguration;
import ee.ria.tara.config.TestTaraProperties;
import ee.ria.tara.model.OpenIdConnectFlow;
import ee.ria.tara.steps.Eidas;
import ee.ria.tara.steps.Requests;
import ee.ria.tara.steps.Steps;
import ee.ria.tara.utils.EidasResponseDataUtils;
import ee.ria.tara.utils.OpenIdConnectUtils;
import io.restassured.path.json.JsonPath;
import io.restassured.response.Response;
import lombok.AllArgsConstructor;
import lombok.Data;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;

import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.KeyStore;
import java.security.Security;
import java.text.ParseException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Map;

import static ee.ria.tara.config.TaraTestStrings.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.lessThanOrEqualTo;
import static org.hamcrest.core.StringStartsWith.startsWith;


@SpringBootTest(classes = EidasTest.class)
@Category(IntegrationTest.class)
public class EidasTest extends TestsBase {
    @Autowired
    private ResourceLoader resourceLoader;
    private static boolean setupComplete = false;
    private OpenIdConnectFlow flow;

    @Data
    @AllArgsConstructor
    class ExpectedOutput {
        private String subject;
        private String firstName;
        private String familyName;
        private String dateOfBirth;
        private String amr;
        private String acr;
    }

    @Before
    public void setUp() throws IOException, ParseException, InitializationException {
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
        flow.setEncryptionCredential(encryptionCredential);
        flow.setSignatureCredential(signatureCredential);
        flow.setup(properties);
    }

    public void initialize() throws IOException, ParseException, InitializationException {
        jwkSet = JWKSet.load(new URL(testTaraProperties.getFullJwksUrl()));
        tokenIssuer = getIssuer(testTaraProperties.getTargetUrl() + testTaraProperties.getConfigurationUrl());
        Security.addProvider(new BouncyCastleProvider());

        //For eIDAS
        InitializationService.initialize();
        Security.addProvider(new BouncyCastleProvider());
        try {
            KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            Resource resource = resourceLoader.getResource(testTaraProperties.getKeystore());
            keystore.load(resource.getInputStream(), testTaraProperties.getKeystorePass().toCharArray());
            signatureCredential = getCredential(keystore, testTaraProperties.getResponseSigningKeyId(), testTaraProperties.getResponseSigningKeyPass());
            encryptionCredential = getEncryptionCredentialFromMetaData(getMetadataBody());
        } catch (Exception e) {
            throw new RuntimeException("Something went wrong initializing credentials:", e);
        }
    }

    @Test
    public void eidas1_eidasAuthenticationMinAttrSuccess() throws URISyntaxException, ParseException, JOSEException, IOException, InterruptedException {

        Map<String, String> token = Eidas.eIDASAuthenticationWithScopeAndAcr(flow, DEF_COUNTRY, OIDC_DEF_SCOPE, "low");
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, token.get("id_token")).getJWTClaimsSet();

        ExpectedOutput expectedOutcome = new ExpectedOutput("EE30011092212", DEFATTR_FIRST, DEFATTR_FAMILY, DEFATTR_DATE, OIDC_AMR_EIDAS, OIDC_ACR_VALUES_SUBSTANTIAL);

        assertThat(claims.getSubject(), equalTo(expectedOutcome.getSubject()));
        assertThat(claims.getJSONObjectClaim("profile_attributes").getAsString("given_name"), equalTo(expectedOutcome.getFirstName()));
        assertThat(claims.getJSONObjectClaim("profile_attributes").getAsString("family_name"), equalTo(expectedOutcome.getFamilyName()));
        assertThat(claims.getJSONObjectClaim("profile_attributes").getAsString("date_of_birth"), equalTo(expectedOutcome.getDateOfBirth()));
        assertThat(claims.getStringArrayClaim("amr")[0], equalTo(expectedOutcome.getAmr()));

        assertValidUserinfoResponse(expectedOutcome, token.get("access_token"));
    }



    @Test
    public void eidas1_eidasAuthenticationMaxAttrSuccess() throws Exception {
        Response response = Eidas.initiateEidasAuthentication(flow, DEF_COUNTRY, OIDC_DEF_SCOPE, null);
        String relayState = response.htmlPath().getString("**.findAll { it.@name == 'RelayState' }[0].@value");

        //Here we need to simulate a response from foreign country eIDAS Node
        String samlResponse = EidasResponseDataUtils.getBase64SamlResponseDefaultMaximalAttributes(flow, response.getBody().asString());
        String location = Eidas.returnEidasResponse(flow, samlResponse, relayState);
        Response oidcResponse = Requests.followLoginRedirects(flow, location);
        Map<String, String> token = Requests.getTokenResponse(flow, OpenIdConnectUtils.getCode(flow, oidcResponse.getHeader("location")));
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, token.get("id_token")).getJWTClaimsSet();

        ExpectedOutput expectedOutcome = new ExpectedOutput("EE30011092212", DEFATTR_FIRST, DEFATTR_FAMILY, DEFATTR_DATE, OIDC_AMR_EIDAS, OIDC_ACR_VALUES_SUBSTANTIAL);

        assertThat(claims.getSubject(), equalTo(expectedOutcome.getSubject()));
        assertThat(claims.getJSONObjectClaim("profile_attributes").getAsString("given_name"), equalTo(expectedOutcome.getFirstName()));
        assertThat(claims.getJSONObjectClaim("profile_attributes").getAsString("family_name"), equalTo(expectedOutcome.getFamilyName()));
        assertThat(claims.getJSONObjectClaim("profile_attributes").getAsString("date_of_birth"), equalTo(expectedOutcome.getDateOfBirth()));
        assertThat(claims.getStringArrayClaim("amr")[0], equalTo(expectedOutcome.getAmr()));

        assertValidUserinfoResponse(expectedOutcome, token.get("access_token"));
    }

    @Test
    public void eidas1_eidasAuthenticationWithScope() throws Exception {
        Response response = Eidas.initiateEidasAuthentication(flow, DEF_COUNTRY, OIDC_OPENID_SCOPE + OIDC_EIDAS_SCOPE, null);
        String relayState = response.htmlPath().getString("**.findAll { it.@name == 'RelayState' }[0].@value");

        //Here we need to simulate a response from foreign country eIDAS Node
        String samlResponse = EidasResponseDataUtils.getBase64SamlResponseDefaultMaximalAttributes(flow, response.getBody().asString());
        String location = Eidas.returnEidasResponse(flow, samlResponse, relayState);
        Response oidcResponse = Requests.followLoginRedirects(flow, location);
        Map<String, String> token = Requests.getTokenResponse(flow, OpenIdConnectUtils.getCode(flow, oidcResponse.getHeader("location")));
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, token.get("id_token")).getJWTClaimsSet();

        ExpectedOutput expectedOutcome = new ExpectedOutput("EE30011092212", DEFATTR_FIRST, DEFATTR_FAMILY, DEFATTR_DATE, OIDC_AMR_EIDAS, OIDC_ACR_VALUES_SUBSTANTIAL);

        assertThat(claims.getSubject(), equalTo(expectedOutcome.getSubject()));
        assertThat(claims.getJSONObjectClaim("profile_attributes").getAsString("given_name"), equalTo(expectedOutcome.getFirstName()));
        assertThat(claims.getJSONObjectClaim("profile_attributes").getAsString("family_name"), equalTo(expectedOutcome.getFamilyName()));
        assertThat(claims.getJSONObjectClaim("profile_attributes").getAsString("date_of_birth"), equalTo(expectedOutcome.getDateOfBirth()));
        assertThat(claims.getStringArrayClaim("amr")[0], equalTo(expectedOutcome.getAmr()));

        assertValidUserinfoResponse(expectedOutcome, token.get("access_token"));
    }

    @Test
    //TODO: should use getBase64SamlResponseLegalMaximalAttributes?
    public void eidas1_eidasAuthenticationMaxLegalAttrSuccess() throws Exception {
        Response response = Eidas.initiateEidasAuthentication(flow, DEF_COUNTRY, OIDC_DEF_SCOPE, null);
        String relayState = response.htmlPath().getString("**.findAll { it.@name == 'RelayState' }[0].@value");

        //Here we need to simulate a response from foreign country eIDAS Node
        String samlResponse = EidasResponseDataUtils.getBase64SamlResponseDefaultMaximalAttributes(flow, response.getBody().asString());

        String location = Eidas.returnEidasResponse(flow, samlResponse, relayState);
        Response oidcResponse = Requests.followLoginRedirects(flow, location);
        Map<String, String> token = Requests.getTokenResponse(flow, OpenIdConnectUtils.getCode(flow, oidcResponse.getHeader("location")));
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, token.get("id_token")).getJWTClaimsSet();

        ExpectedOutput expectedOutcome = new ExpectedOutput("EE30011092212", DEFATTR_FIRST, DEFATTR_FAMILY, DEFATTR_DATE, OIDC_AMR_EIDAS, OIDC_ACR_VALUES_SUBSTANTIAL);
        assertThat(claims.getSubject(), equalTo(expectedOutcome.getSubject()));
        assertThat(claims.getJSONObjectClaim("profile_attributes").getAsString("given_name"), equalTo(expectedOutcome.getFirstName()));
        assertThat(claims.getJSONObjectClaim("profile_attributes").getAsString("family_name"), equalTo(expectedOutcome.getFamilyName()));
        assertThat(claims.getJSONObjectClaim("profile_attributes").getAsString("date_of_birth"), equalTo(expectedOutcome.getDateOfBirth()));
        assertThat(claims.getStringArrayClaim("amr")[0], equalTo(expectedOutcome.getAmr()));

        assertValidUserinfoResponse(expectedOutcome, token.get("access_token"));
    }

    @Test
    public void eidas2_eidasAuthenticationFailure() throws Exception {
        Response response = Eidas.initiateEidasAuthentication(flow, DEF_COUNTRY, OIDC_DEF_SCOPE, null);
        String relayState = response.htmlPath().getString("**.findAll { it.@name == 'RelayState' }[0].@value");

        //Here we need to simulate a response from foreign country eIDAS Node
        String samlResponse = EidasResponseDataUtils.getBase64SamlResponseWithErrors(flow, response.getBody().asString(), "AuthFailed");
        Response errorResponse = Eidas.returnEidasErrorResponse(flow, samlResponse, relayState);
        String error = (String) Steps.extractError(errorResponse).get(1);

        assertThat(error, startsWith("Autentimine ebaõnnestus"));
    }

    @Test
    public void eidas2_eidasConsentFailure() throws Exception {
        Response response = Eidas.initiateEidasAuthentication(flow, DEF_COUNTRY, OIDC_DEF_SCOPE, null);
        String relayState = response.htmlPath().getString("**.findAll { it.@name == 'RelayState' }[0].@value");

        //Here we need to simulate a response from foreign country eIDAS Node
        String samlResponse = EidasResponseDataUtils.getBase64SamlResponseWithErrors(flow, response.getBody().asString(), "ConsentNotGiven");
        Response errorResponse = Eidas.returnEidasErrorResponse(flow, samlResponse, relayState);

        String error = (String) Steps.extractError(errorResponse).get(1);

        assertThat(error, startsWith("Autentimine ebaõnnestus"));
    }

    @Test
    public void eidas2_eidasRandomFailure() throws Exception {
        Response response = Eidas.initiateEidasAuthentication(flow, DEF_COUNTRY, OIDC_DEF_SCOPE, null);
        String relayState = response.htmlPath().getString("**.findAll { it.@name == 'RelayState' }[0].@value");

        //Here we need to simulate a response from foreign country eIDAS Node
        String samlResponse = EidasResponseDataUtils.getBase64SamlResponseWithErrors(flow, response.getBody().asString(), "RandomFailure");
        Response errorResponse = Eidas.returnEidasErrorResponse(flow, samlResponse, relayState);
        String error = (String) Steps.extractError(errorResponse).get(1);

        assertThat(error, startsWith("Üldine viga"));
    }

    @Test
    public void eidas3_eidasAcrValueLowShouldReturnSuccess() throws Exception {

        Map<String, String> token = Eidas.eIDASAuthenticationWithScopeAndAcr(flow, DEF_COUNTRY, OIDC_DEF_SCOPE, OIDC_ACR_VALUES_LOW);
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, token.get("id_token")).getJWTClaimsSet();

        ExpectedOutput expectedOutcome = new ExpectedOutput("EE30011092212", DEFATTR_FIRST, DEFATTR_FAMILY, DEFATTR_DATE, OIDC_AMR_EIDAS, OIDC_ACR_VALUES_LOW);

        assertThat(claims.getSubject(), equalTo(expectedOutcome.getSubject()));
        assertThat(claims.getJSONObjectClaim("profile_attributes").getAsString("given_name"), equalTo(expectedOutcome.getFirstName()));
        assertThat(claims.getJSONObjectClaim("profile_attributes").getAsString("family_name"), equalTo(expectedOutcome.getFamilyName()));
        assertThat(claims.getJSONObjectClaim("profile_attributes").getAsString("date_of_birth"), equalTo(expectedOutcome.getDateOfBirth()));
        assertThat(claims.getStringArrayClaim("amr")[0], equalTo(expectedOutcome.getAmr()));
        assertThat(claims.getClaim("acr"), equalTo(expectedOutcome.getAcr()));

        assertValidUserinfoResponse(expectedOutcome, token.get("access_token"));
    }

    @Test
    public void eidas3_eidasAcrValueSubstantialShouldReturnSuccess() throws Exception {
        Map<String, String> token = Eidas.eIDASAuthenticationWithScopeAndAcr(flow, DEF_COUNTRY, OIDC_DEF_SCOPE, OIDC_ACR_VALUES_SUBSTANTIAL);
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, token.get("id_token")).getJWTClaimsSet();

        ExpectedOutput expectedOutcome = new ExpectedOutput("EE30011092212", DEFATTR_FIRST, DEFATTR_FAMILY, DEFATTR_DATE, OIDC_AMR_EIDAS, OIDC_ACR_VALUES_SUBSTANTIAL);

        assertThat(claims.getSubject(), equalTo(expectedOutcome.getSubject()));
        assertThat(claims.getJSONObjectClaim("profile_attributes").getAsString("given_name"), equalTo(expectedOutcome.getFirstName()));
        assertThat(claims.getJSONObjectClaim("profile_attributes").getAsString("family_name"), equalTo(expectedOutcome.getFamilyName()));
        assertThat(claims.getJSONObjectClaim("profile_attributes").getAsString("date_of_birth"), equalTo(expectedOutcome.getDateOfBirth()));
        assertThat(claims.getStringArrayClaim("amr")[0], equalTo(expectedOutcome.getAmr()));
        assertThat(claims.getClaim("acr"), equalTo(expectedOutcome.getAcr()));

        assertValidUserinfoResponse(expectedOutcome, token.get("access_token"));
    }

    @Test
    public void eidas3_eidasAcrValueHighShouldReturnSuccess() throws Exception {
        Map<String, String> token = Eidas.eIDASAuthenticationWithScopeAndAcr(flow, DEF_COUNTRY, OIDC_DEF_SCOPE, OIDC_ACR_VALUES_HIGH);
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, token.get("id_token")).getJWTClaimsSet();

        ExpectedOutput expectedOutcome = new ExpectedOutput("EE30011092212", DEFATTR_FIRST, DEFATTR_FAMILY, DEFATTR_DATE, OIDC_AMR_EIDAS, OIDC_ACR_VALUES_HIGH);

        assertThat(claims.getSubject(), equalTo(expectedOutcome.getSubject()));
        assertThat(claims.getJSONObjectClaim("profile_attributes").getAsString("given_name"), equalTo(expectedOutcome.getFirstName()));
        assertThat(claims.getJSONObjectClaim("profile_attributes").getAsString("family_name"), equalTo(expectedOutcome.getFamilyName()));
        assertThat(claims.getJSONObjectClaim("profile_attributes").getAsString("date_of_birth"), equalTo(expectedOutcome.getDateOfBirth()));
        assertThat(claims.getStringArrayClaim("amr")[0], equalTo(expectedOutcome.getAmr()));
        assertThat(claims.getClaim("acr"), equalTo(expectedOutcome.getAcr()));

        assertValidUserinfoResponse(expectedOutcome, token.get("access_token"));
    }

    @Test
    public void eidas3_eidasAcrValueDefaultShouldReturnSuccess() throws Exception {
        Map<String, String> token = Eidas.eIDASAuthenticationWithScopeAndAcr(flow, DEF_COUNTRY, OIDC_DEF_SCOPE, null);
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, token.get("id_token")).getJWTClaimsSet();

        ExpectedOutput expectedOutcome = new ExpectedOutput("EE30011092212", DEFATTR_FIRST, DEFATTR_FAMILY, DEFATTR_DATE, OIDC_AMR_EIDAS, OIDC_ACR_VALUES_SUBSTANTIAL);

        assertThat(claims.getSubject(), equalTo(expectedOutcome.getSubject()));
        assertThat(claims.getJSONObjectClaim("profile_attributes").getAsString("given_name"), equalTo(expectedOutcome.getFirstName()));
        assertThat(claims.getJSONObjectClaim("profile_attributes").getAsString("family_name"), equalTo(expectedOutcome.getFamilyName()));
        assertThat(claims.getJSONObjectClaim("profile_attributes").getAsString("date_of_birth"), equalTo(expectedOutcome.getDateOfBirth()));
        assertThat(claims.getStringArrayClaim("amr")[0], equalTo(expectedOutcome.getAmr()));
        assertThat(claims.getClaim("acr"), equalTo(expectedOutcome.getAcr()));

        assertValidUserinfoResponse(expectedOutcome, token.get("access_token"));
    }

    @Test
    public void eidas3_eidasAcrValueHigherLoaReturnedThanAskedShouldReturnSuccess() throws Exception {
        Response response = Eidas.initiateEidasAuthentication(flow, DEF_COUNTRY, OIDC_DEF_SCOPE, OIDC_ACR_VALUES_LOW);
        String relayState = response.htmlPath().getString("**.findAll { it.@name == 'RelayState' }[0].@value");

        //Here we need to simulate a response from foreign country eIDAS Node
        String samlResponse = EidasResponseDataUtils.getBase64SamlResponseMinimalAttributes(flow, response.getBody().asString(), DEFATTR_FIRST, DEFATTR_FAMILY, DEFATTR_PNO, DEFATTR_DATE, LOA_HIGH);

        String location = Eidas.returnEidasResponse(flow, samlResponse, relayState);
        Response oidcResponse = Requests.followLoginRedirects(flow, location);
        Map<String, String> token = Requests.getTokenResponse(flow, OpenIdConnectUtils.getCode(flow, oidcResponse.getHeader("location")));
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, token.get("id_token")).getJWTClaimsSet();


        ExpectedOutput expectedOutcome = new ExpectedOutput("EE30011092212", DEFATTR_FIRST, DEFATTR_FAMILY, DEFATTR_DATE, OIDC_AMR_EIDAS, OIDC_ACR_VALUES_HIGH);

        assertThat(claims.getSubject(), equalTo(expectedOutcome.getSubject()));
        assertThat(claims.getJSONObjectClaim("profile_attributes").getAsString("given_name"), equalTo(expectedOutcome.getFirstName()));
        assertThat(claims.getJSONObjectClaim("profile_attributes").getAsString("family_name"), equalTo(expectedOutcome.getFamilyName()));
        assertThat(claims.getJSONObjectClaim("profile_attributes").getAsString("date_of_birth"), equalTo(expectedOutcome.getDateOfBirth()));
        assertThat(claims.getStringArrayClaim("amr")[0], equalTo(expectedOutcome.getAmr()));
        assertThat(claims.getClaim("acr"), equalTo(expectedOutcome.getAcr()));

        assertValidUserinfoResponse(expectedOutcome, token.get("access_token"));
    }

    @Test
    public void eidas3_eidasAcrValueLowerLoaReturnedThanAskedShouldReturnError() throws Exception {
        Response response = Eidas.initiateEidasAuthentication(flow, DEF_COUNTRY, OIDC_DEF_SCOPE, OIDC_ACR_VALUES_SUBSTANTIAL);
        String relayState = response.htmlPath().getString("**.findAll { it.@name == 'RelayState' }[0].@value");

        //Here we need to simulate a response from foreign country eIDAS Node
        String samlResponse = EidasResponseDataUtils.getBase64SamlResponseMinimalAttributes(flow, response.getBody().asString(), DEFATTR_FIRST, DEFATTR_FAMILY, DEFATTR_PNO, DEFATTR_DATE, LOA_LOW);

        Response errorResponse = Eidas.returnEidasFailureResponse(flow, samlResponse, relayState);
        String error = errorResponse.htmlPath().getString("**.findAll { it.@class=='sub-title' }");

        assertThat(error, equalTo("An unexpected error has occurred"));
    }

    @Test
    @Ignore("Requires CSP with form-action")
    public void eidas3_eidasUrlInCspHeader() throws URISyntaxException, ParseException, JOSEException, IOException, InterruptedException {
        Response taraLoginPage = Requests.getAuthenticationMethodsPageWithScope(flow, OIDC_DEF_SCOPE);

        String execution = taraLoginPage.getBody().htmlPath().getString("**.findAll { it.@name == 'execution' }[0].@value");
        Response redirectResponse = Eidas.submitEidasLogin(flow, DEF_COUNTRY, execution);
        String eidasRedirectUrl = redirectResponse.htmlPath().getString("**.find {it.@enctype =='application/x-www-form-urlencoded'}.@action");
        redirectResponse.then()
                .header("Content-Security-Policy", containsString(
                        "form-action " + eidasRedirectUrl + " 'self' " + flow.getTestProperties().getManageUrl() + " " + flow.getRelyingParty().getRedirectUri()));

    }

    private void assertValidUserinfoResponse(ExpectedOutput expectedOutcome, String accessToken) {
        assertValidUserinfoResponse(
                expectedOutcome,
                Requests.getUserInfoWithAccessTokenAsBearerToken(flow, accessToken, flow.getOpenIDProvider().getUserInfoUrl())
        );

        assertValidUserinfoResponse(
                expectedOutcome,
                Requests.getUserInfoWithAccessTokenAsQueryParameter(flow, accessToken, flow.getOpenIDProvider().getUserInfoUrl())
        );
    }

    private void assertValidUserinfoResponse(ExpectedOutput expectedOutcome, Response userInfoResponse) {
        JsonPath json = userInfoResponse.jsonPath();
        assertThat(json.getMap("$.").keySet(), hasItems("sub", "auth_time", "given_name", "family_name", "date_of_birth", "acr", "amr"));
        assertThat(json.get("sub"), equalTo(expectedOutcome.getSubject()));
        assertThat("auth_time must be a unix timestamp format and within the allowed timeframe", json.getLong("auth_time"), is(both(greaterThan(new Long(Instant.now().getEpochSecond() - TestConfiguration.ALLOWED_TIME_DIFFERENCE_IN_SECONDS))).and(lessThanOrEqualTo(Instant.now().getEpochSecond()))));
        assertThat(json.get("given_name"), equalTo(expectedOutcome.getFirstName()));
        assertThat(json.get("family_name"), equalTo(expectedOutcome.getFamilyName()));
        assertThat(json.get("date_of_birth"), equalTo(expectedOutcome.getDateOfBirth()));
        assertThat(json.get("acr"), equalTo(expectedOutcome.getAcr()));
        assertThat(json.getList("amr"), equalTo(Arrays.asList(expectedOutcome.getAmr())));
    }
}
