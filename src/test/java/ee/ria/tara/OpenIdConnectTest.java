package ee.ria.tara;


import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.SignedJWT;
import ee.ria.tara.config.IntegrationTest;
import ee.ria.tara.config.TestTaraProperties;
import ee.ria.tara.model.OpenIdConnectFlow;
import ee.ria.tara.steps.Eidas;
import ee.ria.tara.steps.MobileId;
import ee.ria.tara.steps.Requests;
import ee.ria.tara.steps.Steps;
import ee.ria.tara.utils.EidasResponseDataUtils;
import ee.ria.tara.utils.OpenIdConnectUtils;
import io.restassured.response.Response;
import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URLEncodedUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.Security;
import java.text.ParseException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static ee.ria.tara.config.TaraTestStrings.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.isEmptyOrNullString;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.Assert.assertEquals;


@SpringBootTest(classes = OpenIdConnectTest.class)
@Category(IntegrationTest.class)
public class OpenIdConnectTest extends TestsBase {
    @Autowired
    private ResourceLoader resourceLoader;
    private static boolean setupComplete = false;
    private OpenIdConnectFlow flow;

    @Before
    public void setUp() throws IOException, ParseException, InitializationException {
        if (!setupComplete) {
            initialize();
            setupComplete = true;
        }
        flow = new OpenIdConnectFlow();
        setupFlow(flow, testTaraProperties);
    }

    private void setupFlow(OpenIdConnectFlow flow, TestTaraProperties properties) throws IOException, ParseException {
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
    public void oidc1_authenticationWithMidShouldSucceed() throws Exception {
        Response oidcResponse = MobileId.authenticateWithMobileId(flow, "00000766", "60001019906", 7000, OIDC_DEF_SCOPE);
        String token = Requests.getIdToken(flow, OpenIdConnectUtils.getCode(flow, oidcResponse.getHeader("location")));
        SignedJWT signedJWT = Steps.verifyTokenAndReturnSignedJwtObject(flow, token);

        assertEquals(OIDC_AMR_MID, signedJWT.getJWTClaimsSet().getStringArrayClaim("amr")[0]);
        assertEquals("EE60001019906", signedJWT.getJWTClaimsSet().getSubject());
        assertEquals("MARY ÄNN", signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("given_name"));
        assertEquals("O’CONNEŽ-ŠUSLIK TESTNUMBER", signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("family_name"));
        assertEquals(null, signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("mobile_number"));
        assertEquals("2000-01-01", signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("date_of_birth"));
    }

    @Test
    public void oidc1_authenticationWithEidasShouldSucceed() throws Exception {
        Response response = Eidas.initiateEidasAuthentication(flow, DEF_COUNTRY, OIDC_DEF_SCOPE, null);
        String relayState = response.htmlPath().getString("**.findAll { it.@name == 'RelayState' }[0].@value");

        //Here we need to simulate a response from foreign country eIDAS Node
        String samlResponse = EidasResponseDataUtils.getBase64SamlResponseMinimalAttributes(flow, response.getBody().asString(), DEFATTR_FIRST, DEFATTR_FAMILY, DEFATTR_PNO, DEFATTR_DATE, LOA_SUBSTANTIAL);

        String location = Eidas.returnEidasResponse(flow, samlResponse, relayState);
        Response oidcResponse = Requests.followLoginRedirects(flow, location);
        String token = Requests.getIdToken(flow, OpenIdConnectUtils.getCode(flow, oidcResponse.getHeader("location")));
        SignedJWT signedJWT = Steps.verifyTokenAndReturnSignedJwtObject(flow, token);

        assertEquals("EE30011092212", signedJWT.getJWTClaimsSet().getSubject());
        assertEquals(DEFATTR_FIRST, signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("given_name"));
        assertEquals(DEFATTR_FAMILY, signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("family_name"));
        assertEquals(DEFATTR_DATE, signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("date_of_birth"));
        assertEquals(OIDC_AMR_EIDAS, signedJWT.getJWTClaimsSet().getStringArrayClaim("amr")[0]);
    }

    @Test
    public void oidc2_requestTokenTwiceShouldFail() throws Exception {
        Response oidcResponse = MobileId.authenticateWithMobileId(flow, "00000766", "60001019906", 7000, OIDC_DEF_SCOPE);
        Requests.getIdToken(flow, OpenIdConnectUtils.getCode(flow, oidcResponse.getHeader("location")));

        Response response = Requests.postToTokenEndpoint(flow, OpenIdConnectUtils.getCode(flow, oidcResponse.getHeader("location")));
        assertEquals(400, response.statusCode());
        assertEquals("invalid_grant", response.body().jsonPath().getString("error"));
    }

    @Test //TODO: Error handling is changed with AUT-57
    public void oidc2_mandatoryScopeMissingErrorMustBeReturned() throws Exception {
        Response response = Requests.getAuthenticationMethodsPageWithScope(flow, "eidasonly");
        assertThat("openid scope must be present error", response.body().asString(), startsWith("RESPONSE ERROR: invalid_scope - Required scope <openid> not provided."));
    }

    @Test //TODO: Error handling is changed with AUT-57
    public void oidc2_emptyScopeErrorMustBeReturned() throws Exception {
        Response response = Requests.getAuthenticationMethodsPageWithScope(flow, null);
        assertThat("scope missing error", response.body().asString(), startsWith("RESPONSE ERROR: invalid_scope - No value found in the request for <scope> parameter"));
    }

    @Test //TODO: Error handling is changed with AUT-57
    public void oidc2_notKnownScopeErrorMustBeReturned() throws Exception {
        Response response = Requests.getAuthenticationMethodsPageWithScope(flow, "openid newscope");
        assertThat("scope missing error", response.body().asString(), startsWith("RESPONSE ERROR: invalid_scope - One or some of the provided scopes are not allowed by TARA, only <openid, eidasonly> are permitted."));
    }

    @Test
    public void oidc2_incorrectSecretShouldReturnError() throws Exception {
        Response oidcResponse = MobileId.authenticateWithMobileId(flow, "00000766", "60001019906", 3000, OIDC_DEF_SCOPE);
        flow.getRelyingParty().setSecret("invalid_secret");
        Response response = Requests.postToTokenEndpoint(flow, OpenIdConnectUtils.getCode(flow, oidcResponse.getHeader("location")));
        assertEquals(401, response.statusCode());
        assertEquals("invalid_client", response.body().jsonPath().getString("error"));
    }

    @Test
    public void oidc2_incorrectAuthorizationCodeShouldReturnError() throws Exception {
        Response oidcResponse = MobileId.authenticateWithMobileId(flow, "00000766", "60001019906", 3000, OIDC_DEF_SCOPE);
        String authorizationCode = OpenIdConnectUtils.getCode(flow, oidcResponse.getHeader("location"));
        Response response = Requests.postToTokenEndpoint(flow, authorizationCode + "a");

        assertEquals(400, response.statusCode());
        assertEquals("invalid_grant", response.body().jsonPath().getString("error"));
    }

    @Test
    public void oidc2_missingAuthorizationCodeShouldReturnError() throws Exception {
        Map<String, String> params = new HashMap<>();
        params.put("grant_type", "authorization_code");
        params.put("redirect_uri", flow.getRelyingParty().getRedirectUri());
        Response response = Requests.postToTokenEndpoint(flow, params);
        assertEquals(400, response.statusCode());
        assertEquals("invalid_request", response.body().jsonPath().getString("error"));
    }

    @Test
    public void oidc2_missingGrantTypeShouldReturnError() throws Exception {
        Response oidcResponse = MobileId.authenticateWithMobileId(flow, "00000766", "60001019906", 3000, OIDC_DEF_SCOPE);
        String authorizationCode = OpenIdConnectUtils.getCode(flow, oidcResponse.getHeader("location"));

        Map<String, String> params = new HashMap<>();
        params.put("code", authorizationCode);
        params.put("redirect_uri", testTaraProperties.getTestRedirectUri());
        Response response = Requests.postToTokenEndpoint(flow, params);
        assertEquals(400, response.statusCode());
        assertEquals("invalid_request", response.body().jsonPath().getString("error"));
    }

    @Test
    public void oidc2_unsupportedResponseTypeShouldReturnError() throws Exception {
        Map<String, Object> queryParams = OpenIdConnectUtils.getAuthorizationRequestData(flow);
        queryParams.put("response_type", "token");

        Response response = Requests.getAuthenticationMethodsPageWithParameters(flow, queryParams);
        assertThat("Only supported response_type is allowed", response.body().asString(), startsWith("RESPONSE ERROR: unsupported_response_type - Provided response type is not allowed by TARA, only <code> is permitted"));
    }

    @Test
    public void oidc2_mandatoryClientIdMissingMustReturnError() throws Exception {
        Map queryParams = OpenIdConnectUtils.getAuthorizationRequestData(flow);
        queryParams.remove("client_id");
        Response response = Requests.getAuthenticationMethodsPageWithParameters(flow, queryParams);
        assertThat("client_id is mandatory parameter", response.body().asString(), startsWith("RESPONSE ERROR: invalid_client - No value found in the request for <client_id> parameter"));
    }

    @Test
    public void oidc2_mandatoryStateMissingMustReturnError() throws Exception {
        Map queryParams = OpenIdConnectUtils.getAuthorizationRequestData(flow);
        Response response = Requests.getAuthenticationMethodsPageWithoutStateOrNonce(flow, queryParams);

        assertThat("State is mandatory parameter", response.body().asString(), startsWith("RESPONSE ERROR: invalid_request - No value found in the request for <state> parameter"));
    }

    @Test //TODO: Error handling is changed with AUT-57
    public void oidc2_mandatoryRedirectUriMissingMustReturnError() {
        Map queryParams = OpenIdConnectUtils.getAuthorizationRequestData(flow);
        queryParams.remove("redirect_uri");
        Response response = Requests.openIdConnectAuthenticationRequest(flow, queryParams);
        assertThat("Without redirect uri there is no redirection link", response.getHeader("location"), isEmptyOrNullString());
    }

    @Test
    public void oidc2_mandatoryResponseTypeMissingMustReturnError() throws Exception {
        Map queryParams = OpenIdConnectUtils.getAuthorizationRequestData(flow);
        queryParams.remove("response_type");
        Response response = Requests.getAuthenticationMethodsPageWithParameters(flow, queryParams);
        assertThat("Response type parameter is mandatory", response.body().asString(), startsWith("RESPONSE ERROR: invalid_request - No value found in the request for <response_type> parameter"));
    }

    @Test
    public void oidc2_invalidGrantTypeShouldReturnError() throws Exception {

        Map<String, String> params = new HashMap<String, String>();
        params.put("grant_type", "code");
        params.put("redirect_uri", flow.getRelyingParty().getRedirectUri());
        Response response = Requests.postToTokenEndpoint(flow, params);
        assertEquals(400, response.statusCode());
        assertEquals("unsupported_grant_type", response.body().jsonPath().getString("error"));
    }

    @Test
    public void oidc2_stateAndNonceInAuthorizationCodeResponseShouldMatchExpected() throws Exception {
        Response oidcResponse = MobileId.authenticateWithMobileId(flow, "00000766", "60001019906", 3000, OIDC_DEF_SCOPE);
        Map<String, String> params = getQueryParams(oidcResponse.getHeader("location"));
        assertEquals(params.get("nonce"), flow.getNonce());
        assertEquals(params.get("state"), flow.getState());
    }

    @Test
    public void oidc2_stateAndNonceInIdTokenResponseShouldMatchExpected() throws Exception {
        Response oidcResponse = MobileId.authenticateWithMobileId(flow, "00000766", "60001019906", 3000, OIDC_DEF_SCOPE);
        String token = Requests.getIdToken(flow, OpenIdConnectUtils.getCode(flow, oidcResponse.getHeader("location")));
        SignedJWT signedJWT = SignedJWT.parse(token);
        assertEquals(signedJWT.getJWTClaimsSet().getStringClaim("nonce"), flow.getNonce());
        assertEquals(signedJWT.getJWTClaimsSet().getStringClaim("state"), flow.getState());
    }

    @Test
    public void oidc2_getAuthorizationCodeResponseWithoutNonceShouldSucceed() throws Exception {

        Map queryParams = OpenIdConnectUtils.getAuthorizationRequestData(flow);
        queryParams.put("state", flow.getState());
        Response authenticationResponse = Requests.openIdConnectAuthenticationRequestWithoutStateAndNonce(flow, queryParams);
        String location = authenticationResponse.then().extract().response()
                .getHeader("location");
        Response taraLoginPageResponse = Requests.followRedirect(flow, location);
        String execution = taraLoginPageResponse.getBody().htmlPath().getString("**.findAll { it.@name == 'execution' }[0].@value");
        Response submitResponse = MobileId.submitMobileIdLogin(flow, "00000766", "60001019906", execution, location);
        String execution2 = submitResponse.getBody().htmlPath().getString("**.findAll { it.@name == 'execution' }[0].@value");
        Response pollResponse = MobileId.pollForAuthentication(flow, execution2, 3000);
        Response oidcResponse = Requests.followLoginRedirects(flow, pollResponse.getHeader("location"));

        Map<String, String> params = getQueryParams(oidcResponse.getHeader("location"));
        assertEquals(params.get("nonce"), null);
        assertEquals(params.get("state"), flow.getState());
    }

    @Test
    public void oidc2_getIdTokenResponseWithoutNonceShouldSucceed() throws Exception {

        Map queryParams = OpenIdConnectUtils.getAuthorizationRequestData(flow);
        queryParams.put("state", flow.getState());
        Response authenticationResponse = Requests.openIdConnectAuthenticationRequestWithoutStateAndNonce(flow, queryParams);
        String location = authenticationResponse.then().extract().response()
                .getHeader("location");
        Response taraLoginPageResponse = Requests.followRedirect(flow, location);
        String execution = taraLoginPageResponse.getBody().htmlPath().getString("**.findAll { it.@name == 'execution' }[0].@value");
        Response submitResponse = MobileId.submitMobileIdLogin(flow, "00000766", "60001019906", execution, location);
        String execution2 = submitResponse.getBody().htmlPath().getString("**.findAll { it.@name == 'execution' }[0].@value");
        Response pollResponse = MobileId.pollForAuthentication(flow, execution2, 3000);
        Response oidcResponse = Requests.followLoginRedirects(flow, pollResponse.getHeader("location"));
        String token = Requests.getIdToken(flow, OpenIdConnectUtils.getCode(flow, oidcResponse.getHeader("location")));
        SignedJWT signedJWT = SignedJWT.parse(token);

        assertThat("There is no nonce in id token", signedJWT.getJWTClaimsSet().getStringClaim("nonce"), isEmptyOrNullString());
        assertEquals(signedJWT.getJWTClaimsSet().getStringClaim("state"), flow.getState());
    }

    @Test
    public void oidc3_eidasOnlyScopeShouldShowOnlyEidas() throws Exception {
        Response response = Requests.getAuthenticationMethodsPageWithScope(flow, OIDC_EIDAS_ONLY_SCOPE);

        assertEquals("Only eIDAS must be present", true, isEidasPresent(response));
        assertEquals("Only eIDAS must be present", false, isMidPresent(response));
        assertEquals("Only eIDAS must be present", false, isIdCardPresent(response));
        assertEquals("Only eIDAS must be present", false, isBankPresent(response));
        //TODO: isSmartIdPresent
    }

    @Test
    public void oidc3_allAuthenticationMethodsShouldBePresent() throws Exception {
        Response response = Requests.getAuthenticationMethodsPageWithScope(flow, OIDC_DEF_SCOPE);

        assertEquals("eIDAS must be present", true, isEidasPresent(response));
        assertEquals("MID must be present", true, isMidPresent(response));
        assertEquals("ID-Card must be present", true, isIdCardPresent(response));
        assertEquals("Bank must be present", true, isBankPresent(response));
        //TODO: isSmartIdPresent
    }

    @Test
    public void oidc3_illegalAcrValuesShouldReturnError() throws Exception {
        Response response = Requests.getAuthenticationMethodsPageWithAcr(flow, "High");

        assertThat("Only supported acr_values are allowed", response.body().asString(), startsWith("RESPONSE ERROR: unsupported_acr_values - Provided acr_values is not allowed by TARA, only "));
    }

    @Test
    public void oidc3_emptyAcrValuesShouldReturnError() throws Exception {
        Response response = Requests.getAuthenticationMethodsPageWithAcr(flow, null);

        assertThat("Only supported acr_values are allowed", response.body().asString(), startsWith("RESPONSE ERROR: invalid_request - No value found in the request for <acr_values> parameter"));
    }

    @Test
    public void oidc3_severalAcrValuesShouldReturnError() throws Exception {
        Response response = Requests.getAuthenticationMethodsPageWithAcr(flow, "high low");

        assertThat("Only supported acr_values are allowed", response.body().asString(), startsWith("RESPONSE ERROR: unsupported_acr_values - Provided acr_values is not allowed by TARA, only "));
    }

    @Test
    //TODO: It does the exact opposite
    public void oidc3_severalAcrValuesParameterShouldReturnSuccess() throws Exception {
        Response response = Requests.getAuthenticationMethodsPageWithAcr(flow, Arrays.asList(OIDC_ACR_VALUES_HIGH, OIDC_ACR_VALUES_LOW));

        assertThat("Only supported acr_values are allowed", response.body().asString(), startsWith("RESPONSE ERROR: invalid_request - Multiple values found in the request for <acr_values> parameter"));

    }

    @Test
    public void oidc3_authenticationWithMidAcrValuesShouldSucceed() throws Exception {
        Map queryParams = OpenIdConnectUtils.getAuthorizationRequestData(flow);
        queryParams.put("acr_values", OIDC_ACR_VALUES_HIGH);

        Response authenticationResponse = Requests.openIdConnectAuthenticationRequest(flow, queryParams);
        String location = authenticationResponse.then().extract().response()
                .getHeader("location");
        Response taraLoginPageResponse = Requests.followRedirect(flow, location);
        String execution = taraLoginPageResponse.getBody().htmlPath().getString("**.findAll { it.@name == 'execution' }[0].@value");
        Response submitResponse = MobileId.submitMobileIdLogin(flow, "00000766", "60001019906", execution, location);
        String execution2 = submitResponse.getBody().htmlPath().getString("**.findAll { it.@name == 'execution' }[0].@value");
        Response pollResponse = MobileId.pollForAuthentication(flow, execution2, 7000);
        Response oidcResponse = Requests.followLoginRedirects(flow, pollResponse.getHeader("location"));
        String token = Requests.getIdToken(flow, OpenIdConnectUtils.getCode(flow, oidcResponse.getHeader("location")));
        SignedJWT signedJWT = Steps.verifyTokenAndReturnSignedJwtObject(flow, token);

        assertEquals(OIDC_AMR_MID, signedJWT.getJWTClaimsSet().getStringArrayClaim("amr")[0]);
        assertEquals("EE60001019906", signedJWT.getJWTClaimsSet().getSubject());
        assertEquals("MARY ÄNN", signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("given_name"));
        assertEquals("O’CONNEŽ-ŠUSLIK TESTNUMBER", signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("family_name"));
        assertEquals(null, signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("mobile_number"));
        assertEquals("acr value should not be present for MID", null, signedJWT.getJWTClaimsSet().getClaim("acr"));
    }

    @Test
    public void oidc3_supportedLocaleShouldSucceed() throws Exception {
        Map queryParams = OpenIdConnectUtils.getAuthorizationRequestData(flow);
        //TODO: which is it?
        queryParams.remove("lang");
        queryParams.put("locale", "ru");
        Response response = Requests.getAuthenticationMethodsPageWithParameters(flow, queryParams);
        String pageTitle = response.htmlPath().getString("html.head.title");
        assertEquals("Департамент государственной инфосистемы", pageTitle);
    }

    @Test
    public void oidc3_unsupportedLocaleShouldSwitchToEnglish() throws Exception {
        Map queryParams = OpenIdConnectUtils.getAuthorizationRequestData(flow);
        //TODO: which is it?
        queryParams.remove("lang");
        queryParams.put("locale", "fi");
        Response response = Requests.getAuthenticationMethodsPageWithParameters(flow, queryParams);
        String pageTitle = response.htmlPath().getString("html.head.title");
        assertEquals("Information System Authority", pageTitle);
    }

    private Map<String, String> getQueryParams(String url) throws URISyntaxException {
        List<NameValuePair> params = URLEncodedUtils.parse(new URI(url), StandardCharsets.UTF_8);
        return params.stream().collect(
                Collectors.toMap(NameValuePair::getName, NameValuePair::getValue));
    }
}
