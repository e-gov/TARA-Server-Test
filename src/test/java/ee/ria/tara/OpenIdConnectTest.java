package ee.ria.tara;


import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import ee.ria.tara.config.IntegrationTest;
import ee.ria.tara.config.TestTaraProperties;
import ee.ria.tara.model.OpenIdConnectFlow;
import ee.ria.tara.steps.*;
import ee.ria.tara.utils.AllureRestAssuredFormParam;
import ee.ria.tara.utils.EidasResponseDataUtils;
import ee.ria.tara.utils.OpenIdConnectUtils;
import io.qameta.allure.Feature;
import io.qameta.allure.Issue;
import io.qameta.allure.Link;
import io.qameta.allure.Step;
import io.restassured.config.RestAssuredConfig;
import io.restassured.config.SSLConfig;
import io.restassured.response.Response;
import io.restassured.specification.RequestSenderOptions;
import io.restassured.specification.RequestSpecification;
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
import static io.restassured.RestAssured.given;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;


@SpringBootTest(classes = OpenIdConnectTest.class)
@Category(IntegrationTest.class)
public class OpenIdConnectTest extends TestsBase {
    @Autowired
    private ResourceLoader resourceLoader;
    private static boolean setupComplete = false;
    private OpenIdConnectFlow flow;
    private static RestAssuredConfig config;

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
        flow.getOpenIDProvider().setSslConfig(config);
        flow.setup(properties);
    }

    public void initialize() throws IOException, ParseException, InitializationException {
        jwkSet = JWKSet.load(new URL(testTaraProperties.getFullJwksUrl()));
        tokenIssuer = getIssuer(testTaraProperties.getTargetUrl() + testTaraProperties.getConfigurationUrl());
        Security.addProvider(new BouncyCastleProvider());

        //For eIDAS
        InitializationService.initialize();
        Security.addProvider(new BouncyCastleProvider());
        if (testTaraProperties.getBackendUrl().startsWith("https")) {
            config = new RestAssuredConfig().sslConfig(new SSLConfig().
                    keyStore(testTaraProperties.getFrontEndKeystore(), testTaraProperties.getFrontEndKeystorePassword()).
                    trustStore(testTaraProperties.getBackEndTruststore(), testTaraProperties.getBackEndTruststorePassword()));
        }
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
    //TODO: duplicate with MobileIdTest.mob1_mobileIdAuthenticationSuccessWithRealLifeDelay
    public void oidc1_authenticationWithMidShouldSucceed() throws Exception {
        Response oidcResponse = MobileId.authenticateWithMobileId(flow, "00000766", "60001019906", 7000, OIDC_DEF_SCOPE);
        Map<String, String> token = Requests.getTokenResponse(flow, OpenIdConnectUtils.getCode(flow, oidcResponse.getHeader("location")));
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, token.get("id_token")).getJWTClaimsSet();

        assertThat(claims.getSubject(), equalTo("EE60001019906"));
        assertThat(claims.getJSONObjectClaim("profile_attributes").getAsString("given_name"), equalTo("MARY ÄNN"));
        assertThat(claims.getJSONObjectClaim("profile_attributes").getAsString("family_name"), equalTo("O’CONNEŽ-ŠUSLIK TESTNUMBER"));
        assertThat(claims.getJSONObjectClaim("profile_attributes").getAsString("date_of_birth"), equalTo("2000-01-01"));
        assertThat(claims.getJSONObjectClaim("profile_attributes").keySet(), not(hasItem("mobile_number")));
        assertThat(claims.getStringArrayClaim("amr")[0], equalTo(OIDC_AMR_MID));
    }

    @Test
    public void oidc1_authenticationWithEidasShouldSucceed() throws Exception {
        Response response = Eidas.initiateEidasAuthentication(flow, DEF_COUNTRY, OIDC_DEF_SCOPE, null);
        String relayState = response.htmlPath().getString("**.findAll { it.@name == 'RelayState' }[0].@value");

        //Here we need to simulate a response from foreign country eIDAS Node
        String samlResponse = EidasResponseDataUtils.getBase64SamlResponseMinimalAttributes(flow, response.getBody().asString(), DEFATTR_FIRST, DEFATTR_FAMILY, DEFATTR_PNO, DEFATTR_DATE, LOA_SUBSTANTIAL);

        String location = Eidas.returnEidasResponse(flow, samlResponse, relayState);
        Response oidcResponse = Requests.followLoginRedirects(flow, location);
        Map<String, String> token = Requests.getTokenResponse(flow, OpenIdConnectUtils.getCode(flow, oidcResponse.getHeader("location")));
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, token.get("id_token")).getJWTClaimsSet();

        assertThat(claims.getSubject(), equalTo("EE30011092212"));
        assertThat(claims.getJSONObjectClaim("profile_attributes").getAsString("given_name"), equalTo(DEFATTR_FIRST));
        assertThat(claims.getJSONObjectClaim("profile_attributes").getAsString("family_name"), equalTo(DEFATTR_FAMILY));
        assertThat(claims.getJSONObjectClaim("profile_attributes").getAsString("date_of_birth"), equalTo(DEFATTR_DATE));
        assertThat(claims.getStringArrayClaim("amr")[0], equalTo(OIDC_AMR_EIDAS));
    }

    @Test
    public void oidc1_MetadataAndTokenKeyIdMatches() throws Exception {
        Response oidcResponse = MobileId.authenticateWithMobileId(flow, "00000766", "60001019906", 7000, OIDC_DEF_SCOPE);
        Map<String, String> token = Requests.getTokenResponse(flow, OpenIdConnectUtils.getCode(flow, oidcResponse.getHeader("location")));
        SignedJWT signedJWT = Steps.verifyTokenAndReturnSignedJwtObject(flow, token.get("id_token"));

        assertThat(flow.getOpenIDProvider().getJwkSet().getKeys().get(0).getKeyID(), equalTo(signedJWT.getHeader().getKeyID()));
    }

    @Test
    @Issue("AUT-223")
    //TODO: Should be invalid_grant according to https://tools.ietf.org/html/rfc6749#section-5.2
    public void oidc2_requestTokenTwiceShouldFail() throws Exception {
        Response oidcResponse = MobileId.authenticateWithMobileId(flow, "00000766", "60001019906", 7000, OIDC_DEF_SCOPE);
        Requests.getTokenResponse(flow, OpenIdConnectUtils.getCode(flow, oidcResponse.getHeader("location")));

        Response response = Requests.postToTokenEndpoint(flow, OpenIdConnectUtils.getCode(flow, oidcResponse.getHeader("location")));
        response.then().statusCode(400);
        response.then().body("error", equalTo("invalid_request"));

    }

    @Test //TODO: Error handling is changed with AUT-57
    public void oidc2_mandatoryScopeMissingErrorMustBeReturned() throws Exception {
        Response response = Requests.getAuthenticationMethodsPageWithScope(flow, "eidasonly");
        assertThat("openid scope must be present error", response.body().asString(), startsWith("RESPONSE ERROR: invalid_scope - Required scope <openid> not provided"));
    }

    @Test //TODO: Error handling is changed with AUT-57
    public void oidc2_emptyScopeErrorMustBeReturned() throws Exception {
        Response response = Requests.getAuthenticationMethodsPageWithScope(flow, null);
        assertThat("scope missing error", response.body().asString(), startsWith("RESPONSE ERROR: invalid_scope - No value found in the request for <scope> parameter"));
    }

    @Test
    public void oidc2_incorrectSecretShouldReturnError() throws Exception {
        Response oidcResponse = MobileId.authenticateWithMobileId(flow, "00000766", "60001019906", 3000, OIDC_DEF_SCOPE);
        flow.getRelyingParty().setSecret("invalid_secret");
        Response response = Requests.postToTokenEndpoint(flow, OpenIdConnectUtils.getCode(flow, oidcResponse.getHeader("location")));
        response.then().statusCode(401);
        response.then().body("error", equalTo("invalid_client"));
    }

    @Test
    @Issue("AUT-223")
    //TODO: Should be invalid_grant according to https://tools.ietf.org/html/rfc6749#section-5.2
    public void oidc2_incorrectAuthorizationCodeShouldReturnError() throws Exception {
        Response oidcResponse = MobileId.authenticateWithMobileId(flow, "00000766", "60001019906", 3000, OIDC_DEF_SCOPE);
        String authorizationCode = OpenIdConnectUtils.getCode(flow, oidcResponse.getHeader("location"));
        Response response = Requests.postToTokenEndpoint(flow, authorizationCode + "a");
        response.then().statusCode(400);
        response.then().body("error", equalTo("invalid_request"));
    }

    @Test
    public void oidc2_missingAuthorizationCodeShouldReturnError() throws Exception {
        Map<String, String> params = new HashMap<>();
        params.put("grant_type", "authorization_code");
        params.put("redirect_uri", flow.getRelyingParty().getRedirectUri());
        Response response = Requests.postToTokenEndpoint(flow, params);
        response.then().statusCode(400);
        response.then().body("error", equalTo("invalid_request"));
    }

    @Test
    public void oidc2_missingGrantTypeShouldReturnError() throws Exception {
        Response oidcResponse = MobileId.authenticateWithMobileId(flow, "00000766", "60001019906", 3000, OIDC_DEF_SCOPE);
        String authorizationCode = OpenIdConnectUtils.getCode(flow, oidcResponse.getHeader("location"));

        Map<String, String> params = new HashMap<>();
        params.put("code", authorizationCode);
        params.put("redirect_uri", testTaraProperties.getTestRedirectUri());
        Response response = Requests.postToTokenEndpoint(flow, params);
        response.then().statusCode(400);
        response.then().body("error", equalTo("invalid_request"));
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
        Response response = Requests.openIdConnectAuthenticationRequest(flow, queryParams);
        assertThat("No redirect is allowed without client id", response.getHeader("location"), isEmptyOrNullString());
        assertThat("Generic error should be returned", Steps.extractError(response).get(1), equalTo("Kasutaja tuvastamisel tekkis ootamatu tehniline probleem."));
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
        assertThat("Generic error should be returned", Steps.extractError(response).get(1), equalTo("Kasutaja tuvastamisel tekkis ootamatu tehniline probleem."));

    }

    @Test //TODO: Error handling is changed with AUT-57
    public void oidc2_unknownRedirectUriMustReturnError() {
        Map queryParams = OpenIdConnectUtils.getAuthorizationRequestData(flow);
        queryParams.put("redirect_uri", "some_random.url");
        Response response = Requests.openIdConnectAuthenticationRequest(flow, queryParams);
        assertThat("Without redirect uri there is no redirection link", response.getHeader("location"), isEmptyOrNullString());
        assertThat("Generic error should be returned", Steps.extractError(response).get(1), equalTo("Kasutaja tuvastamisel tekkis ootamatu tehniline probleem."));

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
        response.then().statusCode(400);
        response.then().body("error", equalTo("unsupported_grant_type"));
    }

    @Test
    public void oidc2_stateAndNonceInAuthorizationCodeResponseShouldMatchExpected() throws Exception {
        Response oidcResponse = MobileId.authenticateWithMobileId(flow, "00000766", "60001019906", 3000, OIDC_DEF_SCOPE);
        Map<String, String> params = getQueryParams(oidcResponse.getHeader("location"));

        assertThat(params.get("nonce"), equalTo(flow.getNonce()));
        assertThat(params.get("state"), equalTo(flow.getState()));
    }

    @Test
    public void oidc2_stateAndNonceInAuthorizationCodeResponseShouldMatchExpectedUrlEncoded() throws Exception {
        flow.setState("testȺ田\uD83D\uDE0D&additional=1 %20");
        flow.setNonce("testȺ田\uD83D\uDE0D&additional=1 %20");
        Response oidcResponse = MobileId.authenticateWithMobileId(flow, "00000766", "60001019906", 3000, OIDC_DEF_SCOPE);
        Map<String, String> params = getQueryParams(oidcResponse.getHeader("location"));

        assertThat(params.get("nonce"), equalTo(flow.getNonce()));
        assertThat(params.get("state"), equalTo(flow.getState()));
    }

    @Test
    public void oidc2_stateAndNonceInIdTokenResponseShouldMatchExpectedUrlEncoded() throws Exception {
        flow.setState("testȺ田\uD83D\uDE0D&additional=1 %20");
        flow.setNonce("testȺ田\uD83D\uDE0D&additional=1 %20");
        Response oidcResponse = MobileId.authenticateWithMobileId(flow, "00000766", "60001019906", 3000, OIDC_DEF_SCOPE);
        Map<String, String> token = Requests.getTokenResponse(flow, OpenIdConnectUtils.getCode(flow, oidcResponse.getHeader("location")));
        JWTClaimsSet claims = SignedJWT.parse(token.get("id_token")).getJWTClaimsSet();
        assertThat(claims.getStringClaim("nonce"), equalTo(flow.getNonce()));
        assertThat(claims.getStringClaim("state"), equalTo(flow.getState()));
    }

    @Test
    public void oidc2_stateAndNonceInIdTokenResponseShouldMatchExpected() throws Exception {
        Response oidcResponse = MobileId.authenticateWithMobileId(flow, "00000766", "60001019906", 3000, OIDC_DEF_SCOPE);
        Map<String, String> token = Requests.getTokenResponse(flow, OpenIdConnectUtils.getCode(flow, oidcResponse.getHeader("location")));
        JWTClaimsSet claims = SignedJWT.parse(token.get("id_token")).getJWTClaimsSet();
        assertThat(claims.getStringClaim("nonce"), equalTo(flow.getNonce()));
        assertThat(claims.getStringClaim("state"), equalTo(flow.getState()));
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
        assertThat(params.get("nonce"), equalTo(null));
        assertThat(params.get("state"), equalTo(flow.getState()));
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
        Map<String, String> token = Requests.getTokenResponse(flow, OpenIdConnectUtils.getCode(flow, oidcResponse.getHeader("location")));
        JWTClaimsSet claims = SignedJWT.parse(token.get("id_token")).getJWTClaimsSet();

        assertThat("There is no nonce in id token", claims.getStringClaim("nonce"), isEmptyOrNullString());
        assertThat(claims.getStringClaim("state"), equalTo(flow.getState()));
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
    public void oidc3_severalAcrValuesParameterShouldReturnError() throws Exception {
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
        Map<String, String> token = Requests.getTokenResponse(flow, OpenIdConnectUtils.getCode(flow, oidcResponse.getHeader("location")));
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, token.get("id_token")).getJWTClaimsSet();

        assertThat(claims.getSubject(), equalTo("EE60001019906"));
        assertThat(claims.getJSONObjectClaim("profile_attributes").getAsString("given_name"), equalTo("MARY ÄNN"));
        assertThat(claims.getJSONObjectClaim("profile_attributes").getAsString("family_name"), equalTo("O’CONNEŽ-ŠUSLIK TESTNUMBER"));
        assertThat(claims.getJSONObjectClaim("profile_attributes").getAsString("date_of_birth"), equalTo("2000-01-01"));
        assertThat(claims.getJSONObjectClaim("profile_attributes").keySet(), not(hasItem("mobile_number")));
        assertThat(claims.getStringArrayClaim("amr")[0], equalTo(OIDC_AMR_MID));
        assertThat("acr value should not be present for MID", claims.getClaim("acr"), equalTo(null));
    }

    @Test
    public void oidc3_supportedLocaleRuShouldSucceed() throws Exception {
        Map queryParams = OpenIdConnectUtils.getAuthorizationRequestData(flow);
        queryParams.remove("ui_locales");
        queryParams.put("ui_locales", "ru");
        Response response = Requests.getAuthenticationMethodsPageWithParameters(flow, queryParams);
        response.then().body("html.head.title", equalTo("Национальный сервис аутентификации - Для безопасной аутентификации в э-услугах"));
    }

    @Test
    public void oidc3_supportedLocaleEnShouldSucceed() throws Exception {
        Map queryParams = OpenIdConnectUtils.getAuthorizationRequestData(flow);
        queryParams.remove("ui_locales");
        queryParams.put("ui_locales", "en");
        Response response = Requests.getAuthenticationMethodsPageWithParameters(flow, queryParams);
        response.then().body("html.head.title", equalTo("National authentication service - Secure authentication for e-services"));
    }

    @Test
    //TODO: AUT-132 changed from english to default language
    public void oidc3_unsupportedLocaleShouldSwitchToDefaultLanguage() throws Exception {
        Map queryParams = OpenIdConnectUtils.getAuthorizationRequestData(flow);
        queryParams.remove("ui_locales");
        queryParams.put("ui_locales", "fi");
        Response response = Requests.getAuthenticationMethodsPageWithParameters(flow, queryParams);
        response.then().body("html.head.title", equalTo("Riigi autentimisteenus"));
    }

    @Test
    public void oidc3_localeParameterStillSupportedEn() throws Exception {
        Map queryParams = OpenIdConnectUtils.getAuthorizationRequestData(flow);
        queryParams.remove("ui_locales");
        queryParams.put("locale", "en");
        Response response = Requests.getAuthenticationMethodsPageWithParameters(flow, queryParams);
        response.then().body("html.head.title", equalTo("National authentication service - Secure authentication for e-services"));
    }

    @Test
    public void oidc3_localeParameterStillSupportedRu() throws Exception {
        Map queryParams = OpenIdConnectUtils.getAuthorizationRequestData(flow);
        queryParams.remove("ui_locales");
        queryParams.put("locale", "ru");
        Response response = Requests.getAuthenticationMethodsPageWithParameters(flow, queryParams);
        response.then().body("html.head.title", equalTo("Национальный сервис аутентификации - Для безопасной аутентификации в э-услугах"));
    }

    @Test
    @Link(name = "Specification", url = "https://tools.ietf.org/html/rfc5646#section-2.1.1")
    public void oidc3_localesAreCaseInsensitiveEn() throws Exception {
        Map queryParams = OpenIdConnectUtils.getAuthorizationRequestData(flow);
        queryParams.remove("ui_locales");
        queryParams.put("ui_locales", "EN");
        Response response = Requests.getAuthenticationMethodsPageWithParameters(flow, queryParams);
        response.then().body("html.head.title", equalTo("National authentication service - Secure authentication for e-services"));
    }

    @Test
    @Link(name = "Specification", url = "https://tools.ietf.org/html/rfc5646#section-2.1.1")
    public void oidc3_localesAreCaseInsensitiveRu() throws Exception {
        Map queryParams = OpenIdConnectUtils.getAuthorizationRequestData(flow);
        queryParams.remove("ui_locales");
        queryParams.put("ui_locales", "RU");
        Response response = Requests.getAuthenticationMethodsPageWithParameters(flow, queryParams);
        response.then().body("html.head.title", equalTo("Национальный сервис аутентификации - Для безопасной аутентификации в э-услугах"));
    }

    @Test
    public void oidc3_localesFirstSupportedValueIsUsed() throws Exception {
        Map queryParams = OpenIdConnectUtils.getAuthorizationRequestData(flow);
        queryParams.remove("ui_locales");
        queryParams.put("ui_locales", "fi en et");
        Response response = Requests.getAuthenticationMethodsPageWithParameters(flow, queryParams);
        response.then().body("html.head.title", equalTo("National authentication service - Secure authentication for e-services"));
    }

    @Test
    @Feature("OIDC_SCOPES_SUPPORTED")
    public void allAuthenticationMethodsShouldBePresentWithDefaultScope() throws Exception {
        Response response = Requests.getAuthenticationMethodsPageWithScope(flow, OIDC_OPENID_SCOPE);

        assertThat("eIDAS must be present", isEidasPresent(response));
        assertThat("MID must be present", isMidPresent(response));
        assertThat("ID-Card must be present", isIdCardPresent(response));
        assertThat("Bank must be present", isBankPresent(response));
        assertThat("Smart-ID must be present", isSmartIdPresent(response));
    }

    @Test
    @Feature("OIDC_SCOPES_SUPPORTED")
    public void allAuthenticationMethodsPresentWhenAskedWithScopesIndividually() throws Exception {
        Response response = Requests.getAuthenticationMethodsPageWithScope(flow, OIDC_IDCARD_SCOPE + OIDC_MID_SCOPE + OIDC_EIDAS_SCOPE + OIDC_BANKLINK_SCOPE + OIDC_SMARTID_SCOPE + OIDC_OPENID_SCOPE);

        assertThat("eIDAS must be present", isEidasPresent(response));
        assertThat("MID must be present", isMidPresent(response));
        assertThat("ID-Card must be present", isIdCardPresent(response));
        assertThat("Bank must be present", isBankPresent(response));
        assertThat("Smart-ID must be present", isSmartIdPresent(response));
    }

    @Test
    @Feature("OIDC_SCOPES_SUPPORTED")
    public void unknownScopeIsIgnored() throws Exception {
        Response response = Requests.getAuthenticationMethodsPageWithScope(flow, OIDC_OPENID_SCOPE + "unknown");

        assertThat("eIDAS must be present", isEidasPresent(response));
        assertThat("MID must be present", isMidPresent(response));
        assertThat("ID-Card must be present", isIdCardPresent(response));
        assertThat("Bank must be present", isBankPresent(response));
        assertThat("Smart-ID must be present", isSmartIdPresent(response));
    }

    @Test
    @Feature("OIDC_SCOPES_SUPPORTED")
    public void unknownScopeTogetherWIthValidIsIgnored() throws Exception {
        Response response = Requests.getAuthenticationMethodsPageWithScope(flow, OIDC_OPENID_SCOPE + OIDC_IDCARD_SCOPE + "unknown");

        assertThat("eIDAS must not be present", isEidasPresent(response), is(false));
        assertThat("MID must not be present", isMidPresent(response), is(false));
        assertThat("ID-Card must be present", isIdCardPresent(response));
        assertThat("Bank must not be present", isBankPresent(response), is(false));
        assertThat("Smart-ID must not be present", isSmartIdPresent(response), is(false));
    }

    @Test
    @Feature("OIDC_SCOPES_SUPPORTED")
    public void unknownScopeIsIgnoredIfMixedWithValidScopes() throws Exception {
        Response response = Requests.getAuthenticationMethodsPageWithScope(flow, OIDC_OPENID_SCOPE + OIDC_IDCARD_SCOPE + "unknown " + OIDC_MID_SCOPE);

        assertThat("eIDAS must not be present", isEidasPresent(response), is(false));
        assertThat("MID must be present", isMidPresent(response));
        assertThat("ID-Card must be present", isIdCardPresent(response));
        assertThat("Bank must not be present", isBankPresent(response), is(false));
        assertThat("Smart-ID must not be present", isSmartIdPresent(response), is(false));
    }

    @Test
    @Feature("OIDC_SCOPES_SUPPORTED")
    public void emailScopeIsIgnoredIfMixedWithValidScopes() throws Exception {
        Response response = Requests.getAuthenticationMethodsPageWithScope(flow, OIDC_OPENID_SCOPE + OIDC_IDCARD_SCOPE + OIDC_EMAIL_SCOPE + OIDC_MID_SCOPE);

        assertThat("eIDAS must not be present", isEidasPresent(response), is(false));
        assertThat("MID must be present", isMidPresent(response));
        assertThat("ID-Card must be present", isIdCardPresent(response));
        assertThat("Bank must not be present", isBankPresent(response), is(false));
        assertThat("Smart-ID must not be present", isSmartIdPresent(response), is(false));
    }

    @Test
    @Feature("OIDC_SCOPES_SUPPORTED")
    public void scopeIsCaseSensitiveShouldBeHandledAsUnknown() throws Exception {
        Response response = Requests.getAuthenticationMethodsPageWithScope(flow, OIDC_OPENID_SCOPE + "IDCARD");

        assertThat("eIDAS must be present", isEidasPresent(response));
        assertThat("MID must be present", isMidPresent(response));
        assertThat("ID-Card must be present", isIdCardPresent(response));
        assertThat("Bank must be present", isBankPresent(response));
        assertThat("Smart-ID must be present", isSmartIdPresent(response));
    }

    @Test
    @Feature("OIDC_SCOPES_SUPPORTED")
    public void doubleScopeValuesAreIgnored() throws Exception {
        Response response = Requests.getAuthenticationMethodsPageWithScope(flow, OIDC_OPENID_SCOPE + OIDC_IDCARD_SCOPE + OIDC_IDCARD_SCOPE + OIDC_OPENID_SCOPE);

        assertThat("eIDAS must not be present", isEidasPresent(response), is(false));
        assertThat("MID must not be present", isMidPresent(response), is(false));
        assertThat("ID-Card must be present", isIdCardPresent(response));
        assertThat("Bank must not be present", isBankPresent(response), is(false));
        assertThat("Smart-ID not must be present", isSmartIdPresent(response), is(false));
    }

    @Test
    @Feature("OIDC_SCOPES_SUPPORTED")
    public void checkThatMidIsNotAllowed() throws Exception {
        String errorMessage = MobileId.extractError(MobileId.authenticateWithMobileIdError(flow, "00000766", "60001019906", OIDC_OPENID_SCOPE + OIDC_SMARTID_SCOPE));

        assertThat(errorMessage, startsWith("Keelatud autentimismeetod!"));
    }

    @Test
    @Feature("OIDC_SCOPES_SUPPORTED")
    public void checkThatIdCardIsNotAllowed() throws Exception {
        String errorMessage = IdCard.extractError(IdCard.authenticateWithIdAndReceiveError(flow, "37101010021.pem", OIDC_OPENID_SCOPE + OIDC_SMARTID_SCOPE, "et"));

        assertThat(errorMessage, startsWith("Keelatud autentimismeetod!"));
    }

    @Test
    @Feature("OIDC_SCOPES_SUPPORTED")
    public void checkThatBankLinkIsNotAllowed() throws Exception {
        String errorMessage = Banklink.extractError(Banklink.startBankAuthenticationWithError(flow, "seb", OIDC_OPENID_SCOPE + OIDC_SMARTID_SCOPE, "en"));

        assertThat(errorMessage, startsWith("Unauthorised authentication method!"));
    }

    @Test
    @Feature("OIDC_SCOPES_SUPPORTED")
    public void checkThatEidasIsNotAllowed() throws Exception {
        String errorMessage = Eidas.extractError(Eidas.initiateEidasAuthenticationWithError(flow, DEF_COUNTRY, OIDC_OPENID_SCOPE + OIDC_SMARTID_SCOPE, "low"));

        assertThat(errorMessage, startsWith("Keelatud autentimismeetod!"));
    }

    @Test
    @Feature("OIDC_SCOPES_SUPPORTED")
    public void checkThatSmartIdIsNotAllowed() throws Exception {
        String errorMessage = SmartId.extractError(SmartId.authenticateWithSmartIdError(flow, "10101010005", OIDC_OPENID_SCOPE + OIDC_MID_SCOPE));

        assertThat(errorMessage, startsWith("Keelatud autentimismeetod!"));
    }

    @Test
    @Feature("OIDC_SCOPES_EIDASONLY")
    public void eidasOnlyScopeShouldShowOnlyEidas() throws Exception {
        Response response = Requests.getAuthenticationMethodsPageWithScope(flow, OIDC_OPENID_SCOPE + OIDC_EIDAS_ONLY_SCOPE);

        assertThat("Only eIDAS must be present", isEidasPresent(response));
        assertThat("Only eIDAS must be present", isMidPresent(response), is(false));
        assertThat("Only eIDAS must be present", isIdCardPresent(response), is(false));
        assertThat("Only eIDAS must be present", isBankPresent(response), is(false));
        assertThat("Only eIDAS must be present", isSmartIdPresent(response), is(false));
    }

    @Test
    @Feature("OIDC_SCOPES_EIDASONLY")
    public void eidasonlyOverridesOtherScopes() throws Exception {
        Response response = Requests.getAuthenticationMethodsPageWithScope(flow, OIDC_OPENID_SCOPE + OIDC_IDCARD_SCOPE + OIDC_MID_SCOPE + OIDC_BANKLINK_SCOPE + OIDC_SMARTID_SCOPE + OIDC_EIDAS_ONLY_SCOPE);

        assertThat("Only eIDAS must be present", isEidasPresent(response));
        assertThat("MID must not be present", isMidPresent(response), is(false));
        assertThat("ID-Card must not be present", isIdCardPresent(response), is(false));
        assertThat("Bank must not be present", isBankPresent(response), is(false));
        assertThat("Smart-ID not must be present", isSmartIdPresent(response), is(false));
    }

    @Test
    @Feature("OIDC_SCOPES_EIDASONLY")
    public void eidasonlyShouldNotConflictWithEidas() throws Exception {
        Response response = Requests.getAuthenticationMethodsPageWithScope(flow, OIDC_OPENID_SCOPE + OIDC_EIDAS_SCOPE + OIDC_EIDAS_ONLY_SCOPE);

        assertThat("Only eIDAS must be present", isEidasPresent(response));
        assertThat("MID must not be present", isMidPresent(response), is(false));
        assertThat("ID-Card must not be present", isIdCardPresent(response), is(false));
        assertThat("Bank must not be present", isBankPresent(response), is(false));
        assertThat("Smart-ID not must be present", isSmartIdPresent(response), is(false));
    }

    @Test
    @Feature("OIDC_SCOPES_EIDASONLY")
    public void eidasonlyShouldAllowOnlyEidas() throws Exception {
        String errorMessage = MobileId.extractError(MobileId.authenticateWithMobileIdError(flow, "00000766", "60001019906", OIDC_OPENID_SCOPE + OIDC_EIDAS_ONLY_SCOPE));

        assertThat(errorMessage, startsWith("Keelatud autentimismeetod!"));
    }

    @Test
    @Feature("OIDC_SCOPE_EMAIL")
    public void emailScopeReturnsValues() throws Exception {
        Response oidcResponse = IdCard.authenticateWithIdCard(flow, "38001085718.pem", OIDC_OPENID_SCOPE + OIDC_EMAIL_SCOPE, "et");
        Map<String, String> token = Requests.getTokenResponse(flow, OpenIdConnectUtils.getCode(flow, oidcResponse.getHeader("location")));
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, token.get("id_token")).getJWTClaimsSet();

        assertThat(claims.getStringArrayClaim("amr")[0], equalTo(OIDC_AMR_IDC));
        assertThat(claims.getClaim("email"), equalTo("38001085718@eesti.ee"));
        assertThat(claims.getClaim("email_verified"), equalTo(false));
    }

    @Test
    @Feature("OIDC_SCOPE_EMAIL")
    public void emailScopeReturnsValuesWithIdCardScope() throws Exception {
        Response oidcResponse = IdCard.authenticateWithIdCard(flow, "38001085718.pem", OIDC_OPENID_SCOPE + OIDC_EMAIL_SCOPE + OIDC_IDCARD_SCOPE, "et");
        Map<String, String> token = Requests.getTokenResponse(flow, OpenIdConnectUtils.getCode(flow, oidcResponse.getHeader("location")));
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, token.get("id_token")).getJWTClaimsSet();

        assertThat(claims.getStringArrayClaim("amr")[0], equalTo(OIDC_AMR_IDC));
        assertThat(claims.getClaim("email"), equalTo("38001085718@eesti.ee"));
        assertThat(claims.getClaim("email_verified"), equalTo(false));
    }

    @Test
    @Feature("OIDC_SCOPE_EMAIL")
    public void emailScopeMissingEmailNotReturned() throws Exception {
        Response oidcResponse = IdCard.authenticateWithIdCard(flow, "38001085718.pem", OIDC_OPENID_SCOPE, "et");
        Map<String, String> token = Requests.getTokenResponse(flow, OpenIdConnectUtils.getCode(flow, oidcResponse.getHeader("location")));
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, token.get("id_token")).getJWTClaimsSet();

        assertThat(claims.getStringArrayClaim("amr")[0], equalTo(OIDC_AMR_IDC));
        assertThat(claims.getClaim("email"), is(nullValue()));
        assertThat(claims.getClaim("email_verified"), is(nullValue()));
    }

    @Test
    @Feature("OIDC_SCOPE_EMAIL")
    public void emailScopeNotSupportedAndShouldNotBeReturned() throws Exception {
        Response oidcResponse = MobileId.authenticateWithMobileId(flow, "00000766", "60001019906", 3000, OIDC_OPENID_SCOPE);
        Map<String, String> token = Requests.getTokenResponse(flow, OpenIdConnectUtils.getCode(flow, oidcResponse.getHeader("location")));
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, token.get("id_token")).getJWTClaimsSet();

        assertThat(claims.getStringArrayClaim("amr")[0], equalTo(OIDC_AMR_MID));
        assertThat(claims.getClaim("email"), is(nullValue()));
        assertThat(claims.getClaim("email_verified"), is(nullValue()));
    }

    @Test
    @Feature("OIDC_SCOPE_EMAIL")
    public void emailScopeNotSupportedButAskedShouldNotBeReturned() throws Exception {
        Response oidcResponse = SmartId.authenticateWithSmartId(flow, "10101010005", 3000, OIDC_OPENID_SCOPE + OIDC_EMAIL_SCOPE);
        Map<String, String> token = Requests.getTokenResponse(flow, OpenIdConnectUtils.getCode(flow, oidcResponse.getHeader("location")));
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, token.get("id_token")).getJWTClaimsSet();

        assertThat(claims.getStringArrayClaim("amr")[0], equalTo(OIDC_AMR_SMARTID));
        assertThat(claims.getClaim("email"), is(nullValue()));
        assertThat(claims.getClaim("email_verified"), is(nullValue()));
    }

    @Test
    @Feature("OIDC_USERINFO_ACCESSTOKEN_MISSING")
    public void userInfoWithoutAccessToken() throws Exception {
        Response userInfoResponse = Requests.getUserInfoWithAccessTokenAsBearerToken(flow, null, flow.getOpenIDProvider().getUserInfoUrl());
        assertThat(userInfoResponse.getStatusCode(), is(400));
        assertThat(userInfoResponse.getHeader("WWW-Authenticate"), is("Bearer error=\"invalid_request\",error_description=\"Missing access token from the request\""));
    }

    @Test
    @Feature("OIDC_USERINFO_ACCESSTOKEN_EXPIRED")
    public void userInfoWithInvalidAccessTokenInHeader() throws Exception {
        Response userInfoResponse = Requests.getUserInfoWithAccessTokenAsBearerToken(flow, "AT-123456abcdefg", flow.getOpenIDProvider().getUserInfoUrl());
        assertThat(userInfoResponse.getStatusCode(), is(401));
        assertThat(userInfoResponse.getHeader("WWW-Authenticate"), is("Bearer error=\"invalid_token\",error_description=\"The access token has expired\""));
    }

    @Test
    @Feature("OIDC_USERINFO_ACCESSTOKEN_EXPIRED")
    public void userInfoWithInvalidAccessTokenAsParameter() throws Exception {
        Response userInfoResponse = Requests.getUserInfoWithAccessTokenAsQueryParameter(flow, "AT-123456abcdefg", flow.getOpenIDProvider().getUserInfoUrl());
        assertThat(userInfoResponse.getStatusCode(), is(401));
        assertThat(userInfoResponse.getHeader("WWW-Authenticate"), is("Bearer error=\"invalid_token\",error_description=\"The access token has expired\""));
    }

    @Test
    @Feature("OIDC_USERINFO_ENDPOINT")
    public void userInfoHttpPostMethodNotAllowed() throws Exception {
        Response userInfoResponse =

                given()
                        .filter(flow.getCookieFilter())
                        .filter(new AllureRestAssuredFormParam())
                        .relaxedHTTPSValidation()
                        .when()
                        .queryParam("access_token", "AT-123456abcdefg")
                        .post(flow.getOpenIDProvider().getUserInfoUrl())
                        .then()
                        .extract().response();

        assertThat(userInfoResponse.getStatusCode(), is(405));
    }

    @Test
    @Feature("OIDC_USERINFO_ENDPOINT")
    public void userInfoHttpDeleteMethodNotAllowed() throws Exception {

        Response userInfoResponse =

                given()
                        .filter(flow.getCookieFilter())
                        .filter(new AllureRestAssuredFormParam())
                        .relaxedHTTPSValidation()
                        .when()
                        .queryParam("access_token", "AT-123456abcdefg")
                        .delete(flow.getOpenIDProvider().getUserInfoUrl())
                        .then()
                        .extract().response();

        assertThat(userInfoResponse.getStatusCode(), is(405));
    }

    @Test
    @Feature("OIDC_USERINFO_ENDPOINT")
    public void userInfoHttpPutMethodNotAllowed() throws Exception {

        Response userInfoResponse =

                given()
                        .filter(flow.getCookieFilter())
                        .filter(new AllureRestAssuredFormParam())
                        .relaxedHTTPSValidation()
                        .when()
                        .queryParam("access_token", "AT-123456abcdefg")
                        .put(flow.getOpenIDProvider().getUserInfoUrl())
                        .then()
                        .extract().response();

        assertThat(userInfoResponse.getStatusCode(), is(405));
    }

    @Test
    @Feature("OIDC_USERINFO_ENDPOINT")
    public void userInfoHttpPatchMethodNotAllowed() throws Exception {

        Response userInfoResponse =
                given()
                        .filter(flow.getCookieFilter())
                        .filter(new AllureRestAssuredFormParam())
                        .relaxedHTTPSValidation()
                        .when()
                        .queryParam("access_token", "AT-123456abcdefg")
                        .put(flow.getOpenIDProvider().getUserInfoUrl())
                        .then()
                        .extract().response();

        assertThat(userInfoResponse.getStatusCode(), is(405));
    }

    @Test
    public void metadataScopesSupportedHasListOfEidasCountries() throws Exception {
        Response metadata = Requests.getMetadata(flow);
        metadata.then().statusCode(200).body(
                "scopes_supported", hasItems("eidas:country:at",
                        "eidas:country:ee",
                        "eidas:country:sk")
        );
    }

    @Test
    public void metadataScopesSupprtedHasListOfAuthenticationMethods() throws Exception {
        Response metadata = Requests.getMetadata(flow);
        metadata.then().statusCode(200).body(
                "scopes_supported", hasItems(
                        "idcard",
                        "mid",
                        "banklink",
                        "smartid",
                        "eidas",
                        "eidasonly")
        );
    }

    @Test
    public void metadataScopesSupprtedHasOpenidAndEmail() throws Exception {
        Response metadata = Requests.getMetadata(flow);
        metadata.then().statusCode(200).body(
                "scopes_supported", hasItems(
                        "openid",
                        "email")
        );
    }

    private Map<String, String> getQueryParams(String url) throws URISyntaxException {
        List<NameValuePair> params = URLEncodedUtils.parse(new URI(url), StandardCharsets.UTF_8);
        return params.stream().collect(
                Collectors.toMap(NameValuePair::getName, NameValuePair::getValue));
    }
}
