package ee.ria.tara;


import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.SignedJWT;
import ee.ria.tara.config.IntegrationTest;
import io.restassured.response.Response;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.springframework.boot.test.context.SpringBootTest;
import java.net.URISyntaxException;
import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;

import static ee.ria.tara.config.TaraTestStrings.*;
import static org.hamcrest.Matchers.*;
import static org.junit.Assert.*;

@SpringBootTest(classes = OpenIdConnectTest.class)
@Category(IntegrationTest.class)
public class OpenIdConnectTest extends TestsBase {

    @Test
    public void oidc1_authenticationWithMidShouldSucceed() throws InterruptedException, URISyntaxException, ParseException, JOSEException {
        String authorizationCode = authenticateWithMobileId("00000766", "60001019906", 3000, OIDC_DEF_SCOPE);
        SignedJWT signedJWT = verifyTokenAndReturnSignedJwtObject(getIdToken(authorizationCode));

        assertEquals(OIDC_AMR_MID, signedJWT.getJWTClaimsSet().getStringArrayClaim("amr")[0]);
        assertEquals("EE60001019906", signedJWT.getJWTClaimsSet().getSubject());
        assertEquals("MARY ÄNN", signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("given_name"));
        assertEquals("O’CONNEŽ-ŠUSLIK TESTNUMBER", signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("family_name"));
        assertEquals("+37200000766", signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("mobile_number"));
        assertEquals("2000-01-01", signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("date_of_birth"));
    }

    @Test
    public void oidc1_authenticationWithEidasShouldSucceed() throws URISyntaxException, ParseException, JOSEException {
        Response response = initiateEidasAuthentication(DEF_COUNTRY, OIDC_DEF_SCOPE, null);
        String relayState = response.htmlPath().getString("**.findAll { it.@name == 'RelayState' }[0].@value");

        //Here we need to simulate a response from foreign country eIDAS Node
        String samlResponse = getBase64SamlResponseMinimalAttributes(response.getBody().asString(), DEFATTR_FIRST, DEFATTR_FAMILY, DEFATTR_PNO, DEFATTR_DATE, LOA_SUBSTANTIAL);

        String authorizationCode = getAuthorizationCode(returnEidasResponse(samlResponse, relayState));
        SignedJWT signedJWT = verifyTokenAndReturnSignedJwtObject(getIdToken(authorizationCode));

        assertEquals("EE30011092212", signedJWT.getJWTClaimsSet().getSubject());
        assertEquals(DEFATTR_FIRST, signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("given_name"));
        assertEquals(DEFATTR_FAMILY, signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("family_name"));
        assertEquals(DEFATTR_DATE, signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("date_of_birth"));
        assertEquals(OIDC_AMR_EIDAS, signedJWT.getJWTClaimsSet().getStringArrayClaim("amr")[0]);
    }

    @Test
    public void oidc1_eidasAuthenticationWithoutNonceShouldSucceed() throws URISyntaxException, ParseException, JOSEException {

        Map<String,String> formParams = new HashMap<String,String>();
        formParams.put("scope", OIDC_DEF_SCOPE);
        formParams.put("response_type", "code");
        formParams.put("client_id", testTaraProperties.getClientId());
        formParams.put("redirect_uri", testTaraProperties.getTestRedirectUri());
        formParams.put("locale", "et");
        formParams.put("acr_values", "low");

        String execution = getAuthenticationMethodsPageWithOptionalStateOrNonce(formParams,true,false).getBody().htmlPath().getString("**.findAll { it.@name == 'execution' }[0].@value");
        Response response = getEidasSamlRequest(DEF_COUNTRY, execution);

        String relayState = response.htmlPath().getString("**.findAll { it.@name == 'RelayState' }[0].@value");

        //Here we need to simulate a response from foreign country eIDAS Node
        String samlResponse = getBase64SamlResponseMinimalAttributes(response.getBody().asString(), DEFATTR_FIRST, DEFATTR_FAMILY, DEFATTR_PNO, DEFATTR_DATE, LOA_SUBSTANTIAL);

        String authorizationCode = getAuthorizationCode(returnEidasResponse(samlResponse, relayState));
        SignedJWT signedJWT = verifyTokenAndReturnSignedJwtObjectWithoutNonce(getIdToken(authorizationCode));

        assertEquals("EE30011092212", signedJWT.getJWTClaimsSet().getSubject());
        assertEquals(DEFATTR_FIRST, signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("given_name"));
        assertEquals(DEFATTR_FAMILY, signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("family_name"));
        assertEquals(DEFATTR_DATE, signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("date_of_birth"));
        assertEquals(OIDC_AMR_EIDAS, signedJWT.getJWTClaimsSet().getStringArrayClaim("amr")[0]);
    }

    @Test
    public void oidc2_requestTokenTwiceShouldFail() throws InterruptedException, URISyntaxException {
        String authorizationCode = authenticateWithMobileId("00000766", "60001019906", 3000, OIDC_DEF_SCOPE);
        getIdToken(authorizationCode);
        Response response = postToTokenEndpoint(authorizationCode);
        assertEquals(400, response.statusCode());
        assertEquals("invalid_grant", response.body().jsonPath().getString("error"));
    }

    @Test //TODO: Error handling is changed with AUT-57
    public void oidc2_mandatoryScopeMissingErrorMustBeReturned() {
        Response response = getAuthenticationMethodsPage("eidasonly");
        assertThat("openid scope must be present error", response.body().asString(), startsWith("RESPONSE ERROR: invalid_scope - Required scope <openid> not provided.") );
    }

    @Test //TODO: Error handling is changed with AUT-57
    public void oidc2_emptyScopeErrorMustBeReturned() {
        Response response = getAuthenticationMethodsPage(null);
        assertThat("scope missing error", response.body().asString(), startsWith("RESPONSE ERROR: invalid_scope - No value found in the request for <scope> parameter") );
    }

    @Test //TODO: Error handling is changed with AUT-57
    public void oidc2_notKnownScopeErrorMustBeReturned() {
        Response response = getAuthenticationMethodsPage("openid newscope");
        assertThat("scope missing error", response.body().asString(), startsWith("RESPONSE ERROR: invalid_scope - One or some of the provided scopes are not allowed by TARA, only <openid, eidasonly> are permitted.") );
    }

    @Test
    public void oidc2_incorrectSecretShouldReturnError() throws InterruptedException, URISyntaxException, ParseException, JOSEException {
        String authorizationCode = authenticateWithMobileId("00000766", "60001019906", 3000, OIDC_DEF_SCOPE);
        Response response = postToTokenEndpoint(authorizationCode, "invalid secret");

        assertEquals(401, response.statusCode());
        assertEquals("invalid_client", response.body().jsonPath().getString("error"));
    }

    @Test
    public void oidc2_incorrectAuthorizationCodeShouldReturnError() throws InterruptedException, URISyntaxException, ParseException, JOSEException {
        String authorizationCode = authenticateWithMobileId("00000766", "60001019906", 3000, OIDC_DEF_SCOPE);
        Response response = postToTokenEndpoint(authorizationCode + "a");

        assertEquals(400, response.statusCode());
        assertEquals("invalid_grant", response.body().jsonPath().getString("error"));
    }

    @Test
    public void oidc2_missingAuthorizationCodeShouldReturnError() throws InterruptedException, URISyntaxException, ParseException, JOSEException {
        authenticateWithMobileId("00000766", "60001019906", 3000, OIDC_DEF_SCOPE);
        Map<String,String> params = new HashMap<String,String>();
        params.put("grant_type", "authorization_code");
        params.put("redirect_uri", testTaraProperties.getTestRedirectUri());
        Response response = postToTokenEndpoint(params);

        assertEquals(400, response.statusCode());
        assertEquals("invalid_request", response.body().jsonPath().getString("error"));
    }

    @Test
    public void oidc2_missingGrantTypeShouldReturnError() throws InterruptedException, URISyntaxException, ParseException, JOSEException {
        String authorizationCode = authenticateWithMobileId("00000766", "60001019906", 3000, OIDC_DEF_SCOPE);
        Map<String,String> params = new HashMap<String,String>();
        params.put("code", authorizationCode);
        params.put("redirect_uri", testTaraProperties.getTestRedirectUri());
        Response response = postToTokenEndpoint(params);

        assertEquals(400, response.statusCode());
        assertEquals("invalid_request", response.body().jsonPath().getString("error"));
    }

    @Test
    public void oidc2_unsupportedResponseTypeShouldReturnError() {
        Map<String,String> formParams = new HashMap<String,String>();
        formParams.put("scope", OIDC_DEF_SCOPE);
        formParams.put("response_type", "token");
        formParams.put("client_id", testTaraProperties.getClientId());
        formParams.put("redirect_uri", testTaraProperties.getTestRedirectUri());
        formParams.put("lang", "et");
        formParams.put("acr_values", null);

        Response response = getAuthenticationMethodsPageWithParams(formParams);
        assertThat("Only supported response_type is allowed", response.body().asString(), startsWith("RESPONSE ERROR: unsupported_response_type - Provided response type is not allowed by TARA, only <code> is permitted") );
    }

    @Test
    public void oidc2_mandatoryClientIdMissingMustReturnError() {
        Map<String,String> formParams = new HashMap<String,String>();
        formParams.put("scope", OIDC_DEF_SCOPE);
        formParams.put("response_type", "code");
        formParams.put("redirect_uri", testTaraProperties.getTestRedirectUri());
        formParams.put("locale", "et");
        formParams.put("acr_values", "low");

        Response response = getAuthenticationMethodsPageWithParams(formParams);
        assertThat("client_id is mandatory parameter", response.body().asString(), startsWith("RESPONSE ERROR: invalid_client - No value found in the request for <client_id> parameter") );
    }

    @Test
    public void oidc2_mandatoryStateMissingMustReturnError() {
        Map<String,String> formParams = new HashMap<String,String>();
        formParams.put("scope", OIDC_DEF_SCOPE);
        formParams.put("response_type", "code");
        formParams.put("client_id", testTaraProperties.getClientId());
        formParams.put("redirect_uri", testTaraProperties.getTestRedirectUri());
        formParams.put("locale", "et");
        formParams.put("acr_values", "low");

        Response response = getAuthenticationMethodsPageWithOptionalStateOrNonce(formParams, false, true);
        assertThat("State is mandatory parameter", response.body().asString(), startsWith("RESPONSE ERROR: invalid_request - No value found in the request for <state> parameter") );
    }


    @Test //TODO: Error handling is changed with AUT-57
    public void oidc2_mandatoryRedirectUriMissingMustReturnError() {
        Map<String,String> formParams = new HashMap<String,String>();
        formParams.put("scope", OIDC_DEF_SCOPE);
        formParams.put("response_type", "code");
        formParams.put("client_id", testTaraProperties.getClientId());
        formParams.put("locale", "et");
        formParams.put("acr_values", "low");

        Response response = sendAuthenticationRequest(formParams);
        assertThat("Without redirect uri there is no redirection link", response.getHeader("location"), isEmptyOrNullString());
    }

    @Test
    public void oidc2_mandatoryResponseTypeMissingMustReturnError() {
        Map<String,String> formParams = new HashMap<String,String>();
        formParams.put("scope", OIDC_DEF_SCOPE);
        formParams.put("client_id", testTaraProperties.getClientId());
        formParams.put("redirect_uri", testTaraProperties.getTestRedirectUri());
        formParams.put("locale", "et");
        formParams.put("acr_values", "low");

        Response response = getAuthenticationMethodsPageWithParams(formParams);
        assertThat("Response type parameter is mandatory", response.body().asString(), startsWith("RESPONSE ERROR: invalid_request - No value found in the request for <response_type> parameter"));
    }

    @Test
    public void oidc2_invalidGrantTypeShouldReturnError() throws InterruptedException, URISyntaxException, ParseException, JOSEException {
        authenticateWithMobileId("00000766", "60001019906", 3000, OIDC_DEF_SCOPE);
        Map<String, String> params = new HashMap<String, String>();
        params.put("grant_type", "code");
        params.put("redirect_uri", testTaraProperties.getTestRedirectUri());
        Response response = postToTokenEndpoint(params);

        assertEquals(400, response.statusCode());
        assertEquals("unsupported_grant_type", response.body().jsonPath().getString("error"));
    }

    @Test
    public void oidc2_stateAndNonceInAuthorizationCodeResponseShouldMatchExpected() throws InterruptedException, URISyntaxException, ParseException, JOSEException {
        String execution = getAuthenticationMethodsPage(OIDC_DEF_SCOPE).getBody().htmlPath().getString("**.findAll { it.@name == 'execution' }[0].@value");
        String location = getAuthorizationCodeResponseWithMobileId("00000766", "60001019906", 3000, execution);
        Map<String,String> params = getQueryParams(location);

        assertEquals(params.get("nonce"), createBase64EncodedHash(nonce));
        assertEquals(params.get("state"), createBase64EncodedHash(state));
    }

    @Test
    public void oidc2_stateAndNonceInIdTokenResponseShouldMatchExpected() throws InterruptedException, URISyntaxException, ParseException, JOSEException {
        String authorizationCode = authenticateWithMobileId("00000766", "60001019906", 3000, OIDC_DEF_SCOPE);
        SignedJWT token = SignedJWT.parse(getIdToken(authorizationCode));

        assertEquals(token.getJWTClaimsSet().getStringClaim("nonce"), createBase64EncodedHash(nonce));
        assertEquals(token.getJWTClaimsSet().getStringClaim("state"), createBase64EncodedHash(state));
    }

    @Test
    public void oidc2_getAuthorizationCodeResponseWithoutNonceShouldSucceed() throws InterruptedException, URISyntaxException, ParseException, JOSEException {
        Map<String,String> formParams = new HashMap<String,String>();
        formParams.put("scope", OIDC_DEF_SCOPE);
        formParams.put("response_type", "code");
        formParams.put("client_id", testTaraProperties.getClientId());
        formParams.put("redirect_uri", testTaraProperties.getTestRedirectUri());
        formParams.put("locale", "et");

        String execution = getAuthenticationMethodsPageWithOptionalStateOrNonce(formParams,true,false).getBody().htmlPath().getString("**.findAll { it.@name == 'execution' }[0].@value");
        String location = getAuthorizationCodeResponseWithMobileId("00000766", "60001019906", 3000, execution);
        Map<String,String> params = getQueryParams(location);

        assertEquals(params.get("nonce"), null);
        assertEquals(params.get("state"), createBase64EncodedHash(state));
    }

    @Test
    public void oidc2_getIdTokenResponseWithoutNonceShouldSucceed() throws InterruptedException, URISyntaxException, ParseException, JOSEException {
        Map<String,String> formParams = new HashMap<String,String>();
        formParams.put("scope", OIDC_DEF_SCOPE);
        formParams.put("response_type", "code");
        formParams.put("client_id", testTaraProperties.getClientId());
        formParams.put("redirect_uri", testTaraProperties.getTestRedirectUri());
        formParams.put("locale", "et");

        String execution = getAuthenticationMethodsPageWithOptionalStateOrNonce(formParams,true,false).getBody().htmlPath().getString("**.findAll { it.@name == 'execution' }[0].@value");
        String location = getAuthorizationCodeResponseWithMobileId("00000766", "60001019906", 3000, execution);

        SignedJWT token = SignedJWT.parse(getIdToken(getCode(location)));

        assertThat("There is no nonce in id token", token.getJWTClaimsSet().getStringClaim("nonce"), isEmptyOrNullString());
        assertEquals(token.getJWTClaimsSet().getStringClaim("state"), createBase64EncodedHash(state));
    }

    @Test
    public void oidc3_eidasOnlyScopeShouldShowOnlyEidas() {
        Response response = getAuthenticationMethodsPage(OIDC_EIDAS_ONLY_SCOPE);

        assertEquals("Only eIDAS must be present", true, isEidasPresent(response));
        assertEquals("Only eIDAS must be present", false, isMidPresent(response));
        assertEquals("Only eIDAS must be present", false, isIdCardPresent(response));
        assertEquals("Only eIDAS must be present", false, isBankPresent(response));
    }

    @Test
    public void oidc3_allAuthenticationMethodsShouldBePresent() {
        Response response = getAuthenticationMethodsPage(OIDC_DEF_SCOPE);

        assertEquals("eIDAS must be present", true, isEidasPresent(response));
        assertEquals("MID must be present", true, isMidPresent(response));
        assertEquals("ID-Card must be present", true, isIdCardPresent(response));
        assertEquals("Bank must be present", true, isBankPresent(response));

    }

    @Test
    public void oidc3_illegalAcrValuesShouldReturnError() {
        Map<String,String> formParams = new HashMap<String,String>();
        formParams.put("scope", OIDC_DEF_SCOPE);
        formParams.put("response_type", "code");
        formParams.put("client_id", testTaraProperties.getClientId());
        formParams.put("redirect_uri", testTaraProperties.getTestRedirectUri());
        formParams.put("lang", "et");
        formParams.put("acr_values", "High");

        Response response = getAuthenticationMethodsPageWithParams(formParams);

        assertThat("Only supported acr_values are allowed", response.body().asString(), startsWith("RESPONSE ERROR: unsupported_acr_values - Provided acr_values is not allowed by TARA, only ") );
    }

    @Test
    public void oidc3_emptyAcrValuesShouldReturnError() {
        Map<String,String> formParams = new HashMap<String,String>();
        formParams.put("scope", OIDC_DEF_SCOPE);
        formParams.put("response_type", "code");
        formParams.put("client_id", testTaraProperties.getClientId());
        formParams.put("redirect_uri", testTaraProperties.getTestRedirectUri());
        formParams.put("lang", "et");
        formParams.put("acr_values", null);

        Response response = getAuthenticationMethodsPageWithParams(formParams);
        assertThat("Only supported acr_values are allowed", response.body().asString(), startsWith("RESPONSE ERROR: invalid_request - No value found in the request for <acr_values> parameter") );
    }

    @Test
    public void oidc3_severalAcrValuesShouldReturnError() {
        Map<String,String> formParams = new HashMap<String,String>();
        formParams.put("scope", OIDC_DEF_SCOPE);
        formParams.put("response_type", "code");
        formParams.put("client_id", testTaraProperties.getClientId());
        formParams.put("redirect_uri", testTaraProperties.getTestRedirectUri());
        formParams.put("lang", "et");
        formParams.put("acr_values", "high low");

        Response response = getAuthenticationMethodsPageWithParams(formParams);
        assertThat("Only supported acr_values are allowed", response.body().asString(), startsWith("RESPONSE ERROR: unsupported_acr_values - Provided acr_values is not allowed by TARA, only ") );
    }

    @Test
    public void oidc3_severalAcrValuesParameterShouldReturnSuccess() throws URISyntaxException, ParseException, JOSEException {
        Map<String,String> formParams = new HashMap<String,String>();
        formParams.put("scope", OIDC_DEF_SCOPE);
        formParams.put("response_type", "code");
        formParams.put("client_id", testTaraProperties.getClientId());
        formParams.put("redirect_uri", testTaraProperties.getTestRedirectUri());
        formParams.put("lang", "et");
        formParams.put("acr_values", OIDC_ACR_VALUES_HIGH);
        formParams.put("acr_values", OIDC_ACR_VALUES_LOW);

        String execution = getAuthenticationMethodsPageWithParams(formParams).getBody().htmlPath().getString("**.findAll { it.@name == 'execution' }[0].@value");
        Response response = getEidasSamlRequest(DEF_COUNTRY, execution);
        String relayState = response.htmlPath().getString("**.findAll { it.@name == 'RelayState' }[0].@value");

        String loa = getDecodedSamlRequestBodyXml(response.getBody().asString()).getString("AuthnRequest.RequestedAuthnContext.AuthnContextClassRef");
        //Here we need to simulate a response from foreign country eIDAS Node
        String samlResponse = getBase64SamlResponseMinimalAttributes(response.getBody().asString(), DEFATTR_FIRST, DEFATTR_FAMILY, DEFATTR_PNO, DEFATTR_DATE, loa);

        String authorizationCode = getAuthorizationCode(returnEidasResponse(samlResponse, relayState));
        SignedJWT signedJWT = verifyTokenAndReturnSignedJwtObject(getIdToken(authorizationCode));

        assertEquals("EE30011092212", signedJWT.getJWTClaimsSet().getSubject());
        assertEquals(DEFATTR_FIRST, signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("given_name"));
        assertEquals(DEFATTR_FAMILY, signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("family_name"));
        assertEquals(DEFATTR_DATE, signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("date_of_birth"));
        assertEquals(OIDC_AMR_EIDAS, signedJWT.getJWTClaimsSet().getStringArrayClaim("amr")[0]);
        assertEquals("Last parameter is used", OIDC_ACR_VALUES_LOW, signedJWT.getJWTClaimsSet().getClaim("acr"));
    }

    @Test
    public void oidc3_severalAcrValuesNotSupportedParametersShouldReturnSuccess() throws URISyntaxException, ParseException, JOSEException {
        Map<String,String> formParams = new HashMap<String,String>();
        formParams.put("scope", OIDC_DEF_SCOPE);
        formParams.put("response_type", "code");
        formParams.put("client_id", testTaraProperties.getClientId());
        formParams.put("redirect_uri", testTaraProperties.getTestRedirectUri());
        formParams.put("lang", "et");
        formParams.put("acr_values", "randomValue");
        formParams.put("acr_values", OIDC_ACR_VALUES_HIGH);

        String execution = getAuthenticationMethodsPageWithParams(formParams).getBody().htmlPath().getString("**.findAll { it.@name == 'execution' }[0].@value");
        Response response = getEidasSamlRequest(DEF_COUNTRY, execution);
        String relayState = response.htmlPath().getString("**.findAll { it.@name == 'RelayState' }[0].@value");

        String loa = getDecodedSamlRequestBodyXml(response.getBody().asString()).getString("AuthnRequest.RequestedAuthnContext.AuthnContextClassRef");
        //Here we need to simulate a response from foreign country eIDAS Node
        String samlResponse = getBase64SamlResponseMinimalAttributes(response.getBody().asString(), DEFATTR_FIRST, DEFATTR_FAMILY, DEFATTR_PNO, DEFATTR_DATE, loa);

        String authorizationCode = getAuthorizationCode(returnEidasResponse(samlResponse, relayState));
        SignedJWT signedJWT = verifyTokenAndReturnSignedJwtObject(getIdToken(authorizationCode));

        assertEquals("EE30011092212", signedJWT.getJWTClaimsSet().getSubject());
        assertEquals(DEFATTR_FIRST, signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("given_name"));
        assertEquals(DEFATTR_FAMILY, signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("family_name"));
        assertEquals(DEFATTR_DATE, signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("date_of_birth"));
        assertEquals(OIDC_AMR_EIDAS, signedJWT.getJWTClaimsSet().getStringArrayClaim("amr")[0]);
        assertEquals("Last parameter is used", OIDC_ACR_VALUES_HIGH, signedJWT.getJWTClaimsSet().getClaim("acr"));
    }

    @Test
    public void oidc3_authenticationWithMidAcrValuesShouldSucceed() throws InterruptedException, URISyntaxException, ParseException, JOSEException {
        Map<String,String> formParams = new HashMap<String,String>();
        formParams.put("scope", OIDC_DEF_SCOPE);
        formParams.put("response_type", "code");
        formParams.put("client_id", testTaraProperties.getClientId());
        formParams.put("redirect_uri", testTaraProperties.getTestRedirectUri());
        formParams.put("lang", "et");
        formParams.put("acr_values", OIDC_ACR_VALUES_HIGH);
        String authorizationCode = authenticateWithMobileIdWithParams("00000766", "60001019906", 3000, formParams);
        SignedJWT signedJWT = verifyTokenAndReturnSignedJwtObject(getIdToken(authorizationCode));

        assertEquals(OIDC_AMR_MID, signedJWT.getJWTClaimsSet().getStringArrayClaim("amr")[0]);
        assertEquals("EE60001019906", signedJWT.getJWTClaimsSet().getSubject());
        assertEquals("MARY ÄNN", signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("given_name"));
        assertEquals("O’CONNEŽ-ŠUSLIK TESTNUMBER", signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("family_name"));
        assertEquals("+37200000766", signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("mobile_number"));
        assertEquals("acr value should not be present for MID", null, signedJWT.getJWTClaimsSet().getClaim("acr"));
    }

    @Test
    public void oidc3_supportedLocaleShouldSucceed() throws URISyntaxException, ParseException, JOSEException{
        Map<String,String> formParams = new HashMap<String,String>();
        formParams.put("scope", OIDC_DEF_SCOPE);
        formParams.put("response_type", "code");
        formParams.put("client_id", testTaraProperties.getClientId());
        formParams.put("redirect_uri", testTaraProperties.getTestRedirectUri());
        formParams.put("locale", "ru");
        formParams.put("acr_values", "low");

        Response response = getAuthenticationMethodsPageWithParams(formParams);
        String pageTitle = response.htmlPath().getString("html.head.title");

        assertEquals("Департамент государственной инфосистемы", pageTitle);
    }

    @Test
    public void oidc3_unsupportedLocaleShouldSwitchToEnglish() throws URISyntaxException, ParseException, JOSEException{
        Map<String,String> formParams = new HashMap<String,String>();
        formParams.put("scope", OIDC_DEF_SCOPE);
        formParams.put("response_type", "code");
        formParams.put("client_id", testTaraProperties.getClientId());
        formParams.put("redirect_uri", testTaraProperties.getTestRedirectUri());
        formParams.put("locale", "fi");
        formParams.put("acr_values", "low");

        Response response = getAuthenticationMethodsPageWithParams(formParams);
        String pageTitle = response.htmlPath().getString("html.head.title");

        assertEquals("Information System Authority", pageTitle);
    }
}
