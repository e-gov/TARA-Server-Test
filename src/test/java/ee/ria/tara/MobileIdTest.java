package ee.ria.tara;


import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWTClaimsSet;
import ee.ria.tara.config.IntegrationTest;
import ee.ria.tara.config.TestConfiguration;
import ee.ria.tara.config.TestTaraProperties;
import ee.ria.tara.model.OpenIdConnectFlow;
import ee.ria.tara.steps.MobileId;
import ee.ria.tara.steps.Requests;
import ee.ria.tara.steps.Steps;
import ee.ria.tara.utils.OpenIdConnectUtils;
import io.qameta.allure.Feature;
import io.restassured.path.json.JsonPath;
import io.restassured.response.Response;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.ResourceLoader;

import java.io.IOException;
import java.net.URL;
import java.security.Security;
import java.text.ParseException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Map;

import static ee.ria.tara.config.TaraTestStrings.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;


@SpringBootTest(classes = MobileIdTest.class)
@Category(IntegrationTest.class)
public class MobileIdTest extends TestsBase {
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
    }

    public void initialize() throws IOException, ParseException {
        jwkSet = JWKSet.load(new URL(testTaraProperties.getFullJwksUrl()));
        tokenIssuer = getIssuer(testTaraProperties.getTargetUrl() + testTaraProperties.getConfigurationUrl());
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void mob1_mobileIdAuthenticationSuccessWithRealLifeDelay() throws Exception {
        Response oidcResponse = MobileId.authenticateWithMobileId(flow, "00000766", "60001019906", 7000, OIDC_DEF_SCOPE);
        Map<String, String> token = Requests.getTokenResponse(flow, OpenIdConnectUtils.getCode(flow, oidcResponse.getHeader("location")));

        assertValidIdToken(token);

        assertValidUserinfoResponse(token);
    }

    @Test
    @Feature("OIDC_SCOPE_PHONE")
    public void mob1_mobileIdAuthenticationSuccessWithRealLifeDelayPhoneScope() throws Exception {
        Response oidcResponse = MobileId.authenticateWithMobileId(flow, "00000766", "60001019906", 7000, "openid phone");
        Map<String, String> token = Requests.getTokenResponse(flow, OpenIdConnectUtils.getCode(flow, oidcResponse.getHeader("location")));

        assertValidIdTokenWithPhoneNumber(token);

        assertValidUserinfoResponseWithPhoneNumber(token);
    }

    @Test
    public void mob1_mobileIdCancelAndRetrySuccessful() throws Exception {
        Map queryParams = OpenIdConnectUtils.getAuthorizationRequestData(flow);

        Response authenticationResponse = Requests.openIdConnectAuthenticationRequest(flow, queryParams);
        String location = authenticationResponse.then().extract().response()
                .getHeader("location");
        Response taraLoginPageResponse = Requests.followRedirect(flow, location);
        String execution = taraLoginPageResponse.getBody().htmlPath().getString("**.findAll { it.@name == 'execution' }[0].@value");
        Response submitResponse = MobileId.submitMobileIdLogin(flow, "00000766", "60001019906", execution, location);
        String execution2 = submitResponse.getBody().htmlPath().getString("**.findAll { it.@name == 'execution' }[0].@value");
        Response cancelResponse = MobileId.cancelAuthentication(flow, execution2);


        String execution3 = cancelResponse.getBody().htmlPath().getString("**.findAll { it.@name == 'execution' }[0].@value");
        Response submitResponse2 = MobileId.submitMobileIdLogin(flow, "00000766", "60001019906", execution3, location);
        String execution4 = submitResponse2.getBody().htmlPath().getString("**.findAll { it.@name == 'execution' }[0].@value");
        Response pollResponse = MobileId.pollForAuthentication(flow, execution4, 7000);
        Response oidcResponse = Requests.followLoginRedirects(flow, pollResponse.getHeader("location"));
        Map<String, String> token = Requests.getTokenResponse(flow, OpenIdConnectUtils.getCode(flow, oidcResponse.getHeader("location")));

        assertValidIdToken(token);

        assertValidUserinfoResponse(token);
    }

    @Test
    public void mob1_mobileIdAuthenticationSuccessPNOEEPrefixWithRealLifeDelay() throws Exception {
        Response oidcResponse = MobileId.authenticateWithMobileId(flow, "00000566", "60001018800", 7000, OIDC_DEF_SCOPE);
        Map<String, String> token = Requests.getTokenResponse(flow, OpenIdConnectUtils.getCode(flow, oidcResponse.getHeader("location")));

        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, token.get("id_token")).getJWTClaimsSet();

        assertThat(claims.getSubject(), equalTo("EE60001018800"));
        assertThat(claims.getJSONObjectClaim("profile_attributes").getAsString("given_name"), equalTo("MARY ÄNN"));
        assertThat(claims.getJSONObjectClaim("profile_attributes").getAsString("family_name"), equalTo("O’CONNEŽ-ŠUSLIK TESTNUMBER"));
        assertThat(claims.getJSONObjectClaim("profile_attributes").getAsString("date_of_birth"), equalTo("2000-01-01"));
        assertThat(claims.getJSONObjectClaim("profile_attributes").keySet(), not(hasItem("mobile_number")));
        assertThat(claims.getStringArrayClaim("amr")[0], equalTo(OIDC_AMR_MID));
    }

    @Test
    public void mob1_mobileIdAuthenticationSuccessWithSpecificSope() throws Exception {
        Response oidcResponse = MobileId.authenticateWithMobileId(flow, "00000766", "60001019906", 3000, OIDC_OPENID_SCOPE + OIDC_MID_SCOPE);
        Map<String, String> token = Requests.getTokenResponse(flow, OpenIdConnectUtils.getCode(flow, oidcResponse.getHeader("location")));

    }

    @Test
    public void mob2_mobileIdAuthenticationUserCertificatesRevoked() throws Exception {
        String errorMessage = MobileId.extractError(MobileId.authenticateWithMobileIdPollError(flow, "00000266", "60001019939", 1000));
        assertThat(errorMessage, startsWith("Kasutajal pole Mobiil-ID lepingut."));
    }

    @Test
    public void mob2_mobileIdAuthenticationRequestToPhoneFailed() throws Exception {
        String errorMessage = MobileId.extractError(MobileId.authenticateWithMobileIdPollError(flow, "07110066", "60001019947", 500));
        assertThat(errorMessage, startsWith("Teie mobiiltelefoni ei saa Mobiil-ID autentimise sõnumeid saata."));
    }

    @Test
    public void mob2_mobileIdAuthenticationTechnicalError() throws Exception {
        String errorMessage = MobileId.extractError(MobileId.authenticateWithMobileIdPollError(flow, "00000666", "60001019961", 3000));
        assertThat(errorMessage, startsWith("Autentimine Mobiil-ID-ga ei õnnestunud. Testi oma Mobiil-ID toimimist DigiDoc4 kliendis: https://www.id.ee/index.php?id=39003"));
    }

    @Test
    public void mob2_mobileIdAuthenticationSimApplicationError() throws Exception {
        String errorMessage = MobileId.extractError(MobileId.authenticateWithMobileIdPollError(flow, "01200266", "60001019972", 1000));
        assertThat(errorMessage, startsWith("Teie mobiiltelefoni SIM kaardiga tekkis tõrge."));
    }

    @Test
    public void mob2_mobileIdAuthenticationPhoneNotInNetwork() throws Exception {
        String errorMessage = MobileId.extractError(MobileId.authenticateWithMobileIdPollError(flow, "13100266", "60001019983", 1000));
        assertThat(errorMessage, startsWith("Teie mobiiltelefon on levialast väljas."));
    }

    @Test
    public void mob3_mobileIdAuthenticationUserCancels() throws Exception {
        String errorMessage = MobileId.extractError(MobileId.authenticateWithMobileIdPollError(flow, "01100266", "60001019950", 1000));
        assertThat(errorMessage, startsWith("Autentimine on katkestatud."));
    }

    /**
     * Verifying that user receives proper error message when user inserts invalid id code
     */
    @Test
    public void mob3_mobileIdAuthenticationInvalidIdCode() throws Exception {
        String errorMessage = MobileId.extractError(MobileId.authenticateWithMobileIdPollError(flow, "00000766", "10001010002", 1000));
        assertThat(errorMessage, startsWith("Kasutajal pole Mobiil-ID lepingut"));
    }

    /**
     * Verifying that user receives proper error message when user inserts invalid phone number
     */
    @Test
    public void mob3_mobileIdAuthenticationInvalidPhoneNumber() throws Exception {
        String errorMessage = MobileId.extractError(MobileId.authenticateWithMobileIdPollError(flow, "123456789123", "60001019906", 1000));
        assertThat(errorMessage, startsWith("Kasutajal pole Mobiil-ID lepingut."));
    }

    /**
     * Verifying that user receives proper error message when user doesn't insert phone number
     */
    @Test
    public void mob3_mobileIdAuthenticationNoMobileNo() {
        String errorMessage = MobileId.extractError(MobileId.authenticateWithMobileIdError(flow, "", "60001019906", OIDC_DEF_SCOPE));
        assertThat(errorMessage, startsWith("Telefoninumber ei ole korrektne."));
    }

    /**
     * Verifying that user receives proper error message when user doesn't insert id code
     */
    @Test
    public void mob3_mobileIdAuthenticationNoIdCode() {
        String errorMessage = MobileId.extractError(MobileId.authenticateWithMobileIdError(flow, "00000766", "", OIDC_DEF_SCOPE));
        assertThat(errorMessage, startsWith("Isikukood ei ole korrektne."));
    }

    /**
     * Verifying that user receives proper error message when user doesn't insert any parameters
     */
    @Test
    public void mob3_mobileIdAuthenticationNoParameters() {
        String errorMessage = MobileId.extractError(MobileId.authenticateWithMobileIdError(flow, "", "", OIDC_DEF_SCOPE));
        assertThat(errorMessage, startsWith("Isikukood ei ole korrektne."));
    }


    private void assertValidUserinfoResponse(Map<String, String> token) {
        assertValidUserinfoResponse(
                Requests.getUserInfoWithAccessTokenAsBearerToken(flow, token.get("access_token"), flow.getOpenIDProvider().getUserInfoUrl())
        );

        assertValidUserinfoResponse(
                Requests.getUserInfoWithAccessTokenAsQueryParameter(flow, token.get("access_token"), flow.getOpenIDProvider().getUserInfoUrl())
        );
    }

    private void assertValidUserinfoResponseWithPhoneNumber(Map<String, String> token) {
        assertValidUserinfoResponseWithPhoneNumber(
                Requests.getUserInfoWithAccessTokenAsBearerToken(flow, token.get("access_token"), flow.getOpenIDProvider().getUserInfoUrl())
        );

        assertValidUserinfoResponseWithPhoneNumber(
                Requests.getUserInfoWithAccessTokenAsQueryParameter(flow, token.get("access_token"), flow.getOpenIDProvider().getUserInfoUrl())
        );
    }

    private void assertValidIdToken(Map<String, String> token) throws ParseException, JOSEException, IOException {
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, token.get("id_token")).getJWTClaimsSet();

        assertThat(claims.getSubject(), equalTo("EE60001019906"));
        assertThat(claims.getJSONObjectClaim("profile_attributes").getAsString("given_name"), equalTo("MARY ÄNN"));
        assertThat(claims.getJSONObjectClaim("profile_attributes").getAsString("family_name"), equalTo("O’CONNEŽ-ŠUSLIK TESTNUMBER"));
        assertThat(claims.getJSONObjectClaim("profile_attributes").getAsString("date_of_birth"), equalTo("2000-01-01"));
        assertThat(claims.getJSONObjectClaim("profile_attributes").keySet(), not(hasItem("mobile_number")));
        assertThat(claims.toJSONObject().keySet(), not(hasItem("mobile_number")));
        assertThat(claims.getStringArrayClaim("amr")[0], equalTo(OIDC_AMR_MID));
        assertThat(claims.getClaim("acr"), equalTo("high"));

    }

    private void assertValidIdTokenWithPhoneNumber(Map<String, String> token) throws ParseException, JOSEException, IOException {
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, token.get("id_token")).getJWTClaimsSet();

        assertThat(claims.getSubject(), equalTo("EE60001019906"));
        assertThat(claims.getJSONObjectClaim("profile_attributes").getAsString("given_name"), equalTo("MARY ÄNN"));
        assertThat(claims.getJSONObjectClaim("profile_attributes").getAsString("family_name"), equalTo("O’CONNEŽ-ŠUSLIK TESTNUMBER"));
        assertThat(claims.getJSONObjectClaim("profile_attributes").getAsString("date_of_birth"), equalTo("2000-01-01"));
        assertThat(claims.getClaim("phone_number"), equalTo("+37200000766"));
        assertThat(claims.getClaim("phone_number_verified"), equalTo(true));
        assertThat(claims.getStringArrayClaim("amr")[0], equalTo(OIDC_AMR_MID));
        assertThat(claims.getClaim("acr"), equalTo("high"));

    }

    private void assertValidUserinfoResponse(Response userInfoResponse) {
        JsonPath json = userInfoResponse.jsonPath();
        assertThat(json.getMap("$.").keySet(), hasItems("sub", "auth_time", "given_name", "family_name", "date_of_birth", "amr"));
        assertThat(json.get("sub"), equalTo("EE60001019906"));
        assertThat("auth_time must be a unix timestamp format and within the allowed timeframe", json.getLong("auth_time"), is(both(greaterThan(new Long(Instant.now().getEpochSecond() - TestConfiguration.ALLOWED_TIME_DIFFERENCE_IN_SECONDS))).and(lessThanOrEqualTo(Instant.now().getEpochSecond()))));
        assertThat(json.get("given_name"), equalTo("MARY ÄNN"));
        assertThat(json.get("family_name"), equalTo("O’CONNEŽ-ŠUSLIK TESTNUMBER"));
        assertThat(json.get("date_of_birth"), equalTo("2000-01-01"));
        assertThat(json.getList("amr"), equalTo(Arrays.asList(OIDC_AMR_MID)));
        assertThat(json.get("acr"), equalTo("high"));
    }

    private void assertValidUserinfoResponseWithPhoneNumber(Response userInfoResponse) {
        JsonPath json = userInfoResponse.jsonPath();
        assertThat(json.getMap("$.").keySet(), hasItems("sub", "auth_time", "given_name", "family_name", "date_of_birth", "amr"));
        assertThat(json.get("sub"), equalTo("EE60001019906"));
        assertThat("auth_time must be a unix timestamp format and within the allowed timeframe", json.getLong("auth_time"), is(both(greaterThan(new Long(Instant.now().getEpochSecond() - TestConfiguration.ALLOWED_TIME_DIFFERENCE_IN_SECONDS))).and(lessThanOrEqualTo(Instant.now().getEpochSecond()))));
        assertThat(json.get("given_name"), equalTo("MARY ÄNN"));
        assertThat(json.get("family_name"), equalTo("O’CONNEŽ-ŠUSLIK TESTNUMBER"));
        assertThat(json.get("date_of_birth"), equalTo("2000-01-01"));
        assertThat(json.get("phone_number"), equalTo("+37200000766"));
        assertThat(json.get("phone_number_verified"), equalTo(true));
        assertThat(json.getList("amr"), equalTo(Arrays.asList(OIDC_AMR_MID)));
        assertThat(json.get("acr"), equalTo("high"));

    }
}

