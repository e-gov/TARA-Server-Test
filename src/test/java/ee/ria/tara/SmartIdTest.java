package ee.ria.tara;


import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWTClaimsSet;
import ee.ria.tara.config.IntegrationTest;
import ee.ria.tara.config.TestConfiguration;
import ee.ria.tara.config.TestTaraProperties;
import ee.ria.tara.model.OpenIdConnectFlow;
import ee.ria.tara.steps.Requests;
import ee.ria.tara.steps.SmartId;
import ee.ria.tara.steps.Steps;
import io.qameta.allure.Feature;
import ee.ria.tara.utils.OpenIdConnectUtils;
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
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.lessThan;


@SpringBootTest(classes = SmartIdTest.class)
@Category(IntegrationTest.class)
public class SmartIdTest extends TestsBase {
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
    @Feature("TSID-12, TSID-13")
    public void smartidSuccess() throws Exception {
        Response oidcResponse = SmartId.authenticateWithSmartId(flow, "10101010005", 3000, OIDC_DEF_SCOPE);
        Map<String, String> token = Requests.getTokenResponse(flow, OpenIdConnectUtils.getCode(flow, oidcResponse.getHeader("location")));

        assertValidIdToken(token);

        assertValidUserInfoResponse(token);
    }

    @Test
    @Feature("TSID-12, TSID-13")
    public void smartidSuccessWithSpecificScope() throws Exception {
        Response oidcResponse = SmartId.authenticateWithSmartId(flow, "10101010005", 3000, OIDC_OPENID_SCOPE + OIDC_SMARTID_SCOPE);
        Map<String, String> token =  Requests.getTokenResponse(flow, OpenIdConnectUtils.getCode(flow, oidcResponse.getHeader("location")));
        assertValidIdToken(token);

        assertValidUserInfoResponse(token);
    }

    @Test
    @Feature("TSID-11")
    public void smartid_UserRefuses() throws Exception {
        String errorMessage = SmartId.extractError(SmartId.authenticatePollError(flow, "10101010016", 3000));
        assertThat(errorMessage, equalTo("Autentimine katkestati kasutaja poolt."));
    }

    /**
     * Verifying that proper error message is displayed when user inserts invalid id code
     *
     * @throws Exception
     */
    @Test
    public void smartIdInvalidFormat() throws Exception {
        Map queryParams = OpenIdConnectUtils.getAuthorizationRequestData(flow);
        Response authenticationResponse = Requests.openIdConnectAuthenticationRequest(flow, queryParams); //getBody().htmlPath().getString("**.findAll { it.@name == 'execution' }[0].@value")
        String location = authenticationResponse.then().extract().response()
                .getHeader("location");
        Response taraLoginPageResponse = Requests.followRedirect(flow, location);
        String execution = taraLoginPageResponse.getBody().htmlPath().getString("**.findAll { it.@name == 'execution' }[0].@value");
        Response submitResponse = SmartId.submitSmartIdLogin(flow, "12akl2", execution, location);


        String errorMessage = SmartId.extractError(submitResponse);
        assertThat(errorMessage, equalTo("Isikukood on ebakorrektses formaadis."));
    }

    /**
     * Verifying that proper error message is displayed when user inserts empty id code
     *
     * @throws Exception
     */
    @Test
    public void smartIdEmptyCode() throws Exception {
        Map queryParams = OpenIdConnectUtils.getAuthorizationRequestData(flow);
        Response authenticationResponse = Requests.openIdConnectAuthenticationRequest(flow, queryParams); //getBody().htmlPath().getString("**.findAll { it.@name == 'execution' }[0].@value")
        String location = authenticationResponse.then().extract().response()
                .getHeader("location");
        Response taraLoginPageResponse = Requests.followRedirect(flow, location);
        String execution = taraLoginPageResponse.getBody().htmlPath().getString("**.findAll { it.@name == 'execution' }[0].@value");
        Response submitResponse = SmartId.submitSmartIdLogin(flow, "", execution, location);
        String errorMessage = SmartId.extractError(submitResponse);
        assertThat(errorMessage, equalTo("Isikukood puudu"));
    }

    private void assertValidUserInfoResponse(Map<String, String> token) {
        assertValidUserinfoResponse(
                Requests.getUserInfoWithAccessTokenAsBearerToken(flow, token.get("access_token"), flow.getOpenIDProvider().getUserInfoUrl())
        );

        assertValidUserinfoResponse(
                Requests.getUserInfoWithAccessTokenAsQueryParameter(flow, token.get("access_token"), flow.getOpenIDProvider().getUserInfoUrl())
        );
    }

    private void assertValidIdToken(Map<String, String> token) throws ParseException, JOSEException, IOException {
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, token.get("id_token")).getJWTClaimsSet();

        assertThat(claims.getSubject(), equalTo("EE10101010005"));
        assertThat(claims.getJSONObjectClaim("profile_attributes").getAsString("given_name"), equalTo("DEMO"));
        assertThat(claims.getJSONObjectClaim("profile_attributes").getAsString("family_name"), equalTo("SMART-ID"));
        assertThat(claims.getJSONObjectClaim("profile_attributes").getAsString("date_of_birth"), equalTo("1801-01-01"));
        assertThat(claims.getStringArrayClaim("amr")[0], equalTo("smartid"));
    }

    private void assertValidUserinfoResponse(Response userInfoResponse) {
        JsonPath json = userInfoResponse.jsonPath();
        assertThat(json.getMap("$.").keySet(), hasItems("sub", "auth_time", "given_name", "family_name", "date_of_birth", "amr"));
        assertThat(json.get("sub"), equalTo("EE10101010005"));
        assertThat("auth_time must be a unix timestamp format and within the allowed timeframe", json.getLong("auth_time"), is(both(greaterThan(new Long(Instant.now().getEpochSecond() - TestConfiguration.ALLOWED_TIME_DIFFERENCE_IN_SECONDS))).and(lessThanOrEqualTo(Instant.now().getEpochSecond()))));
        assertThat(json.get("given_name"), equalTo("DEMO"));
        assertThat(json.get("family_name"), equalTo("SMART-ID"));
        assertThat(json.get("date_of_birth"), equalTo("1801-01-01"));
        assertThat(json.getList("amr"), equalTo(Arrays.asList(OIDC_AMR_SMARTID)));
    }
}
