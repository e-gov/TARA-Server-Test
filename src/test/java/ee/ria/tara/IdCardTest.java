package ee.ria.tara;


import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWTClaimsSet;
import ee.ria.tara.config.IntegrationTest;
import ee.ria.tara.config.TestConfiguration;
import ee.ria.tara.config.TestTaraProperties;
import ee.ria.tara.model.OpenIdConnectFlow;
import ee.ria.tara.steps.IdCard;
import ee.ria.tara.steps.Requests;
import ee.ria.tara.steps.Steps;
import ee.ria.tara.utils.OpenIdConnectUtils;
import io.qameta.allure.Description;
import io.qameta.allure.Feature;
import io.qameta.allure.Link;
import io.restassured.config.RestAssuredConfig;
import io.restassured.config.SSLConfig;
import io.restassured.path.json.JsonPath;
import io.restassured.response.Response;
import lombok.AllArgsConstructor;
import lombok.Data;
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
import java.time.Instant;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static ee.ria.tara.config.TaraTestStrings.*;
import static ee.ria.tara.steps.IdCard.submitIdCardLogin;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;

@SpringBootTest(classes = IdCardTest.class)
@Category(IntegrationTest.class)
public class IdCardTest extends TestsBase {
    @Autowired
    private ResourceLoader resourceLoader;
    private static boolean setupComplete = false;
    private OpenIdConnectFlow flow;
    private static RestAssuredConfig config;

    @Data
    @AllArgsConstructor
    class ExpectedOutput {
        private String subject;
        private String firstName;
        private String familyName;
        private String dateOfBirth;
        private String amr;
        private String email;
        private boolean emailVerified;
    }

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
        flow.getOpenIDProvider().setSslConfig(config);
        flow.setup(properties);
    }

    public void initialize() throws IOException, ParseException {
        jwkSet = JWKSet.load(new URL(testTaraProperties.getFullJwksUrl()));
        tokenIssuer = getIssuer(testTaraProperties.getTargetUrl() + testTaraProperties.getConfigurationUrl());
        Security.addProvider(new BouncyCastleProvider());
        if (testTaraProperties.getBackendUrl().startsWith("https")) {
            config = new RestAssuredConfig().sslConfig(new SSLConfig().
                    keyStore(testTaraProperties.getFrontEndKeystore(), testTaraProperties.getFrontEndKeystorePassword()).
                    trustStore(testTaraProperties.getBackEndTruststore(), testTaraProperties.getBackEndTruststorePassword()));
        }
    }

    @Test
    @Feature("ID-1")
    public void validLoginWithEsteid2018Certificate() throws Exception {
        flow.setState("FcwXIhR5JkHqUqTVZoclTy7QYoQMN9jjXGbp77MnjnSQu8w4Sm9Jw3HuDaimwGNrtdIAT0Pal_XEt3_NWnBPF-gwUTZa5MdDg163JQkJplVtDsyhmMQvLZilCdq_BMKztc7iSptcfGkguba-oBtJaiySnSAvKqvytck0AaNwUyWc2QNBk34kAUIh-CHQS49OYRlRmiYz3AJnxxd6");
        Response oidcResponse = IdCard.authenticateWithIdCard(flow, "38001085718.pem", OIDC_OPENID_SCOPE + OIDC_EMAIL_SCOPE, "et");
        Map<String, String> token = Requests.getTokenResponse(flow, OpenIdConnectUtils.getCode(flow, oidcResponse.getHeader("location")));
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, token.get("id_token")).getJWTClaimsSet();

        IdCardTest.ExpectedOutput expectedOutcome = new IdCardTest.ExpectedOutput("EE38001085718", "JAAK-KRISTJAN", "JÕEORG", "1980-01-08", OIDC_AMR_IDC, "38001085718@eesti.ee", false);

        assertThat(claims.getSubject(), equalTo(expectedOutcome.getSubject()));
        assertThat(claims.getJSONObjectClaim("profile_attributes").getAsString("given_name"), equalTo(expectedOutcome.getFirstName()));
        assertThat(claims.getJSONObjectClaim("profile_attributes").getAsString("family_name"), equalTo(expectedOutcome.getFamilyName()));
        assertThat(claims.getJSONObjectClaim("profile_attributes").getAsString("date_of_birth"), equalTo(expectedOutcome.getDateOfBirth()));
        assertThat(claims.getStringArrayClaim("amr")[0], equalTo(expectedOutcome.getAmr()));
        assertThat(claims.getClaim("email"), equalTo(expectedOutcome.getEmail()));
        assertThat(claims.getClaim("email_verified"), equalTo(expectedOutcome.isEmailVerified()));

        assertValidUserInfoResponseWithEmail(expectedOutcome, token.get("access_token"));
    }


    @Test
    @Feature("ID-1")
    public void validLoginWithScope() throws Exception {
        Response oidcResponse = IdCard.authenticateWithIdCard(flow, "38001085718.pem", OIDC_OPENID_SCOPE + OIDC_IDCARD_SCOPE, "et");
        Map<String, String> token = Requests.getTokenResponse(flow, OpenIdConnectUtils.getCode(flow, oidcResponse.getHeader("location")));
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, token.get("id_token")).getJWTClaimsSet();

        IdCardTest.ExpectedOutput expectedOutcome = new IdCardTest.ExpectedOutput("EE38001085718", "JAAK-KRISTJAN", "JÕEORG", "1980-01-08", OIDC_AMR_IDC, "38001085718@eesti.ee", false);

        assertThat(claims.getSubject(), equalTo(expectedOutcome.getSubject()));
        assertThat(claims.getJSONObjectClaim("profile_attributes").getAsString("given_name"), equalTo(expectedOutcome.getFirstName()));
        assertThat(claims.getJSONObjectClaim("profile_attributes").getAsString("family_name"), equalTo(expectedOutcome.getFamilyName()));
        assertThat(claims.getJSONObjectClaim("profile_attributes").getAsString("date_of_birth"), equalTo(expectedOutcome.getDateOfBirth()));
        assertThat(claims.getStringArrayClaim("amr")[0], equalTo(expectedOutcome.getAmr()));

        assertValidUserInfoResponseWithoutEmail(expectedOutcome, token.get("access_token"));
    }

    @Test
    @Feature("ID-1")
    public void validLoginWithEsteid2015RsaCertificate() throws Exception {
        Response oidcResponse = IdCard.authenticateWithIdCard(flow, "37101010021.pem", OIDC_OPENID_SCOPE + OIDC_EMAIL_SCOPE, "et");
        Map<String, String> token = Requests.getTokenResponse(flow, OpenIdConnectUtils.getCode(flow, oidcResponse.getHeader("location")));
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, token.get("id_token")).getJWTClaimsSet();

        IdCardTest.ExpectedOutput expectedOutcome = new IdCardTest.ExpectedOutput("EE37101010021", "IGOR", "ŽAIKOVSKI", "1971-01-01", OIDC_AMR_IDC, "igor.zaikovski.3@eesti.ee", false);

        assertThat(claims.getSubject(), equalTo(expectedOutcome.getSubject()));
        assertThat(claims.getJSONObjectClaim("profile_attributes").getAsString("given_name"), equalTo(expectedOutcome.getFirstName()));
        assertThat(claims.getJSONObjectClaim("profile_attributes").getAsString("family_name"), equalTo(expectedOutcome.getFamilyName()));
        assertThat(claims.getJSONObjectClaim("profile_attributes").getAsString("date_of_birth"), equalTo(expectedOutcome.getDateOfBirth()));
        assertThat(claims.getStringArrayClaim("amr")[0], equalTo(expectedOutcome.getAmr()));
        assertThat(claims.getClaim("email"), equalTo(expectedOutcome.getEmail()));
        assertThat(claims.getClaim("email_verified"), equalTo(expectedOutcome.isEmailVerified()));

        assertValidUserInfoResponseWithEmail(expectedOutcome, token.get("access_token"));
    }

    @Test
    @Feature("ID-1")
    public void validLoginWithEsteid2015EccCertificate() throws Exception {
        Response oidcResponse = IdCard.authenticateWithIdCard(flow, "47101010033.pem", OIDC_OPENID_SCOPE + OIDC_EMAIL_SCOPE, "et");
        Map<String, String> token = Requests.getTokenResponse(flow, OpenIdConnectUtils.getCode(flow, oidcResponse.getHeader("location")));
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, token.get("id_token")).getJWTClaimsSet();

        IdCardTest.ExpectedOutput expectedOutcome = new IdCardTest.ExpectedOutput("EE47101010033", "MARI-LIIS", "MÄNNIK", "1971-01-01", OIDC_AMR_IDC, "mari-liis.mannik@eesti.ee", false);

        assertThat(claims.getSubject(), equalTo(expectedOutcome.getSubject()));
        assertThat(claims.getJSONObjectClaim("profile_attributes").getAsString("given_name"), equalTo(expectedOutcome.getFirstName()));
        assertThat(claims.getJSONObjectClaim("profile_attributes").getAsString("family_name"), equalTo(expectedOutcome.getFamilyName()));
        assertThat(claims.getJSONObjectClaim("profile_attributes").getAsString("date_of_birth"), equalTo(expectedOutcome.getDateOfBirth()));
        assertThat(claims.getStringArrayClaim("amr")[0], equalTo(expectedOutcome.getAmr()));
        assertThat(claims.getClaim("email"), equalTo(expectedOutcome.getEmail()));
        assertThat(claims.getClaim("email_verified"), equalTo(expectedOutcome.isEmailVerified()));

        assertValidUserInfoResponseWithEmail(expectedOutcome, token.get("access_token"));
    }

    @Test
    public void expired2011RsaCertificate() throws Exception {
        String errorMessage = IdCard.extractError(IdCard.authenticateWithIdAndReceiveError(flow, "47101010033_2011.pem", OIDC_DEF_SCOPE, "et"));
        assertThat(errorMessage, startsWith("Teie sertifikaadid ei kehti."));
    }

    @Test
    @Ignore
    //Full flow, step-by-step for exploratory testing
    public void exampleFlow() throws Exception {
        String certificateFile = "38001085718.pem";
        String scope = OIDC_DEF_SCOPE;
        String locales = "et";

        Map<String, String> formParams = new HashMap<String, String>();
        formParams.put("scope", scope);
        formParams.put("response_type", "code");
        formParams.put("client_id", flow.getRelyingParty().getClientId());
        formParams.put("redirect_uri", flow.getRelyingParty().getRedirectUri());
        formParams.put("ui_locales", locales);
        Response authenticationResponse = Requests.openIdConnectAuthenticationRequest(flow, formParams);

        Response taraLoginPageResponse = Requests.followRedirect(flow, authenticationResponse.getHeader("location"));

        String execution = taraLoginPageResponse.getBody().htmlPath().getString("**.findAll { it.@name == 'execution' }[0].@value");
        Response idcardResponse = IdCard.idcard(flow, OpenIdConnectUtils.getResourceFileAsString(flow.getResourceLoader(), certificateFile));

        flow.updateSessionCookie(idcardResponse.cookie("SESSION"));

        Response submitResponse = submitIdCardLogin(flow, execution, authenticationResponse.getHeader("location"));

        Response oauth2Response = Requests.oauth2AuthorizeRedirect(flow, submitResponse.getHeader("location"));

        Response oidcResponse = Requests.oidcAuthorizeRedirect(flow, oauth2Response.getHeader("location"));

        Map<String, String> token = Requests.getTokenResponse(flow, OpenIdConnectUtils.getCode(flow, oidcResponse.getHeader("location")));
        System.out.println(token);
    }

    @Test
    @Description("Attacker attempts a session fixation attack")
    @Feature("ID-Card")
    @Link("https://www.owasp.org/index.php/Session_fixation")
    public void attackerSetsSessionCookie() throws Exception {
        String certificateFile = "38001085718.pem";

        Map<String, String> formParams = new HashMap<String, String>();
        formParams.put("scope", OIDC_DEF_SCOPE);
        formParams.put("response_type", "code");
        formParams.put("client_id", flow.getRelyingParty().getClientId());
        formParams.put("redirect_uri", flow.getRelyingParty().getRedirectUri());
        formParams.put("ui_locales", "et");

        flow.setEndUser("End-User: ");
        OpenIdConnectFlow attackerFlow = new OpenIdConnectFlow();
        setupFlow(attackerFlow, testTaraProperties);
        attackerFlow.setEndUser("Attacker: ");

        //Attacker obtains a session ID cookie
        Response attackerAuthenticationResponse = Requests.openIdConnectAuthenticationRequest(attackerFlow, formParams);

        Steps.log("Attacker sets SESSION cookie for End-User");
        flow.updateSessionCookie(attackerAuthenticationResponse.cookie("SESSION"));

        //User authenticates with cookie set by attacker
        Response authenticationResponse = Requests.openIdConnectAuthenticationRequest(flow, formParams);
        Response taraLoginPageResponse = Requests.followRedirect(flow, authenticationResponse.getHeader("location"));
        String execution = taraLoginPageResponse.getBody().htmlPath().getString("**.findAll { it.@name == 'execution' }[0].@value");
        Response idcardResponse = IdCard.idcard(flow, OpenIdConnectUtils.getResourceFileAsString(flow.getResourceLoader(), certificateFile));

        //Cookies should be changed when user is authenticated
        assertThat(idcardResponse.cookie("SESSION"), not(flow.getCookieFilter().cookieStore.getCookies().get(0).getValue()));

        //Attacker can not log in with fixed SESSION cookie
        submitIdCardLogin(attackerFlow, execution, authenticationResponse.getHeader("location")).then().statusCode(anyOf(is(401), is(500)));

        //End-User flow is successful
        flow.updateSessionCookie(idcardResponse.cookie("SESSION"));

        Response submitResponse = submitIdCardLogin(flow, execution, authenticationResponse.getHeader("location"));
        Response oauth2Response = Requests.oauth2AuthorizeRedirect(flow, submitResponse.getHeader("location"));
        Response oidcResponse = Requests.oidcAuthorizeRedirect(flow, oauth2Response.getHeader("location"));
        Requests.getTokenResponse(flow, OpenIdConnectUtils.getCode(flow, oidcResponse.getHeader("location")));
    }

    private void assertValidUserInfoResponseWithEmail(ExpectedOutput expectedOutcome, String accessToken) {
        assertValidUserinfoResponseWithEmail(expectedOutcome,
                Requests.getUserInfoWithAccessTokenAsBearerToken(flow, accessToken, flow.getOpenIDProvider().getUserInfoUrl())
        );

        assertValidUserinfoResponseWithEmail(expectedOutcome,
                Requests.getUserInfoWithAccessTokenAsQueryParameter(flow, accessToken, flow.getOpenIDProvider().getUserInfoUrl())
        );
    }


    private void assertValidUserInfoResponseWithoutEmail(ExpectedOutput expectedOutcome, String accessToken) throws Exception {
        assertValidUserinfoResponseWithoutEmail(expectedOutcome,
                Requests.getUserInfoWithAccessTokenAsBearerToken(flow, accessToken, flow.getOpenIDProvider().getUserInfoUrl())
        );

        assertValidUserinfoResponseWithoutEmail(expectedOutcome,
                Requests.getUserInfoWithAccessTokenAsQueryParameter(flow, accessToken, flow.getOpenIDProvider().getUserInfoUrl())
        );
    }

    private void assertValidUserinfoResponseWithEmail(ExpectedOutput expectedOutcome, Response userInfoResponse) {
        JsonPath json = userInfoResponse.jsonPath();
        assertThat(json.getMap("$.").keySet(), hasItems("sub", "auth_time", "given_name", "family_name", "date_of_birth", "amr", "email", "email_verified"));
        assertThat(json.get("sub"), equalTo(expectedOutcome.getSubject()));
        assertThat("auth_time must be a unix timestamp format and within the allowed timeframe", json.getLong("auth_time"), is(both(greaterThan(new Long(Instant.now().getEpochSecond() - TestConfiguration.ALLOWED_TIME_DIFFERENCE_IN_SECONDS))).and(lessThanOrEqualTo(Instant.now().getEpochSecond()))));
        assertThat(json.get("given_name"), equalTo(expectedOutcome.getFirstName()));
        assertThat(json.get("family_name"), equalTo(expectedOutcome.getFamilyName()));
        assertThat(json.get("date_of_birth"), equalTo(expectedOutcome.getDateOfBirth()));
        assertThat(json.get("email_verified"), equalTo(expectedOutcome.isEmailVerified()));
        assertThat(json.get("email"), equalTo(expectedOutcome.getEmail()));
        assertThat(json.getList("amr"), equalTo(Arrays.asList(expectedOutcome.getAmr())));
    }

    private void assertValidUserinfoResponseWithoutEmail(ExpectedOutput expectedOutcome, Response userInfoResponse) throws Exception {
        JsonPath json = userInfoResponse.jsonPath();
        assertThat(json.getMap("$.").keySet(), hasItems("sub", "auth_time", "given_name", "family_name", "date_of_birth", "amr"));
        assertThat(json.get("sub"), equalTo(expectedOutcome.getSubject()));
        assertThat("auth_time must be a unix timestamp format and within the allowed timeframe", json.getLong("auth_time"), is(both(greaterThan(new Long(Instant.now().getEpochSecond() - TestConfiguration.ALLOWED_TIME_DIFFERENCE_IN_SECONDS))).and(lessThanOrEqualTo(Instant.now().getEpochSecond()))));
        assertThat(json.get("given_name"), equalTo(expectedOutcome.getFirstName()));
        assertThat(json.get("family_name"), equalTo(expectedOutcome.getFamilyName()));
        assertThat(json.get("date_of_birth"), equalTo(expectedOutcome.getDateOfBirth()));
        assertThat(json.getList("amr"), equalTo(Arrays.asList(expectedOutcome.getAmr())));
    }

}
