package ee.ria.tara;


import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWTClaimsSet;
import ee.ria.tara.config.IntegrationTest;
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
import io.restassured.response.Response;
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
import java.util.HashMap;
import java.util.Map;

import static ee.ria.tara.config.TaraTestStrings.OIDC_DEF_SCOPE;
import static ee.ria.tara.steps.IdCard.submitIdCardLogin;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;

@SpringBootTest(classes = IdCardTest.class)
@Category(IntegrationTest.class)
public class IdCardTest extends TestsBase {
    @Autowired
    private ResourceLoader resourceLoader;
    private static boolean setupComplete = false;
    private OpenIdConnectFlow flow;
    private RestAssuredConfig config;


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
        Response oidcResponse = IdCard.authenticateWithIdCard(flow, "38001085718.pem", OIDC_DEF_SCOPE, "et");
        String token = Requests.getIdToken(flow, OpenIdConnectUtils.getCode(flow, oidcResponse.getHeader("location")));
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, token).getJWTClaimsSet();

        assertThat(claims.getSubject(), equalTo("EE38001085718"));
        assertThat(claims.getJSONObjectClaim("profile_attributes").getAsString("given_name"), equalTo("JAAK-KRISTJAN"));
        assertThat(claims.getJSONObjectClaim("profile_attributes").getAsString("family_name"), equalTo("JÕEORG"));
        assertThat(claims.getJSONObjectClaim("profile_attributes").getAsString("date_of_birth"), equalTo("1980-01-08"));
        assertThat(claims.getStringArrayClaim("amr")[0], equalTo("idcard"));
    }

    @Test
    @Feature("ID-1")
    public void validLoginWithEsteid2015RsaCertificate() throws Exception {
        Response oidcResponse = IdCard.authenticateWithIdCard(flow, "37101010021.pem", OIDC_DEF_SCOPE, "et");
        String token = Requests.getIdToken(flow, OpenIdConnectUtils.getCode(flow, oidcResponse.getHeader("location")));
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, token).getJWTClaimsSet();

        assertThat(claims.getSubject(), equalTo("EE37101010021"));
        assertThat(claims.getJSONObjectClaim("profile_attributes").getAsString("given_name"), equalTo("IGOR"));
        assertThat(claims.getJSONObjectClaim("profile_attributes").getAsString("family_name"), equalTo("ŽAIKOVSKI"));
        assertThat(claims.getJSONObjectClaim("profile_attributes").getAsString("date_of_birth"), equalTo("1971-01-01"));
        assertThat(claims.getStringArrayClaim("amr")[0], equalTo("idcard"));
    }

    @Test
    @Feature("ID-1")
    public void validLoginWithEsteid2015EccCertificate() throws Exception {
        Response oidcResponse = IdCard.authenticateWithIdCard(flow, "47101010033.pem", OIDC_DEF_SCOPE, "et");
        String token = Requests.getIdToken(flow, OpenIdConnectUtils.getCode(flow, oidcResponse.getHeader("location")));
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, token).getJWTClaimsSet();

        assertThat(claims.getSubject(), equalTo("EE47101010033"));
        assertThat(claims.getJSONObjectClaim("profile_attributes").getAsString("given_name"), equalTo("MARI-LIIS"));
        assertThat(claims.getJSONObjectClaim("profile_attributes").getAsString("family_name"), equalTo("MÄNNIK"));
        assertThat(claims.getJSONObjectClaim("profile_attributes").getAsString("date_of_birth"), equalTo("1971-01-01"));
        assertThat(claims.getStringArrayClaim("amr")[0], equalTo("idcard"));
    }

    @Test
    @Ignore
    //Full flow, step-by-step for exploratory testing
    public void exampleFlow() throws Exception {
        String certificateFile = "38001085718.pem";
        String scope = OIDC_DEF_SCOPE;
        String language = "et";

        Map<String, String> formParams = new HashMap<String, String>();
        formParams.put("scope", scope);
        formParams.put("response_type", "code");
        formParams.put("client_id", flow.getRelyingParty().getClientId());
        formParams.put("redirect_uri", flow.getRelyingParty().getRedirectUri());
        formParams.put("lang", language);
        Response authenticationResponse = Requests.openIdConnectAuthenticationRequest(flow, formParams);

        Response taraLoginPageResponse = Requests.followRedirect(flow, authenticationResponse.getHeader("location"));

        String execution = taraLoginPageResponse.getBody().htmlPath().getString("**.findAll { it.@name == 'execution' }[0].@value");
        Response idcardResponse = IdCard.idcard(flow, OpenIdConnectUtils.getResourceFileAsString(flow.getResourceLoader(), certificateFile));

        flow.updateSessionId(idcardResponse.cookie("JSESSIONID"));
        Response submitResponse = submitIdCardLogin(flow, execution, authenticationResponse.getHeader("location"));

        Response oauth2Response = Requests.oauth2AuthorizeRedirect(flow, submitResponse.getHeader("location"));

        Response oidcResponse = Requests.oidcAuthorizeRedirect(flow, oauth2Response.getHeader("location"));

        String token = Requests.getIdToken(flow, OpenIdConnectUtils.getCode(flow, oidcResponse.getHeader("location")));
        System.out.println(token);
    }

    //TODO: what happens when /idcard response returns false?
    @Test
    @Description("Attacker attempts a session fixation attack")
    @Feature("ID-Card")
    @Link("https://www.owasp.org/index.php/Session_fixation")
    public void jsessionIdAttackerSetsCookie() throws Exception {
        String certificateFile = "38001085718.pem";

        Map<String, String> formParams = new HashMap<String, String>();
        formParams.put("scope", OIDC_DEF_SCOPE);
        formParams.put("response_type", "code");
        formParams.put("client_id", flow.getRelyingParty().getClientId());
        formParams.put("redirect_uri", flow.getRelyingParty().getRedirectUri());
        formParams.put("lang", "et");

        flow.setEndUser("End-User: ");
        OpenIdConnectFlow attackerFlow = new OpenIdConnectFlow();
        setupFlow(attackerFlow, testTaraProperties);
        attackerFlow.setEndUser("Attacker: ");

        //Attacker obtains a session ID cookie
        Response attackerAuthenticationResponse = Requests.openIdConnectAuthenticationRequest(attackerFlow, formParams);

        Steps.log("Attacker sets JSESSIONID cookie for End-User");
        flow.updateSessionId(attackerAuthenticationResponse.cookie("JSESSIONID"));
        //User authenticates with cookie set by attacker
        Response authenticationResponse = Requests.openIdConnectAuthenticationRequest(flow, formParams);
        Response taraLoginPageResponse = Requests.followRedirect(flow, authenticationResponse.getHeader("location"));
        String execution = taraLoginPageResponse.getBody().htmlPath().getString("**.findAll { it.@name == 'execution' }[0].@value");
        Response idcardResponse = IdCard.idcard(flow, OpenIdConnectUtils.getResourceFileAsString(flow.getResourceLoader(), certificateFile));

        //Cookie should be changed when user is authenticated
        assertThat(idcardResponse.cookie("JSESSIONID"), not(flow.getCookieFilter().cookieStore.getCookies().get(0).getValue()));

        //Attacker can not log in with fixed JSESSIONID
        submitIdCardLogin(attackerFlow, execution, authenticationResponse.getHeader("location")).then().statusCode(401);

        //End-User flow is successful
        flow.updateSessionId(idcardResponse.cookie("JSESSIONID"));
        Response submitResponse = submitIdCardLogin(flow, execution, authenticationResponse.getHeader("location"));
        Response oauth2Response = Requests.oauth2AuthorizeRedirect(flow, submitResponse.getHeader("location"));
        Response oidcResponse = Requests.oidcAuthorizeRedirect(flow, oauth2Response.getHeader("location"));
        String token = Requests.getIdToken(flow, OpenIdConnectUtils.getCode(flow, oidcResponse.getHeader("location")));
    }
}
