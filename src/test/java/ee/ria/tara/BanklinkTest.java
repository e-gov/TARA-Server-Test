package ee.ria.tara;


import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.SignedJWT;
import ee.ria.tara.config.IntegrationTest;
import ee.ria.tara.config.TestTaraProperties;
import ee.ria.tara.model.OpenIdConnectFlow;
import ee.ria.tara.steps.Banklink;
import ee.ria.tara.steps.BanklinkMock;
import ee.ria.tara.steps.Requests;
import ee.ria.tara.steps.Steps;
import ee.ria.tara.utils.Feature;
import ee.ria.tara.utils.OpenIdConnectUtils;
import io.restassured.response.Response;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.hamcrest.core.StringContains;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.opensaml.core.config.InitializationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.ResourceLoader;

import java.io.IOException;
import java.net.URL;
import java.security.Security;
import java.text.ParseException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

import static ee.ria.tara.config.TaraTestStrings.OIDC_DEF_SCOPE;
import static io.restassured.RestAssured.given;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertEquals;

@SpringBootTest(classes = BanklinkTest.class)
@Category(IntegrationTest.class)
public class BanklinkTest extends TestsBase {
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
    @Feature("TPL-8")
    public void bank_example_seb() throws Exception {
        BanklinkMock.createBank(flow, "EYP", "seb_priv");
        BanklinkMock.setBankDefault(flow, "EYP", "VK_OTHER", "ISIK:60001019896;NIMI:Test-Surname,Given-Name1 Givenname2");
        BanklinkMock.setBankDefault(flow, "EYP", "VK_USER_NAME", "Test-Surname,Given-Name1 Givenname2");
        BanklinkMock.setBankDefault(flow, "EYP", "VK_USER_ID", "60001019896");
        BanklinkMock.setBankDefault(flow, "EYP", "VK_COUNTRY", "EE");

        Map bankRequestParams = Banklink.startBankAuthentication(flow, "seb", OIDC_DEF_SCOPE, "et");
        Map bankResponseParams = BanklinkMock.getBankResponse(flow, bankRequestParams);
        String location = Banklink.banklinkCallbackPOST(flow, bankResponseParams);
        Response oidcResponse = Requests.followLoginRedirects(flow, location);
        String token = Requests.getIdToken(flow, OpenIdConnectUtils.getCode(flow, oidcResponse.getHeader("location")));
        SignedJWT signedJWT = Steps.verifyTokenAndReturnSignedJwtObject(flow, token);

        assertEquals("EE60001019896", signedJWT.getJWTClaimsSet().getSubject());
        assertEquals("GIVEN-NAME1", signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("given_name"));
        assertEquals("TEST-SURNAME", signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("family_name"));
        assertEquals("2000-01-01", signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("date_of_birth"));
        assertEquals("banklink", signedJWT.getJWTClaimsSet().getStringArrayClaim("amr")[0]);
    }

    @Test
    @Feature("TPL-8")
    public void bank_example_swedbank() throws Exception {
        BanklinkMock.createBank(flow, "HP", "swedbank_priv");
        BanklinkMock.setBankDefault(flow, "HP", "VK_OTHER", "");
        BanklinkMock.setBankDefault(flow, "HP", "VK_USER_NAME", "Test-Surname,Given-Name1 Givenname2");
        BanklinkMock.setBankDefault(flow, "HP", "VK_USER_ID", "60001019896");
        BanklinkMock.setBankDefault(flow, "HP", "VK_COUNTRY", "EE");

        Map bankRequestParams = Banklink.startBankAuthentication(flow, "swedbank", OIDC_DEF_SCOPE, "et");
        Map bankResponseParams = BanklinkMock.getBankResponse(flow, bankRequestParams);
        String location = Banklink.banklinkCallbackPOST(flow, bankResponseParams);
        Response oidcResponse = Requests.followLoginRedirects(flow, location);
        String token = Requests.getIdToken(flow, OpenIdConnectUtils.getCode(flow, oidcResponse.getHeader("location")));
        SignedJWT signedJWT = Steps.verifyTokenAndReturnSignedJwtObject(flow, token);

        assertEquals("EE60001019896", signedJWT.getJWTClaimsSet().getSubject());
        assertEquals("GIVEN-NAME1", signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("given_name"));
        assertEquals("TEST-SURNAME", signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("family_name"));
        assertEquals("2000-01-01", signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("date_of_birth"));
        assertEquals("banklink", signedJWT.getJWTClaimsSet().getStringArrayClaim("amr")[0]);
    }

    @Test
    @Feature("TPL-8")
    public void bank_example_coop() throws Exception {
        BanklinkMock.createBank(flow, "KREP", "coop_priv");
        BanklinkMock.setBankDefault(flow, "KREP", "VK_OTHER", "");
        BanklinkMock.setBankDefault(flow, "KREP", "VK_USER_NAME", "Test-Surname,Given-Name1 Givenname2");
        BanklinkMock.setBankDefault(flow, "KREP", "VK_USER_ID", "60001019896");
        BanklinkMock.setBankDefault(flow, "KREP", "VK_COUNTRY", "EE");

        Map bankRequestParams = Banklink.startBankAuthentication(flow, "coop", OIDC_DEF_SCOPE, "et");
        Map bankResponseParams = BanklinkMock.getBankResponse(flow, bankRequestParams);
        String location = Banklink.banklinkCallbackGET(flow, bankResponseParams);
        Response oidcResponse = Requests.followLoginRedirects(flow, location);
        String token = Requests.getIdToken(flow, OpenIdConnectUtils.getCode(flow, oidcResponse.getHeader("location")));
        SignedJWT signedJWT = Steps.verifyTokenAndReturnSignedJwtObject(flow, token);

        assertEquals("EE60001019896", signedJWT.getJWTClaimsSet().getSubject());
        assertEquals("GIVEN-NAME1", signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("given_name"));
        assertEquals("TEST-SURNAME", signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("family_name"));
        assertEquals("2000-01-01", signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("date_of_birth"));
        assertEquals("banklink", signedJWT.getJWTClaimsSet().getStringArrayClaim("amr")[0]);
    }

    @Test
    @Feature("TPL-8")
    public void bank_example_lhv() throws Exception {
        BanklinkMock.createBank(flow, "LHV", "lhv_priv");

        BanklinkMock.setBankDefault(flow, "LHV", "VK_OTHER", "");
        BanklinkMock.setBankDefault(flow, "LHV", "VK_USER_NAME", "Given-Name1 Given-Name2 Test-Surname");
        BanklinkMock.setBankDefault(flow, "LHV", "VK_USER_ID", "60001019896");
        BanklinkMock.setBankDefault(flow, "LHV", "VK_COUNTRY", "EE");

        Map bankRequestParams = Banklink.startBankAuthentication(flow, "lhv", OIDC_DEF_SCOPE, "et");
        Map bankResponseParams = BanklinkMock.getBankResponse(flow, bankRequestParams);
        String location = Banklink.banklinkCallbackPOST(flow, bankResponseParams);
        Response oidcResponse = Requests.followLoginRedirects(flow, location);
        String token = Requests.getIdToken(flow, OpenIdConnectUtils.getCode(flow, oidcResponse.getHeader("location")));
        SignedJWT signedJWT = Steps.verifyTokenAndReturnSignedJwtObject(flow, token);

        assertEquals("EE60001019896", signedJWT.getJWTClaimsSet().getSubject());
        assertEquals("GIVEN-NAME1 GIVEN-NAME2", signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("given_name"));
        assertEquals("TEST-SURNAME", signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("family_name"));
        assertEquals("2000-01-01", signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("date_of_birth"));
        assertEquals("banklink", signedJWT.getJWTClaimsSet().getStringArrayClaim("amr")[0]);
    }

    @Test
    @Feature("TPL-2")
    public void bank1_bankRequestParams() throws Exception {
        BanklinkMock.createBank(flow, "DANSKE", "danske_priv");

        Map<String, String> bankRequestParams = Banklink.startBankAuthentication(flow, "danske", OIDC_DEF_SCOPE, "et");
        Map<String, String> expectedBankRequestParams = new HashMap<>();
        expectedBankRequestParams.put("VK_SERVICE", "4012");
        expectedBankRequestParams.put("VK_VERSION", "008");
        expectedBankRequestParams.put("VK_SND_ID", "TARA_DANSKE");
        expectedBankRequestParams.put("VK_REC_ID", "DANSKE");
        expectedBankRequestParams.put("VK_RETURN", flow.getOpenIDProvider().getLoginUrl());
        expectedBankRequestParams.put("VK_RID", "");
        expectedBankRequestParams.put("VK_ENCODING", "UTF-8");
        expectedBankRequestParams.put("VK_LANG", "EST");

        assertThat(new HashSet<Object>(bankRequestParams.entrySet()), hasItems(expectedBankRequestParams.entrySet().toArray()));
        assertThat("VK_NONCE", bankRequestParams.get("VK_NONCE"), not(isEmptyString()));
        assertThat("VK_DATETIME", bankRequestParams.get("VK_DATETIME"), not(isEmptyString()));
        assertThat("VK_MAC", bankRequestParams.get("VK_MAC"), not(isEmptyString()));
    }

    @Test
    @Feature("TPL-2")
    public void bank2_bankRequestParams_langEN() throws Exception {
        BanklinkMock.createBank(flow, "DANSKE", "danske_priv");

        Map bankRequestParams = Banklink.startBankAuthentication(flow, "danske", OIDC_DEF_SCOPE, "en");

        Map<String, String> expectedBankRequestParams = new HashMap<String, String>();
        expectedBankRequestParams.put("VK_LANG", "ENG");
        assertThat(new HashSet<Object>(bankRequestParams.entrySet()), hasItems(expectedBankRequestParams.entrySet().toArray()));
    }

    @Test
    @Feature("TPL-2")
    public void bank2_bankRequestParams_langRU() throws Exception {
        BanklinkMock.createBank(flow, "DANSKE", "danske_priv");

        Map bankRequestParams = Banklink.startBankAuthentication(flow, "danske", OIDC_DEF_SCOPE, "ru");

        Map<String, String> expectedBankRequestParams = new HashMap<String, String>();
        expectedBankRequestParams.put("VK_LANG", "RUS");
        assertThat(new HashSet<Object>(bankRequestParams.entrySet()), hasItems(expectedBankRequestParams.entrySet().toArray()));
    }

    @Test
    @Feature("TPL-6")
    public void bank_VK_NONCE_reuseForbidden() throws Exception {
        BanklinkMock.createBank(flow, "DANSKE", "danske_priv");

        Map bankRequestParams = Banklink.startBankAuthentication(flow, "danske", OIDC_DEF_SCOPE, "et");


        Map bankResponseParams = BanklinkMock.getBankResponse(flow, bankRequestParams);
        String location = Banklink.banklinkCallbackPOST(flow, bankResponseParams);
        Response oidcResponse = Requests.followLoginRedirects(flow, location);
        String token = Requests.getIdToken(flow, OpenIdConnectUtils.getCode(flow, oidcResponse.getHeader("location")));
        SignedJWT signedJWT = Steps.verifyTokenAndReturnSignedJwtObject(flow, token);

        String responseBody = given().filter(flow.getCookieFilter()).relaxedHTTPSValidation().log().all().formParams(bankResponseParams).post(flow.getOpenIDProvider().getLoginUrl()).then().statusCode(401).log().all().extract().response().body().asString();
        assertThat(responseBody, StringContains.containsString("Kasutaja tuvastamine ebaõnnestus"));
    }

    @Test
    @Feature("TPL-6")
    public void bank_single_VK_NONCE_in_session() throws Exception {
        BanklinkMock.createBank(flow, "DANSKE", "danske_priv");

        Map bankRequestParams = Banklink.startBankAuthentication(flow, "danske", OIDC_DEF_SCOPE, "et");
        Map bankRequestParams2 = Banklink.startBankAuthentication(flow, "danske", OIDC_DEF_SCOPE, "et");
        Map bankResponseParams = BanklinkMock.getBankResponse(flow, bankRequestParams);
        String location = Banklink.banklinkCallbackPOST(flow, bankResponseParams);
        Response oidcResponse = Requests.followLoginRedirects(flow, location);
        String token = Requests.getIdToken(flow, OpenIdConnectUtils.getCode(flow, oidcResponse.getHeader("location")));
        SignedJWT signedJWT = Steps.verifyTokenAndReturnSignedJwtObject(flow, token);

        String responseBody = given().filter(flow.getCookieFilter()).relaxedHTTPSValidation().log().all().formParams(bankResponseParams).post(flow.getOpenIDProvider().getLoginUrl()).then().statusCode(401).log().all().extract().response().body().asString();
        assertThat(responseBody, StringContains.containsString("Kasutaja tuvastamine ebaõnnestus"));
    }

    @Test
    @Feature("TPL-8")
    public void bank_latvian_example() throws Exception {
        BanklinkMock.createBank(flow, "DANSKE", "danske_priv");

        BanklinkMock.setBankDefault(flow, "DANSKE", "VK_USER_NAME", "Test-Surname,Given-Name1 Givenname2");
        BanklinkMock.setBankDefault(flow, "DANSKE", "VK_USER_ID", "320000-00000");
        BanklinkMock.setBankDefault(flow, "DANSKE", "VK_COUNTRY", "LV");
        Map bankRequestParams = Banklink.startBankAuthentication(flow, "danske", OIDC_DEF_SCOPE, "et");
        Map bankResponseParams = BanklinkMock.getBankResponse(flow, bankRequestParams);
        String location = Banklink.banklinkCallbackPOST(flow, bankResponseParams);
        Response oidcResponse = Requests.followLoginRedirects(flow, location);
        String token = Requests.getIdToken(flow, OpenIdConnectUtils.getCode(flow, oidcResponse.getHeader("location")));
        SignedJWT signedJWT = Steps.verifyTokenAndReturnSignedJwtObject(flow, token);

        assertEquals("LV320000-00000", signedJWT.getJWTClaimsSet().getSubject());
        assertEquals("GIVEN-NAME1", signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("given_name"));
        assertEquals("TEST-SURNAME", signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("family_name"));
        assertEquals(null, signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("date_of_birth"));
    }


    //TODO: datetime tests
    //setBankDefault("HP", "VK_DATETIME", "2018-09-07T12:50:45+0300");

}
