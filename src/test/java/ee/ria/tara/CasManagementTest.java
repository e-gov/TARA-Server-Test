package ee.ria.tara;


import com.nimbusds.jose.jwk.JWKSet;
import ee.ria.tara.config.IntegrationTest;
import ee.ria.tara.config.TestTaraProperties;
import ee.ria.tara.model.OpenIdConnectFlow;
import ee.ria.tara.steps.IdCard;
import ee.ria.tara.steps.Requests;
import ee.ria.tara.utils.AllureRestAssuredCorrectHeaders;
import ee.ria.tara.utils.OpenIdConnectUtils;
import io.qameta.allure.Step;
import io.restassured.config.RestAssuredConfig;
import io.restassured.config.SSLConfig;
import io.restassured.response.Response;
import org.apache.http.cookie.Cookie;
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

import static ee.ria.tara.steps.IdCard.submitIdCardLogin;
import static io.restassured.RestAssured.given;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.startsWith;

@SpringBootTest(classes = CasManagementTest.class)
@Category(IntegrationTest.class)
public class CasManagementTest extends TestsBase {
    @Autowired
    private ResourceLoader resourceLoader;
    private static boolean setupComplete = false;
    private OpenIdConnectFlow flow;
    private static RestAssuredConfig config;

    @Before
    public void setUp() throws IOException, ParseException {
        if (!setupComplete) {
            initialize();
            setupComplete = true;
        }
        flow = new OpenIdConnectFlow();
        setupFlow(flow, testTaraProperties);
    }

    void setupFlow(OpenIdConnectFlow flow, TestTaraProperties properties) {
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
    public void managementLoginIdCard() throws Exception {
        Response manageResponse = openManagementPage(flow);
        Response taraLoginPage = Requests.followRedirect(flow, manageResponse.getHeader("location"));
        String execution = taraLoginPage.getBody().htmlPath().getString("**.findAll { it.@name == 'execution' }[0].@value");
        Response idcardResponse = IdCard.idcard(flow, OpenIdConnectUtils.getResourceFileAsString(flow.getResourceLoader(), "47101010033.pem"));
        flow.updateSessionCookie(idcardResponse.cookie("SESSION"));
        Response submitResponse = submitIdCardLogin(flow, execution, manageResponse.getHeader("location"));
        Response oauth2Response = managementTicketValidation(flow, submitResponse.getHeader("location"));
        String pac4jcookie = oauth2Response.getCookie("pac4jCsrfToken");
        Response managePage = managementPageRedirect(flow, oauth2Response.getHeader("Location"), pac4jcookie);

        managePage.then().statusCode(200);
        assertThat(managePage.htmlPath().getString("html.head.title"), equalTo("Services Management"));
    }

    @Step("Open CAS management page")
    public static Response openManagementPage(OpenIdConnectFlow flow) {
        return given()
                .filter(flow.getCookieFilter())
                .filter(new AllureRestAssuredCorrectHeaders())
                .relaxedHTTPSValidation()
                .when()
                .redirects().follow(false)
                .get(flow.getTestProperties().getManageUrl()+"/cas-management/manage.html")
                .then().extract().response();
    }

    @Step("{flow.endUser}Follow redirect - /manage.html?ticket=ST-*****")
    public static Response managementTicketValidation(OpenIdConnectFlow flow, String location) {
        //TODO: this is no longer the case, uses SESSION cookie
        //CAS management login flow has 2 JSESSIONID cookies - / and /cas-management
        //Regular Rest-Assured cookie filter only sends a single cookie
        String cookieHeader = "";
        for (Cookie cookie : flow.getCookieFilter().cookieStore.getCookies()) {
            cookieHeader += cookie.getName() + "=" + cookie.getValue() + "; ";
        }
        return given()
                .filter(new AllureRestAssuredCorrectHeaders())
                .header("Cookies", cookieHeader)
                .relaxedHTTPSValidation()
                .redirects().follow(false)
                .when()
                .urlEncodingEnabled(false)
                .get(location).then()
                .extract().response();
    }

    @Step("{flow.endUser}Follow redirect - /manage.html")
    public static Response managementPageRedirect(OpenIdConnectFlow flow, String location, String pac4jCookie) {
        String cookieHeader = "";
        for (Cookie cookie : flow.getCookieFilter().cookieStore.getCookies()) {
            cookieHeader += cookie.getName() + "=" + cookie.getValue() + "; ";
        }
        cookieHeader += "pac4jCsrfToken=" + pac4jCookie;
        return given()
                .filter(new AllureRestAssuredCorrectHeaders())
                .header("Cookies", cookieHeader)
                .relaxedHTTPSValidation()
                .redirects().follow(false)
                .when()
                .urlEncodingEnabled(false)
                .get(location).then()
                .extract().response();
    }
}
