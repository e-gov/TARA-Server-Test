package ee.ria.tara;


import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWTClaimsSet;
import ee.ria.tara.config.IntegrationTest;
import ee.ria.tara.config.TestTaraProperties;
import ee.ria.tara.model.OpenIdConnectFlow;
import ee.ria.tara.steps.Requests;
import ee.ria.tara.steps.SmartId;
import ee.ria.tara.steps.Steps;
import ee.ria.tara.utils.Feature;
import ee.ria.tara.utils.OpenIdConnectUtils;
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
import java.util.List;
import java.util.Map;

import static ee.ria.tara.config.TaraTestStrings.OIDC_DEF_SCOPE;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.startsWith;


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
        Response oidcResponse = SmartId.authenticateWithSmartId(flow, "10101010005", 2000, OIDC_DEF_SCOPE);
        String token = Requests.getIdToken(flow, OpenIdConnectUtils.getCode(flow, oidcResponse.getHeader("location")));
        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, token).getJWTClaimsSet();

        assertThat(claims.getSubject(), equalTo("EE10101010005"));
        assertThat(claims.getJSONObjectClaim("profile_attributes").getAsString("given_name"), equalTo("DEMO"));
        assertThat(claims.getJSONObjectClaim("profile_attributes").getAsString("family_name"), equalTo("SMART-ID"));
        assertThat(claims.getJSONObjectClaim("profile_attributes").getAsString("date_of_birth"), equalTo("1801-01-01"));
        assertThat(claims.getStringArrayClaim("amr")[0], equalTo("smartid"));
    }

    @Test
    @Feature("TSID-11")
    public void smartid_UserRefuses() throws Exception {
        List errorMessage = SmartId.extractError(SmartId.authenticatePollError(flow, "10101010016", 2000));
        assertThat(errorMessage.get(1), equalTo("Autentimine katkestati kasutaja poolt."));
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


        List errorMessage = SmartId.extractError(submitResponse);
        assertThat(errorMessage.get(1), equalTo("Isikukood on ebakorrektses formaadis."));
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
        List errorMessage = SmartId.extractError(submitResponse);
        assertThat(errorMessage.get(1), equalTo("Isikukood puudu"));
    }
}
