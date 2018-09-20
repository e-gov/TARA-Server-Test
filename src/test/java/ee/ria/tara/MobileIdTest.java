package ee.ria.tara;


import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWTClaimsSet;
import ee.ria.tara.config.IntegrationTest;
import ee.ria.tara.config.TestTaraProperties;
import ee.ria.tara.model.OpenIdConnectFlow;
import ee.ria.tara.steps.MobileId;
import ee.ria.tara.steps.Requests;
import ee.ria.tara.steps.Steps;
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

import static ee.ria.tara.config.TaraTestStrings.OIDC_AMR_MID;
import static ee.ria.tara.config.TaraTestStrings.OIDC_DEF_SCOPE;
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
        String token = Requests.getIdToken(flow, OpenIdConnectUtils.getCode(flow, oidcResponse.getHeader("location")));

        JWTClaimsSet claims = Steps.verifyTokenAndReturnSignedJwtObject(flow, token).getJWTClaimsSet();

        assertThat(claims.getSubject(), equalTo("EE60001019906"));
        assertThat(claims.getJSONObjectClaim("profile_attributes").getAsString("given_name"), equalTo("MARY ÄNN"));
        assertThat(claims.getJSONObjectClaim("profile_attributes").getAsString("family_name"), equalTo("O’CONNEŽ-ŠUSLIK TESTNUMBER"));
        assertThat(claims.getJSONObjectClaim("profile_attributes").getAsString("date_of_birth"), equalTo("2000-01-01"));
        assertThat(claims.getJSONObjectClaim("profile_attributes").keySet(), not(hasItem("mobile_number")));
        assertThat(claims.getStringArrayClaim("amr")[0], equalTo(OIDC_AMR_MID));
    }

    @Test
    public void mob2_mobileIdAuthenticationMidNotActivated() {
        String errorMessage = MobileId.extractError(MobileId.authenticateWithMobileIdError(flow, "00000366", "60001019928"));
        assertThat(errorMessage, startsWith("Mobiil-ID teenuses esinevad tehnilised tõrked. Palun proovige mõne aja pärast uuesti."));
    }

    @Test
    public void mob2_mobileIdAuthenticationUserCertificatesRevoked() {
        String errorMessage = MobileId.extractError(MobileId.authenticateWithMobileIdError(flow, "00000266", "60001019939"));
        assertThat(errorMessage, startsWith("Autentimine Mobiil-ID-ga ei õnnestunud. Testi oma Mobiil-ID toimimist DigiDoc3 kliendis: http://www.id.ee/index.php?id=35636"));
    }

    @Test
    public void mob2_mobileIdAuthenticationRequestToPhoneFailed() throws Exception {
        String errorMessage = MobileId.extractError(MobileId.authenticateWithMobileIdPollError(flow, "07110066", "60001019947", 500));
        assertThat(errorMessage, startsWith("Teie mobiiltelefoni ei saa Mobiil-ID autentimise sõnumeid saata."));
    }

    @Test
    public void mob2_mobileIdAuthenticationTechnicalError() throws Exception {
        String errorMessage = MobileId.extractError(MobileId.authenticateWithMobileIdPollError(flow, "00000666", "60001019961", 3000));
        assertThat(errorMessage, startsWith("Autentimine Mobiil-ID-ga ei õnnestunud. Testi oma Mobiil-ID toimimist DigiDoc3 kliendis: http://www.id.ee/index.php?id=35636"));
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
    public void mob3_mobileIdAuthenticationInvalidIdCode() {
        String errorMessage = MobileId.extractError(MobileId.authenticateWithMobileIdError(flow, "66", "00000766"));
        assertThat(errorMessage, startsWith("Kasutajal pole Mobiil-ID lepingut"));
    }

    /**
     * Verifying that user receives proper error message when user inserts invalid phone number
     */
    @Test
    public void mob3_mobileIdAuthenticationInvalidPhoneNumber() {
        String errorMessage = MobileId.extractError(MobileId.authenticateWithMobileIdError(flow, "123456789123", "60001019906"));
        assertThat(errorMessage, startsWith("Kasutajal pole Mobiil-ID lepingut.Intsidendi number:"));
    }

    /**
     * Verifying that user receives proper error message when user doesn't insert phone number
     */
    @Test
    public void mob3_mobileIdAuthenticationNoMobileNo() {
        String errorMessage = MobileId.extractError(MobileId.authenticateWithMobileIdError(flow, "", "60001019906"));
        assertThat(errorMessage, startsWith("Telefoninumber ei ole korrektne.Intsidendi number:"));
    }

    /**
     * Verifying that user receives proper error message when user doesn't insert id code
     */
    @Test
    public void mob3_mobileIdAuthenticationNoIdCode() {
        String errorMessage = MobileId.extractError(MobileId.authenticateWithMobileIdError(flow, "00000766", ""));
        assertThat(errorMessage, startsWith("Isikukood ei ole korrektne.Intsidendi number:"));
    }

    /**
     * Verifying that user receives proper error message when user doesn't insert any parameters
     */
    @Test
    public void mob3_mobileIdAuthenticationNoParameters() {
        String errorMessage = MobileId.extractError(MobileId.authenticateWithMobileIdError(flow, "", ""));
        assertThat(errorMessage, startsWith("Isikukood ei ole korrektne.Intsidendi number:"));
    }
}

