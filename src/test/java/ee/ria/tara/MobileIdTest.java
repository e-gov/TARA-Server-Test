package ee.ria.tara;


import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.SignedJWT;
import ee.ria.tara.config.IntegrationTest;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.springframework.boot.test.context.SpringBootTest;

import java.net.URISyntaxException;
import java.text.ParseException;

import static ee.ria.tara.config.TaraTestStrings.OIDC_DEF_SCOPE;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.Assert.assertEquals;

@SpringBootTest(classes = MobileIdTest.class)
@Category(IntegrationTest.class)
public class MobileIdTest extends TestsBase {

    @Ignore
    @Test
    public void mob1_mobileIdAuthenticationSuccess() throws InterruptedException, URISyntaxException, ParseException, JOSEException {
        String authorizationCode = authenticateWithMobileId("00000266", "60001019896", 2000, OIDC_DEF_SCOPE);
        SignedJWT signedJWT = verifyTokenAndReturnSignedJwtObject(getIdToken(authorizationCode));

        assertEquals("EE60001019896", signedJWT.getJWTClaimsSet().getSubject());
        assertEquals("MARY ÄNN", signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("given_name"));
        assertEquals("O’CONNEŽ-ŠUSLIK TESTNUMBER", signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("family_name"));
        assertEquals("+37200000266", signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("mobile_number"));
        assertEquals("2000-01-01", signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("date_of_birth"));
    }

    @Test
    public void mob1_mobileIdAuthenticationSuccessWithRealLifeDelay() throws InterruptedException, URISyntaxException, ParseException, JOSEException {
        String authorizationCode = authenticateWithMobileId("00000766", "60001019906", 7000, OIDC_DEF_SCOPE);
        SignedJWT signedJWT = verifyTokenAndReturnSignedJwtObject(getIdToken(authorizationCode));

        assertEquals("EE60001019906", signedJWT.getJWTClaimsSet().getSubject());
        assertEquals("MARY ÄNN", signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("given_name"));
        assertEquals("O’CONNEŽ-ŠUSLIK TESTNUMBER", signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("family_name"));
        assertEquals("+37200000766", signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("mobile_number"));
        assertEquals("2000-01-01", signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("date_of_birth"));
    }

    @Test
    public void mob2_mobileIdAuthenticationMidNotActivated() {
        String errorMessage = authenticateWithMobileIdError("00000366", "60001019928");
        assertThat(errorMessage, startsWith("Mobiil-ID teenuses esinevad tehnilised tõrked. Palun proovige mõne aja pärast uuesti."));
    }

    @Test
    public void mob2_mobileIdAuthenticationUserCertificatesRevoked() {
        String errorMessage = authenticateWithMobileIdError("00000266", "60001019939");
        assertThat(errorMessage, startsWith("Autentimine Mobiil-ID-ga ei õnnestunud. Testi oma Mobiil-ID toimimist haldusvahendis: http://www.id.ee/index.php?id=35636"));
    }

    @Test
    public void mob2_mobileIdAuthenticationRequestToPhoneFailed() throws URISyntaxException, InterruptedException {
        String errorMessage = authenticateWithMobileIdPollError("07110066", "60001019947", 500);
        assertThat(errorMessage, startsWith("Teie mobiiltelefoni ei saa Mobiil-ID autentimise sõnumeid saata."));
    }

    @Test
    public void mob2_mobileIdAuthenticationTechnicalError() throws URISyntaxException, InterruptedException {
        String errorMessage = authenticateWithMobileIdPollError("00000666", "60001019961", 3000);
        assertThat(errorMessage, startsWith("Autentimine Mobiil-ID-ga ei õnnestunud. Testi oma Mobiil-ID toimimist haldusvahendis: http://www.id.ee/index.php?id=35636"));
    }

    @Test
    public void mob2_mobileIdAuthenticationSimApplicationError() throws URISyntaxException, InterruptedException {
        String errorMessage = authenticateWithMobileIdPollError("01200266", "60001019972", 1000);
        assertThat(errorMessage, startsWith("Teie mobiiltelefoni SIM kaardiga tekkis tõrge."));
    }

    @Test
    public void mob2_mobileIdAuthenticationPhoneNotInNetwork() throws URISyntaxException, InterruptedException {
        String errorMessage = authenticateWithMobileIdPollError("13100266", "60001019983", 1000);
        assertThat(errorMessage, startsWith("Teie mobiiltelefon on levialast väljas."));
    }

    @Test
    public void mob3_mobileIdAuthenticationUserCancels() throws URISyntaxException, InterruptedException {
        String errorMessage = authenticateWithMobileIdPollError("01100266", "60001019950", 1000);
        assertThat(errorMessage, startsWith("Autentimine on katkestatud."));
    }

    /**
     * Verifying that user receives proper error message when user inserts invalid id code
     */
    @Test
    public void mob3_mobileIdAuthenticationInvalidIdCode() {
        String errorMessage = authenticateWithMobileIdInvalidInputError("00000766","66", 1000);
        assertEquals("Kasutajal pole Mobiil-ID lepingut.Intsidendi number:", errorMessage);
    }

    /**
     * Verifying that user receives proper error message when user inserts invalid phone number
     */
    @Test
    public void mob3_mobileIdAuthenticationInvalidPhoneNumber() {
        String errorMessage = authenticateWithMobileIdInvalidInputError("123456789123","60001019906", 1000);
        assertEquals("Kasutajal pole Mobiil-ID lepingut.Intsidendi number:", errorMessage);
    }

    /**
     * Verifying that user receives proper error message when user doesn't insert phone number
     */
    @Test
    public void mob3_mobileIdAuthenticationNoMobileNo() {
        String errorMessage = authenticateWithMobileIdInvalidInputError("","60001019906", 1000);
        assertEquals("Telefoninumber ei ole korrektne.Intsidendi number:", errorMessage);
    }

    /**
     * Verifying that user receives proper error message when user doesn't insert id code
     */
    @Test
    public void mob3_mobileIdAuthenticationNoIdCode() {
        String errorMessage = authenticateWithMobileIdInvalidInputError("00000766","", 1000);
        assertEquals("Isikukood ei ole korrektne.Intsidendi number:", errorMessage);
    }

    /**
     * Verifying that user receives proper error message when user doesn't insert any parameters
     */
    @Test
    public void mob3_mobileIdAuthenticationNoParameters() {
        String errorMessage = authenticateWithMobileIdInvalidInputError("","", 1000);
        assertEquals("Isikukood ei ole korrektne.Intsidendi number:", errorMessage);
    }
}
