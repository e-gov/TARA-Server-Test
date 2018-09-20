package ee.ria.tara;


import com.nimbusds.jwt.SignedJWT;
import ee.ria.tara.config.IntegrationTest;
import ee.ria.tara.utils.Feature;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.ResourceLoader;

import static ee.ria.tara.config.TaraTestStrings.OIDC_DEF_SCOPE;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.Assert.assertEquals;

@SpringBootTest(classes = SmartIdTest.class)
@Category(IntegrationTest.class)
public class SmartIdTest extends TestsBase {
    @Autowired
    private ResourceLoader resourceLoader;

    @Test
    @Feature("TSID-12, TSID-13")
    public void smartidSuccess() throws Exception {
        String authorizationCode = authenticateWithSmartId("10101010005", 2000, OIDC_DEF_SCOPE);
        SignedJWT signedJWT = verifyTokenAndReturnSignedJwtObject(getIdToken(authorizationCode));

        assertEquals("EE10101010005", signedJWT.getJWTClaimsSet().getSubject());
        assertEquals("DEMO", signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("given_name"));
        assertEquals("SMART-ID", signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("family_name"));
        assertEquals("1801-01-01", signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("date_of_birth"));
    }

    @Test
    @Feature("TSID-11")
    public void smartid_UserRefuses() throws Exception {
        String errorMessage = authenticateWithSmartIdPollError("10101010016", 2000);
        assertThat(errorMessage, startsWith("Autentimine katkestati kasutaja poolt."));
    }

    /**
     * Verifying that proper error message is displayed when user inserts invalid id code
     *
     * @throws Exception
     */
    @Test
    public void smartIdInvalidFormat() throws Exception {
        String errorMessage = authenticateWithSmartIdInvalidInputPollError("12akl2", 2000);
        assertEquals("Isikukood on ebakorrektses formaadis.Intsidendi number:", errorMessage);
    }

    /**
     * Verifying that proper error message is displayed when user inserts empty id code
     *
     * @throws Exception
     */
    @Test
    public void smartIdEmptyCode() throws Exception {
        String errorMessage = authenticateWithSmartIdInvalidInputPollError("", 2000);
        assertEquals("Isikukood puuduIntsidendi number:", errorMessage);
    }
}
