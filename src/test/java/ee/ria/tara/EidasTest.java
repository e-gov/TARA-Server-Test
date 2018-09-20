package ee.ria.tara;


import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.SignedJWT;
import ee.ria.tara.config.IntegrationTest;
import ee.ria.tara.config.TestTaraProperties;
import ee.ria.tara.model.OpenIdConnectFlow;
import ee.ria.tara.steps.Eidas;
import ee.ria.tara.steps.Requests;
import ee.ria.tara.steps.Steps;
import ee.ria.tara.utils.EidasResponseDataUtils;
import ee.ria.tara.utils.OpenIdConnectUtils;
import io.restassured.response.Response;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;

import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.KeyStore;
import java.security.Security;
import java.text.ParseException;

import static ee.ria.tara.config.TaraTestStrings.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.StringStartsWith.startsWith;
import static org.junit.Assert.assertEquals;

@SpringBootTest(classes = EidasTest.class)
@Category(IntegrationTest.class)
public class EidasTest extends TestsBase {
    @Autowired
    private ResourceLoader resourceLoader;
    private static boolean setupComplete = false;
    private OpenIdConnectFlow flow;

    @Before
    public void setUp() throws IOException, ParseException, InitializationException {
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
        flow.setEncryptionCredential(encryptionCredential);
        flow.setSignatureCredential(signatureCredential);
        flow.setup(properties);
    }

    public void initialize() throws IOException, ParseException, InitializationException {
        jwkSet = JWKSet.load(new URL(testTaraProperties.getFullJwksUrl()));
        tokenIssuer = getIssuer(testTaraProperties.getTargetUrl() + testTaraProperties.getConfigurationUrl());
        Security.addProvider(new BouncyCastleProvider());

        //For eIDAS
        InitializationService.initialize();
        Security.addProvider(new BouncyCastleProvider());
        try {
            KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            Resource resource = resourceLoader.getResource(testTaraProperties.getKeystore());
            keystore.load(resource.getInputStream(), testTaraProperties.getKeystorePass().toCharArray());
            signatureCredential = getCredential(keystore, testTaraProperties.getResponseSigningKeyId(), testTaraProperties.getResponseSigningKeyPass());
            encryptionCredential = getEncryptionCredentialFromMetaData(getMetadataBody());
        } catch (Exception e) {
            throw new RuntimeException("Something went wrong initializing credentials:", e);
        }
    }

    @Test
    public void eidas1_eidasAuthenticationMinAttrSuccess() throws URISyntaxException, ParseException, JOSEException, IOException, InterruptedException {
        SignedJWT signedJWT = Eidas.eIDASAuthenticationWithScopeAndAcr(flow, DEF_COUNTRY, OIDC_DEF_SCOPE, "low");

        assertEquals("EE30011092212", signedJWT.getJWTClaimsSet().getSubject());
        assertEquals(DEFATTR_FIRST, signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("given_name"));
        assertEquals(DEFATTR_FAMILY, signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("family_name"));
        assertEquals(DEFATTR_DATE, signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("date_of_birth"));
        assertEquals(OIDC_AMR_EIDAS, signedJWT.getJWTClaimsSet().getStringArrayClaim("amr")[0]);
    }


    @Test
    public void eidas1_eidasAuthenticationMaxAttrSuccess() throws Exception {
        Response response = Eidas.initiateEidasAuthentication(flow, DEF_COUNTRY, OIDC_DEF_SCOPE, null);
        String relayState = response.htmlPath().getString("**.findAll { it.@name == 'RelayState' }[0].@value");

        //Here we need to simulate a response from foreign country eIDAS Node
        String samlResponse = EidasResponseDataUtils.getBase64SamlResponseDefaultMaximalAttributes(flow, response.getBody().asString());
        String location = Eidas.returnEidasResponse(flow, samlResponse, relayState);
        Response oidcResponse = Requests.followLoginRedirects(flow, location);
        String token = Requests.getIdToken(flow, OpenIdConnectUtils.getCode(flow, oidcResponse.getHeader("location")));
        SignedJWT signedJWT = Steps.verifyTokenAndReturnSignedJwtObject(flow, token);

        assertEquals("EE30011092212", signedJWT.getJWTClaimsSet().getSubject());
        assertEquals(DEFATTR_FIRST, signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("given_name"));
        assertEquals(DEFATTR_FAMILY, signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("family_name"));
        assertEquals(DEFATTR_DATE, signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("date_of_birth"));
        assertEquals(OIDC_AMR_EIDAS, signedJWT.getJWTClaimsSet().getStringArrayClaim("amr")[0]);
    }

    @Test
    //TODO: should use getBase64SamlResponseLegalMaximalAttributes?
    public void eidas1_eidasAuthenticationMaxLegalAttrSuccess() throws Exception {
        Response response = Eidas.initiateEidasAuthentication(flow, DEF_COUNTRY, OIDC_DEF_SCOPE, null);
        String relayState = response.htmlPath().getString("**.findAll { it.@name == 'RelayState' }[0].@value");

        //Here we need to simulate a response from foreign country eIDAS Node
        String samlResponse = EidasResponseDataUtils.getBase64SamlResponseDefaultMaximalAttributes(flow, response.getBody().asString());

        String location = Eidas.returnEidasResponse(flow, samlResponse, relayState);
        Response oidcResponse = Requests.followLoginRedirects(flow, location);
        String token = Requests.getIdToken(flow, OpenIdConnectUtils.getCode(flow, oidcResponse.getHeader("location")));
        SignedJWT signedJWT = Steps.verifyTokenAndReturnSignedJwtObject(flow, token);

        assertEquals("EE30011092212", signedJWT.getJWTClaimsSet().getSubject());
        assertEquals(DEFATTR_FIRST, signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("given_name"));
        assertEquals(DEFATTR_FAMILY, signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("family_name"));
        assertEquals(DEFATTR_DATE, signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("date_of_birth"));
        assertEquals(OIDC_AMR_EIDAS, signedJWT.getJWTClaimsSet().getStringArrayClaim("amr")[0]);
    }

    @Test
    public void eidas2_eidasAuthenticationFailure() throws Exception {
        Response response = Eidas.initiateEidasAuthentication(flow, DEF_COUNTRY, OIDC_DEF_SCOPE, null);
        String relayState = response.htmlPath().getString("**.findAll { it.@name == 'RelayState' }[0].@value");

        //Here we need to simulate a response from foreign country eIDAS Node
        String samlResponse = EidasResponseDataUtils.getBase64SamlResponseWithErrors(flow, response.getBody().asString(), "AuthFailed");
        Response errorResponse = Eidas.returnEidasErrorResponse(flow, samlResponse, relayState);
        String error = errorResponse.htmlPath().getString("**.findAll { it.@class=='error-box' }").substring(4);

        assertThat(error, startsWith("Autentimine eIDAS-ga ebaõnnestus."));
    }

    @Test
    public void eidas2_eidasConsentFailure() throws Exception {
        Response response = Eidas.initiateEidasAuthentication(flow, DEF_COUNTRY, OIDC_DEF_SCOPE, null);
        String relayState = response.htmlPath().getString("**.findAll { it.@name == 'RelayState' }[0].@value");

        //Here we need to simulate a response from foreign country eIDAS Node
        String samlResponse = EidasResponseDataUtils.getBase64SamlResponseWithErrors(flow, response.getBody().asString(), "ConsentNotGiven");
        Response errorResponse = Eidas.returnEidasErrorResponse(flow, samlResponse, relayState);

        String error = errorResponse.htmlPath().getString("**.findAll { it.@class=='error-box' }").substring(4);

        assertThat(error, startsWith("Autentimine eIDAS-ga ebaõnnestus."));
    }

    @Test
    public void eidas2_eidasRandomFailure() throws Exception {
        Response response = Eidas.initiateEidasAuthentication(flow, DEF_COUNTRY, OIDC_DEF_SCOPE, null);
        String relayState = response.htmlPath().getString("**.findAll { it.@name == 'RelayState' }[0].@value");

        //Here we need to simulate a response from foreign country eIDAS Node
        String samlResponse = EidasResponseDataUtils.getBase64SamlResponseWithErrors(flow, response.getBody().asString(), "RandomFailure");
        Response errorResponse = Eidas.returnEidasErrorResponse(flow, samlResponse, relayState);
        String error = errorResponse.htmlPath().getString("**.findAll { it.@class=='error-box' }").substring(4);

        assertThat(error, startsWith("Autentimine eIDAS-ga ebaõnnestus."));
    }

    @Test
    public void eidas3_eidasAcrValueLowShouldReturnSuccess() throws Exception {
        SignedJWT signedJWT = Eidas.eIDASAuthenticationWithScopeAndAcr(flow, DEF_COUNTRY, OIDC_DEF_SCOPE, OIDC_ACR_VALUES_LOW);

        assertEquals("EE30011092212", signedJWT.getJWTClaimsSet().getSubject());
        assertEquals(DEFATTR_FIRST, signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("given_name"));
        assertEquals(DEFATTR_FAMILY, signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("family_name"));
        assertEquals(DEFATTR_DATE, signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("date_of_birth"));
        assertEquals(OIDC_AMR_EIDAS, signedJWT.getJWTClaimsSet().getStringArrayClaim("amr")[0]);
        assertEquals(OIDC_ACR_VALUES_LOW, signedJWT.getJWTClaimsSet().getClaim("acr"));


    }

    @Test
    public void eidas3_eidasAcrValueSubstantialShouldReturnSuccess() throws Exception {
        SignedJWT signedJWT = Eidas.eIDASAuthenticationWithScopeAndAcr(flow, DEF_COUNTRY, OIDC_DEF_SCOPE, OIDC_ACR_VALUES_SUBSTANTIAL);

        assertEquals("EE30011092212", signedJWT.getJWTClaimsSet().getSubject());
        assertEquals(DEFATTR_FIRST, signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("given_name"));
        assertEquals(DEFATTR_FAMILY, signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("family_name"));
        assertEquals(DEFATTR_DATE, signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("date_of_birth"));
        assertEquals(OIDC_AMR_EIDAS, signedJWT.getJWTClaimsSet().getStringArrayClaim("amr")[0]);
        assertEquals(OIDC_ACR_VALUES_SUBSTANTIAL, signedJWT.getJWTClaimsSet().getClaim("acr"));
    }

    @Test
    public void eidas3_eidasAcrValueHighShouldReturnSuccess() throws Exception {
        SignedJWT signedJWT = Eidas.eIDASAuthenticationWithScopeAndAcr(flow, DEF_COUNTRY, OIDC_DEF_SCOPE, OIDC_ACR_VALUES_HIGH);

        assertEquals("EE30011092212", signedJWT.getJWTClaimsSet().getSubject());
        assertEquals(DEFATTR_FIRST, signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("given_name"));
        assertEquals(DEFATTR_FAMILY, signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("family_name"));
        assertEquals(DEFATTR_DATE, signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("date_of_birth"));
        assertEquals(OIDC_AMR_EIDAS, signedJWT.getJWTClaimsSet().getStringArrayClaim("amr")[0]);
        assertEquals(OIDC_ACR_VALUES_HIGH, signedJWT.getJWTClaimsSet().getClaim("acr"));
    }

    @Test
    public void eidas3_eidasAcrValueDefaultShouldReturnSuccess() throws Exception {
        SignedJWT signedJWT = Eidas.eIDASAuthenticationWithScopeAndAcr(flow, DEF_COUNTRY, OIDC_DEF_SCOPE, null);

        assertEquals("EE30011092212", signedJWT.getJWTClaimsSet().getSubject());
        assertEquals(DEFATTR_FIRST, signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("given_name"));
        assertEquals(DEFATTR_FAMILY, signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("family_name"));
        assertEquals(DEFATTR_DATE, signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("date_of_birth"));
        assertEquals(OIDC_AMR_EIDAS, signedJWT.getJWTClaimsSet().getStringArrayClaim("amr")[0]);
        assertEquals("Default loa is substantial", OIDC_ACR_VALUES_SUBSTANTIAL, signedJWT.getJWTClaimsSet().getClaim("acr"));
    }

    @Test
    public void eidas3_eidasAcrValueHigherLoaReturnedThanAskedShouldReturnSuccess() throws Exception {
        /*Map<String, String> formParams = new HashMap<String, String>();
        formParams.put("scope", "openid");
        formParams.put("response_type", "code");
        formParams.put("client_id", testTaraProperties.getClientId());
        formParams.put("redirect_uri", testTaraProperties.getTestRedirectUri());
        formParams.put("lang", "et");
        formParams.put("acr_values", OIDC_ACR_VALUES_LOW);


        String execution = getAuthenticationMethodsPageWithParams(formParams).getBody().htmlPath().getString("**.findAll { it.@name == 'execution' }[0].@value");
        Response response = getEidasSamlRequest(DEF_COUNTRY, execution);
        String relayState = response.htmlPath().getString("**.findAll { it.@name == 'RelayState' }[0].@value");
        //Here we need to simulate a response from foreign country eIDAS Node

        String samlResponse = getBase64SamlResponseMinimalAttributes(response.getBody().asString(), DEFATTR_FIRST, DEFATTR_FAMILY, DEFATTR_PNO, DEFATTR_DATE, LOA_HIGH);

        String authorizationCode = getAuthorizationCode(returnEidasResponse(samlResponse, relayState));
        SignedJWT signedJWT = verifyTokenAndReturnSignedJwtObject(getIdToken(authorizationCode));

        assertEquals("EE30011092212", signedJWT.getJWTClaimsSet().getSubject());
        assertEquals(DEFATTR_FIRST, signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("given_name"));
        assertEquals(DEFATTR_FAMILY, signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("family_name"));
        assertEquals(DEFATTR_DATE, signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("date_of_birth"));
        assertEquals(OIDC_AMR_EIDAS, signedJWT.getJWTClaimsSet().getStringArrayClaim("amr")[0]);
        assertEquals(OIDC_ACR_VALUES_HIGH, signedJWT.getJWTClaimsSet().getClaim("acr"));*/

        Response response = Eidas.initiateEidasAuthentication(flow, DEF_COUNTRY, OIDC_DEF_SCOPE, OIDC_ACR_VALUES_LOW);
        String relayState = response.htmlPath().getString("**.findAll { it.@name == 'RelayState' }[0].@value");

        //Here we need to simulate a response from foreign country eIDAS Node
        String samlResponse = EidasResponseDataUtils.getBase64SamlResponseMinimalAttributes(flow, response.getBody().asString(), DEFATTR_FIRST, DEFATTR_FAMILY, DEFATTR_PNO, DEFATTR_DATE, LOA_HIGH);

        String location = Eidas.returnEidasResponse(flow, samlResponse, relayState);
        Response oidcResponse = Requests.followLoginRedirects(flow, location);
        String token = Requests.getIdToken(flow, OpenIdConnectUtils.getCode(flow, oidcResponse.getHeader("location")));
        SignedJWT signedJWT = Steps.verifyTokenAndReturnSignedJwtObject(flow, token);

        assertEquals("EE30011092212", signedJWT.getJWTClaimsSet().getSubject());
        assertEquals(DEFATTR_FIRST, signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("given_name"));
        assertEquals(DEFATTR_FAMILY, signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("family_name"));
        assertEquals(DEFATTR_DATE, signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("date_of_birth"));
        assertEquals(OIDC_AMR_EIDAS, signedJWT.getJWTClaimsSet().getStringArrayClaim("amr")[0]);
        assertEquals(OIDC_ACR_VALUES_HIGH, signedJWT.getJWTClaimsSet().getClaim("acr"));
    }

    @Test
    public void eidas3_eidasAcrValueLowerLoaReturnedThanAskedShouldReturnError() throws Exception {
        /*Map<String, String> formParams = new HashMap<String, String>();
        formParams.put("scope", "openid");
        formParams.put("response_type", "code");
        formParams.put("client_id", testTaraProperties.getClientId());
        formParams.put("redirect_uri", testTaraProperties.getTestRedirectUri());
        formParams.put("lang", "et");
        formParams.put("acr_values", OIDC_ACR_VALUES_SUBSTANTIAL);

        String execution = getAuthenticationMethodsPageWithParams(formParams).getBody().htmlPath().getString("**.findAll { it.@name == 'execution' }[0].@value");
        Response response = getEidasSamlRequest(DEF_COUNTRY, execution);
        String relayState = response.htmlPath().getString("**.findAll { it.@name == 'RelayState' }[0].@value");

        //Here we need to simulate a response from foreign country eIDAS Node
        String samlResponse = getBase64SamlResponseMinimalAttributes(response.getBody().asString(), DEFATTR_FIRST, DEFATTR_FAMILY, DEFATTR_PNO, DEFATTR_DATE, LOA_LOW);

        Response errorResponse = returnEidasFailureResponse(samlResponse, relayState);

        String error = errorResponse.htmlPath().getString("**.findAll { it.@class=='sub-title' }");

        assertEquals("An unexpected error has occurred", error);*/

        Response response = Eidas.initiateEidasAuthentication(flow, DEF_COUNTRY, OIDC_DEF_SCOPE, OIDC_ACR_VALUES_SUBSTANTIAL);
        String relayState = response.htmlPath().getString("**.findAll { it.@name == 'RelayState' }[0].@value");

        //Here we need to simulate a response from foreign country eIDAS Node
        String samlResponse = EidasResponseDataUtils.getBase64SamlResponseMinimalAttributes(flow, response.getBody().asString(), DEFATTR_FIRST, DEFATTR_FAMILY, DEFATTR_PNO, DEFATTR_DATE, LOA_LOW);

        Response errorResponse = Eidas.returnEidasFailureResponse(flow, samlResponse, relayState);
        String error = errorResponse.htmlPath().getString("**.findAll { it.@class=='sub-title' }");

        assertEquals("An unexpected error has occurred", error);
    }

    @Ignore
    @Test //TODO: eIDAS Node do not forward the relayState!
    public void eidas4_eidasWrongRelayState() throws URISyntaxException, ParseException, JOSEException {
        /*Response response = initiateEidasAuthentication(DEF_COUNTRY, OIDC_DEF_SCOPE, null);
        String relayState = response.htmlPath().getString("**.findAll { it.@name == 'RelayState' }[0].@value");

        String loa = getDecodedSamlRequestBodyXml(response.getBody().asString()).getString("AuthnRequest.RequestedAuthnContext.AuthnContextClassRef");
        //Here we need to simulate a response from foreign country eIDAS Node
        String samlResponse = getBase64SamlResponseMinimalAttributes(response.getBody().asString(), DEFATTR_FIRST, DEFATTR_FAMILY, DEFATTR_PNO, DEFATTR_DATE, loa);

        String authorizationCode = getAuthorizationCode(returnEidasResponse(samlResponse, "a" + relayState));
        SignedJWT signedJWT = verifyTokenAndReturnSignedJwtObject(getIdToken(authorizationCode));

        assertEquals("EE30011092212", signedJWT.getJWTClaimsSet().getSubject());
        assertEquals(DEFATTR_FIRST, signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("given_name"));
        assertEquals(DEFATTR_FAMILY, signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("family_name"));
        assertEquals(DEFATTR_DATE, signedJWT.getJWTClaimsSet().getJSONObjectClaim("profile_attributes").getAsString("date_of_birth"));
        assertEquals(OIDC_AMR_EIDAS, signedJWT.getJWTClaimsSet().getStringArrayClaim("amr")[0]);*/
    }
}
