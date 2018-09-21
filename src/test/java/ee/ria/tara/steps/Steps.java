package ee.ria.tara.steps;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.SignedJWT;
import ee.ria.tara.model.OpenIdConnectFlow;
import ee.ria.tara.utils.OpenIdConnectUtils;
import io.qameta.allure.Allure;
import io.qameta.allure.Step;

import java.io.IOException;
import java.text.ParseException;
import java.util.Date;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;


public class Steps {
    @Step("{message}")
    public static void log(String message) {
    }

    @Step("Verify token")
    public static SignedJWT verifyTokenAndReturnSignedJwtObject(OpenIdConnectFlow flow, String token) throws ParseException, JOSEException, IOException {
        SignedJWT signedJWT = SignedJWT.parse(token);
        //TODO: single attachment
        addJsonAttachment("Header", signedJWT.getHeader().toJSONObject().toString());
        addJsonAttachment("Payload", signedJWT.getJWTClaimsSet().toJSONObject().toString());
        try {
            Allure.addLinks(new io.qameta.allure.model.Link()
                    .withName("View Token in jwt.io")
                    .withUrl("https://jwt.io/#debugger-io?token=" + token));
        } catch (Exception e) {
            //NullPointerException when running test from IntelliJ
        }

        assertThat("Token Signature is not valid!", OpenIdConnectUtils.isTokenSignatureValid(flow, signedJWT), is(true));
        assertThat(signedJWT.getJWTClaimsSet().getAudience().get(0), equalTo(flow.getRelyingParty().getClientId()));
        assertThat(signedJWT.getJWTClaimsSet().getIssuer(), equalTo(flow.getOpenIDProvider().getIssuer()));
        Date date = new Date();
        assertThat("Expected current: " + date + " to be after nbf: " + signedJWT.getJWTClaimsSet().getNotBeforeTime(), date.after(signedJWT.getJWTClaimsSet().getNotBeforeTime()), is(true));
        assertThat("Expected current: " + date + " to be before exp: " + signedJWT.getJWTClaimsSet().getExpirationTime(), date.before(signedJWT.getJWTClaimsSet().getExpirationTime()), is(true));
        assertThat(signedJWT.getJWTClaimsSet().getStringClaim("state"), equalTo(flow.getState()));
        if (!flow.getNonce().isEmpty()) {
            assertThat(signedJWT.getJWTClaimsSet().getStringClaim("nonce"), equalTo(flow.getNonce()));
        }
        return signedJWT;
    }

    static void addJsonAttachment(String name, String json) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        Object jsonObject = mapper.readValue(json, Object.class);
        String prettyJson = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(jsonObject);
        Allure.addAttachment(name, "application/json", prettyJson, "json");
    }
}
