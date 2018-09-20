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
        Allure.addLinks(new io.qameta.allure.model.Link()
                .withName("View Token in jwt.io")
                .withUrl("https://jwt.io/#debugger-io?token=" + token));
        if (OpenIdConnectUtils.isTokenSignatureValid(flow, signedJWT)) {
            if (signedJWT.getJWTClaimsSet().getAudience().get(0).equals(flow.getRelyingParty().getClientId())) {
                if (signedJWT.getJWTClaimsSet().getIssuer().equals(flow.getOpenIDProvider().getIssuer())) {
                    Date date = new Date();
                    if (date.after(signedJWT.getJWTClaimsSet().getNotBeforeTime()) && date.before(signedJWT.getJWTClaimsSet().getExpirationTime())) {
                        if (signedJWT.getJWTClaimsSet().getClaim("nonce").equals(flow.getNonce())) {
                            return signedJWT;
                        } else {
                            throw new RuntimeException("Calculated nonce do not match the received one!");
                        }
                    } else {
                        throw new RuntimeException("Token validity period is not valid! current: " + date + " nbf: " + signedJWT.getJWTClaimsSet().getNotBeforeTime() + " exp: " + signedJWT.getJWTClaimsSet().getExpirationTime());
                    }
                } else {
                    throw new RuntimeException("Token Issuer is not valid! Expected: " + flow.getOpenIDProvider().getIssuer() + " actual: " + signedJWT.getJWTClaimsSet().getIssuer());
                }
            } else {
                throw new RuntimeException("Token Audience is not valid! Expected: " + flow.getRelyingParty().getClientId() + " actual: " + signedJWT.getJWTClaimsSet().getAudience().get(0));
            }
        } else {
            throw new RuntimeException("Token Signature is not valid!");
        }
    }
    static void addJsonAttachment(String name, String json) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        Object jsonObject = mapper.readValue(json, Object.class);
        String prettyJson = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(jsonObject);
        Allure.addAttachment(name, "application/json",prettyJson,"json");
    }
}
