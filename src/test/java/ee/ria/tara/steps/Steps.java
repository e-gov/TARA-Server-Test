package ee.ria.tara.steps;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.SignedJWT;
import ee.ria.tara.model.OpenIdConnectFlow;
import ee.ria.tara.utils.OpenIdConnectUtils;
import io.qameta.allure.Allure;
import io.qameta.allure.Step;
import org.apache.commons.codec.digest.DigestUtils;

import java.text.ParseException;
import java.util.Base64;
import java.util.Date;

public class Steps {
    @Step("{message}")
    public static void log(String message) {
    }

    @Step("Verify token")
    public static SignedJWT verifyTokenAndReturnSignedJwtObject(OpenIdConnectFlow flow, String token) throws ParseException, JOSEException {
        SignedJWT signedJWT = SignedJWT.parse(token);
        //TODO: single attachment with pretty print
        Allure.addAttachment("Header", signedJWT.getHeader().toJSONObject().toString());
        Allure.addAttachment("Payload", signedJWT.getJWTClaimsSet().toJSONObject().toString());
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
}
