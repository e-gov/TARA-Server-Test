package ee.ria.tara.utils;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jwt.SignedJWT;
import ee.ria.tara.model.OpenIdConnectFlow;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URLEncodedUtils;
import org.springframework.core.io.ResourceLoader;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static ee.ria.tara.config.TaraTestStrings.OIDC_DEF_SCOPE;

public class OpenIdConnectUtils {
    public static String getResourceFileAsString(ResourceLoader resourceLoader, String fileName) throws IOException {
        InputStream is = resourceLoader.getResource(fileName).getInputStream();
        if (is != null) {
            BufferedReader reader = new BufferedReader(new InputStreamReader(is));
            return reader.lines().collect(Collectors.joining());
        }
        return null;
    }
    //TODO: same as rest-assured given().basic(id,secret)?
    public static String getAuthorization(String id, String secret) {
        return String.format("Basic %s", Base64.getEncoder().encodeToString(String.format("%s:%s", id, secret).getBytes(StandardCharsets.UTF_8)));
    }

    public static String getCode(OpenIdConnectFlow flow, String url) throws URISyntaxException {
        //TODO: should not need flow and validate state here
        List<NameValuePair> params = URLEncodedUtils.parse(new URI(url), StandardCharsets.UTF_8);

        Map<String, String> queryParams = params.stream().collect(
                Collectors.toMap(NameValuePair::getName, NameValuePair::getValue));
        if (queryParams.get("state").equals(flow.getState())) {
            return queryParams.get("code");
        } else {
            throw new RuntimeException("State value does not match!");
        }
    }

    public static Boolean isTokenSignatureValid(OpenIdConnectFlow flow, SignedJWT signedJWT) throws JOSEException {
        List<JWK> matches = new JWKSelector(new JWKMatcher.Builder()
                .keyType(KeyType.RSA)
                .build())
                .select(flow.getOpenIDProvider().getJwkSet());

        RSAKey rsaKey = (RSAKey) matches.get(0);

        JWSVerifier verifier = new RSASSAVerifier(rsaKey);
        return signedJWT.verify(verifier);
    }

    public static Map getAuthorizationRequestData(OpenIdConnectFlow flow) {
        Map<String, Object> queryParams = new HashMap<>();
        queryParams.put("scope", OIDC_DEF_SCOPE);
        queryParams.put("response_type", "code");
        queryParams.put("client_id", flow.getRelyingParty().getClientId());
        queryParams.put("redirect_uri", flow.getRelyingParty().getRedirectUri());
        queryParams.put("ui_locales", "et");
        return queryParams;
    }
}
