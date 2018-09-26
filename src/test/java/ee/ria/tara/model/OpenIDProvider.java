package ee.ria.tara.model;

import com.nimbusds.jose.jwk.JWKSet;
import lombok.Data;

@Data
public class OpenIDProvider {
    private JWKSet jwkSet;
    private String jwksUrl;
    private String authorizeUrl;
    private String tokenUrl;
    private String loginUrl;
    private String backendUrl;

    //https://openid.net/specs/openid-connect-core-1_0.html#IDToken
    //Issuer Identifier for the Issuer of the response.
    //The iss value is a case sensitive URL using the https scheme that contains scheme,
    //host, and optionally, port number and path components and no query or fragment components.
    private String issuer;
}
