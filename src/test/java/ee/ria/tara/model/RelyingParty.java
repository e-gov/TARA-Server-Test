package ee.ria.tara.model;

import lombok.Data;

@Data
//Relying Party (RP)/Client from OpenID Connect specification
//OAuth 2.0 Client application requiring End-User Authentication and Claims from an OpenID Provider.
public class RelyingParty {
    private String clientId;
    private String secret;
    private String redirectUri;
}
