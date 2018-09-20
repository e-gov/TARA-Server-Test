package ee.ria.tara.model;

import com.nimbusds.jose.jwk.JWKSet;
import ee.ria.tara.config.TestTaraProperties;
import ee.ria.tara.utils.AdvancedCookieFilter;
import lombok.Data;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang.RandomStringUtils;
import org.apache.http.impl.cookie.BasicClientCookie;
import org.opensaml.security.credential.Credential;
import org.springframework.core.io.ResourceLoader;

import java.io.IOException;
import java.text.ParseException;
import java.util.Base64;

public @Data
class OpenIdConnectFlow {

    private String state = Base64.getEncoder().encodeToString(DigestUtils.sha256(RandomStringUtils.random(16)));
    private String nonce = Base64.getEncoder().encodeToString(DigestUtils.sha256(RandomStringUtils.random(16)));
    private AdvancedCookieFilter cookieFilter = new AdvancedCookieFilter();
    private JWKSet jwkSet;
    private String tokenIssuer;
    private ResourceLoader resourceLoader;
    private Credential signatureCredential;
    private Credential encryptionCredential;

    //Name for user performing action, used only for display purposes in test reports. Example values: End-User or Attacker
    private String endUser = "";
    private TestTaraProperties testProperties;
    private OpenIDProvider openIDProvider = new OpenIDProvider();
    private RelyingParty relyingParty = new RelyingParty();

    public void setup(TestTaraProperties properties) throws IOException, ParseException {
        testProperties = properties;
        relyingParty.setClientId(properties.getClientId());
        relyingParty.setSecret(properties.getClientSecret());
        relyingParty.setRedirectUri(properties.getTestRedirectUri());
        openIDProvider.setJwksUrl(properties.getTargetUrl() + properties.getJwksUrl());
        openIDProvider.setAuthorizeUrl(properties.getTargetUrl() + properties.getAuthorizeUrl());
        openIDProvider.setTokenUrl(properties.getTargetUrl() + properties.getTokenUrl());
        openIDProvider.setLoginUrl(properties.getTargetUrl() + properties.getLoginUrl());
    }

    public void updateSessionId(String sessionId) {
        BasicClientCookie cookie = new BasicClientCookie("JSESSIONID", sessionId);
        cookie.setPath("/");
        cookie.setDomain(testProperties.getDomainName());
        cookieFilter.cookieStore.addCookie(cookie);
    }
}
