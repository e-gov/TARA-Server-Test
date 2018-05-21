package ee.ria.tara.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Validated
@ConfigurationProperties(prefix = "test.tara")
public class TestTaraProperties {

    private String targetUrl;
    private String targetSpUrl;
    private String spProviderName;
    private String keystore;
    private String keystorePass;
    private String responseSigningKeyId;
    private String responseSigningKeyPass;
    private String eidasNodeUrl;
    private String eidasNodeMetadataUrl;
    private String eidasNodeResponseUrl;
    private String jwksUrl;
    private String testRedirectUri;
    private String clientId;
    private String clientSecret;
    private String authorizeUrl;
    private String tokenUrl;
    private String loginUrl;
    private String serviceUrl;
    private String configurationUrl;
    private String casClientId;

    public String getEidasNodeResponseUrl() {
        return eidasNodeResponseUrl;
    }

    public void setEidasNodeResponseUrl(String eidasNodeResponseUrl) {
        this.eidasNodeResponseUrl = eidasNodeResponseUrl;
    }

    public String getEidasNodeUrl() {
        return eidasNodeUrl;
    }

    public void setEidasNodeUrl(String eidasNodeUrl) {
        this.eidasNodeUrl = eidasNodeUrl;
    }

    public String getEidasNodeMetadataUrl() {
        return eidasNodeMetadataUrl;
    }

    public void setEidasNodeMetadataUrl(String eidasNodeMetadataUrl) {
        this.eidasNodeMetadataUrl = eidasNodeMetadataUrl;
    }

    public String getConfigurationUrl() {
        return configurationUrl;
    }

    public void setConfigurationUrl(String configurationUrl) {
        this.configurationUrl = configurationUrl;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public String getCasClientId() {
        return casClientId;
    }

    public void setCasClientId(String casClientId) {
        this.casClientId = casClientId;
    }

    public String getServiceUrl() {
        return serviceUrl;
    }

    public void setServiceUrl(String serviceUrl) {
        this.serviceUrl = serviceUrl;
    }

    public String getTokenUrl() {
        return tokenUrl;
    }

    public void setTokenUrl(String tokenUrl) {
        this.tokenUrl = tokenUrl;
    }

    public String getLoginUrl() {
        return loginUrl;
    }

    public void setLoginUrl(String loginUrl) {
        this.loginUrl = loginUrl;
    }

    public String getAuthorizeUrl() {
        return authorizeUrl;
    }

    public void setAuthorizeUrl(String authorizeUrl) {
        this.authorizeUrl = authorizeUrl;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getTestRedirectUri() {
        return testRedirectUri;
    }

    public void setTestRedirectUri(String testRedirectUri) {
        this.testRedirectUri = testRedirectUri;
    }

    public String getJwksUrl() {
        return jwksUrl;
    }

    public void setJwksUrl(String jwksUrl) {
        this.jwksUrl = jwksUrl;
    }

    public String getFullJwksUrl() {
        return targetUrl+jwksUrl;
    }

    public void setTargetUrl(String targetUrl) {
        this.targetUrl = targetUrl;
    }

    public void setTargetSpUrl(String targetSpUrl) {
        this.targetSpUrl = targetSpUrl;
    }

    public void setSpProviderName(String spProviderName) {
        this.spProviderName = spProviderName;
    }

    public void setKeystore(String keystore) {
        this.keystore = keystore;
    }

    public void setKeystorePass(String keystorePass) {
        this.keystorePass = keystorePass;
    }

    public void setResponseSigningKeyId(String responseSigningKeyId) {
        this.responseSigningKeyId = responseSigningKeyId;
    }

    public void setResponseSigningKeyPass(String responseSigningKeyPass) {
        this.responseSigningKeyPass = responseSigningKeyPass;
    }

    public String getTargetUrl() {
        return targetUrl;
    }

    public String getTargetSpUrl() {
        return targetSpUrl;
    }

    public String getSpProviderName() {
        return spProviderName;
    }

    public String getKeystore() {
        return keystore;
    }

    public String getKeystorePass() {
        return keystorePass;
    }

    public String getResponseSigningKeyId() {
        return responseSigningKeyId;
    }

    public String getResponseSigningKeyPass() {
        return responseSigningKeyPass;
    }

    public String getFullEidasNodeMetadataUrl() {
        return eidasNodeUrl + eidasNodeMetadataUrl;
    }
}
