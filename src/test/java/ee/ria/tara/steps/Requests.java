package ee.ria.tara.steps;

import ee.ria.tara.model.OpenIdConnectFlow;
import ee.ria.tara.utils.AllureRestAssuredCorrectHeaders;
import ee.ria.tara.utils.AllureRestAssuredFormParam;
import ee.ria.tara.utils.OpenIdConnectUtils;
import io.qameta.allure.Step;
import io.restassured.http.ContentType;
import io.restassured.response.Response;

import java.io.IOException;
import java.net.URISyntaxException;
import java.util.Map;

import static io.restassured.RestAssured.given;

public class Requests {
    @Step("Get token")
    //Relying Party retreives ID token
    public static Response postToTokenEndpointUsingQueryParameters(OpenIdConnectFlow flow, String authorizationCode) {
        return given()
                .filter(new AllureRestAssuredCorrectHeaders())
                .relaxedHTTPSValidation()
                .queryParam("grant_type", "authorization_code")
                .queryParam("code", authorizationCode)
                .queryParam("redirect_uri", flow.getRelyingParty().getRedirectUri())
                .when()
                .header("Authorization", OpenIdConnectUtils.getAuthorization(flow.getRelyingParty().getClientId(), flow.getRelyingParty().getSecret()))
                .urlEncodingEnabled(true)
                .post(flow.getOpenIDProvider().getTokenUrl())
                .then()
                .extract().response();
    }

    @Step("Get token")
    //Relying Party retreives ID token
    public static Response postToTokenEndpoint(OpenIdConnectFlow flow, String authorizationCode) {
        //TODO: fix generated curl command
        return given()
                .filter(new AllureRestAssuredFormParam())
                .relaxedHTTPSValidation()
                .formParam("grant_type", "authorization_code")
                .formParam("code", authorizationCode)
                .formParam("redirect_uri", flow.getRelyingParty().getRedirectUri())
                .when()
                .header("Authorization", OpenIdConnectUtils.getAuthorization(flow.getRelyingParty().getClientId(), flow.getRelyingParty().getSecret()))
                .urlEncodingEnabled(true)
                .post(flow.getOpenIDProvider().getTokenUrl())
                .then()
                .extract().response();
    }

    @Step("Get token")
    //Relying Party retreives ID token
    public static Response postToTokenEndpoint(OpenIdConnectFlow flow, Map<String, ?> parameters) {
        //TODO: fix generated curl command
        return given()
                .filter(new AllureRestAssuredFormParam())
                .relaxedHTTPSValidation()
                .formParams(parameters)
                .when()
                .header("Authorization", OpenIdConnectUtils.getAuthorization(flow.getRelyingParty().getClientId(), flow.getRelyingParty().getSecret()))
                .urlEncodingEnabled(true)
                .post(flow.getOpenIDProvider().getTokenUrl())
                .then()
                .extract().response();
    }

    @Step("{flow.endUser}OpenID Connect authentication request")
    public static Response openIdConnectAuthenticationRequest(OpenIdConnectFlow flow, Map<String, ?> values) {
        return given()
                .filter(flow.getCookieFilter())
                .filter(new AllureRestAssuredCorrectHeaders())
                .relaxedHTTPSValidation()
                .queryParams(values)
                .queryParam("state", flow.getState())
                .queryParam("nonce", flow.getNonce())
                .accept(ContentType.HTML)
                .when()
                .redirects().follow(false)
                .get(flow.getOpenIDProvider().getAuthorizeUrl())
                .then().extract().response();
    }

    @Step("{flow.endUser}OpenID Connect authentication request")
    public static Response openIdConnectAuthenticationRequestWithoutStateAndNonce(OpenIdConnectFlow flow, Map<String, ?> values) {
        return given()
                .filter(flow.getCookieFilter())
                .filter(new AllureRestAssuredCorrectHeaders())
                .relaxedHTTPSValidation()
                .queryParams(values)
                .when()
                .redirects().follow(false)
                .get(flow.getOpenIDProvider().getAuthorizeUrl())
                .then().extract().response();
    }

    @Step("{flow.endUser}Follow OpenID Connect Autentication request redirect")
    public static Response followRedirect(OpenIdConnectFlow flow, String location) {
        return given()
                .filter(flow.getCookieFilter())
                .filter(new AllureRestAssuredCorrectHeaders())
                .relaxedHTTPSValidation()
                .when()
                .redirects().follow(false)
                .urlEncodingEnabled(false)
                .get(location)
                .then()
                .extract().response();
    }

    @Step("{flow.endUser}Follow redirects after authorization")
    public static Response followLoginRedirects(OpenIdConnectFlow flow, String url) {
        Response oauth2Response = oauth2AuthorizeRedirect(flow, url);
        return oidcAuthorizeRedirect(flow, oauth2Response.getHeader("location"));
    }

    @Step("{flow.endUser}Follow redirect - /oauth2.0/callbackAuthorize")
    public static Response oauth2AuthorizeRedirect(OpenIdConnectFlow flow, String location) {
        return given()
                .filter(flow.getCookieFilter())
                .filter(new AllureRestAssuredCorrectHeaders())
                .relaxedHTTPSValidation()
                .redirects().follow(false)
                .when()
                .urlEncodingEnabled(false)
                .get(location).then()
                .extract().response();
    }

    @Step("{flow.endUser}Follow redirect - /oidc/authorize")
    public static Response oidcAuthorizeRedirect(OpenIdConnectFlow flow, String location) {
        return given()
                .filter(flow.getCookieFilter())
                .filter(new AllureRestAssuredCorrectHeaders())
                .relaxedHTTPSValidation()
                .redirects().follow(false)
                .when()
                .urlEncodingEnabled(false)
                .get(location)
                .then()
                .extract().response();
    }

    @Step("{flow.endUser}Open TARA Login Page with scope {scope}")
    public static Response getAuthenticationMethodsPageWithScope(OpenIdConnectFlow flow, String scope) throws InterruptedException, URISyntaxException, IOException {
        Map queryParams = OpenIdConnectUtils.getAuthorizationRequestData(flow);
        queryParams.put("scope", scope);
        Response authenticationResponse = Requests.openIdConnectAuthenticationRequest(flow, queryParams); //getBody().htmlPath().getString("**.findAll { it.@name == 'execution' }[0].@value")
        String location = authenticationResponse.then().extract().response()
                .getHeader("location");
        return Requests.followRedirect(flow, location);
    }

    @Step("{flow.endUser}Open TARA Login Page with acr_values {acr}")
    public static Response getAuthenticationMethodsPageWithAcr(OpenIdConnectFlow flow, Object acr) throws InterruptedException, URISyntaxException, IOException {
        Map queryParams = OpenIdConnectUtils.getAuthorizationRequestData(flow);
        queryParams.put("acr_values", acr);
        Response authenticationResponse = Requests.openIdConnectAuthenticationRequest(flow, queryParams); //getBody().htmlPath().getString("**.findAll { it.@name == 'execution' }[0].@value")
        String location = authenticationResponse.then().extract().response()
                .getHeader("location");
        return Requests.followRedirect(flow, location);
    }

    @Step("{flow.endUser}Open TARA Login Page with scope {scope} and acr_values {acr}")
    public static Response getAuthenticationMethodsPageWithScopeAndAcr(OpenIdConnectFlow flow, String scope, Object acr) throws InterruptedException, URISyntaxException, IOException {
        Map queryParams = OpenIdConnectUtils.getAuthorizationRequestData(flow);
        queryParams.put("scope", scope);
        if (acr != null) {
            queryParams.put("acr_values", acr);
        }
        Response authenticationResponse = Requests.openIdConnectAuthenticationRequest(flow, queryParams); //getBody().htmlPath().getString("**.findAll { it.@name == 'execution' }[0].@value")
        String location = authenticationResponse.then().extract().response()
                .getHeader("location");
        return Requests.followRedirect(flow, location);
    }

    @Step("{flow.endUser}Open TARA Login Page with query parameters")
    public static Response getAuthenticationMethodsPageWithParameters(OpenIdConnectFlow flow, Map<String, ?> queryParams) throws InterruptedException, URISyntaxException, IOException {
        Response authenticationResponse = Requests.openIdConnectAuthenticationRequest(flow, queryParams); //getBody().htmlPath().getString("**.findAll { it.@name == 'execution' }[0].@value")
        String location = authenticationResponse.then().extract().response()
                .getHeader("location");
        return Requests.followRedirect(flow, location);
    }

    @Step("{flow.endUser}Open TARA Login Page with missing state or nonce")
    public static Response getAuthenticationMethodsPageWithoutStateOrNonce(OpenIdConnectFlow flow, Map<String, ?> queryParams) throws InterruptedException, URISyntaxException, IOException {
        Response authenticationResponse = Requests.openIdConnectAuthenticationRequestWithoutStateAndNonce(flow, queryParams); //getBody().htmlPath().getString("**.findAll { it.@name == 'execution' }[0].@value")
        String location = authenticationResponse.then().extract().response()
                .getHeader("location");
        return Requests.followRedirect(flow, location);
    }

    public static String getIdToken(OpenIdConnectFlow flow, String authorizationCode) {
        Response response = Requests.postToTokenEndpoint(flow, authorizationCode);
        return response.getBody().jsonPath().getString("id_token");
    }
}
