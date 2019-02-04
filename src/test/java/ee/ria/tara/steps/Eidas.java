package ee.ria.tara.steps;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.SignedJWT;
import ee.ria.tara.model.OpenIdConnectFlow;
import ee.ria.tara.utils.AllureRestAssuredFormParam;
import ee.ria.tara.utils.EidasResponseDataUtils;
import ee.ria.tara.utils.OpenIdConnectUtils;
import io.qameta.allure.Step;
import io.restassured.response.Response;

import java.io.IOException;
import java.net.URISyntaxException;
import java.text.ParseException;

import static ee.ria.tara.config.TaraTestStrings.*;
import static io.restassured.RestAssured.given;

public class Eidas {

    @Step("eIDAS authentication with scope {scope} and acr_values {acr}")
    public static SignedJWT eIDASAuthenticationWithScopeAndAcr(OpenIdConnectFlow flow, String personCountry, String scope, Object acr) throws InterruptedException, IOException, URISyntaxException, ParseException, JOSEException {

        Response response = initiateEidasAuthentication(flow, personCountry, scope, acr);
        String relayState = response.htmlPath().getString("**.findAll { it.@name == 'RelayState' }[0].@value");
        String loa = EidasResponseDataUtils.getDecodedSamlRequestBodyXml(response.getBody().asString()).getString("AuthnRequest.RequestedAuthnContext.AuthnContextClassRef");

        //Here we need to simulate a response from foreign country eIDAS Node
        String samlResponse = EidasResponseDataUtils.getBase64SamlResponseMinimalAttributes(flow, response.getBody().asString(), DEFATTR_FIRST, DEFATTR_FAMILY, DEFATTR_PNO, DEFATTR_DATE, loa);

        String location = Eidas.returnEidasResponse(flow, samlResponse, relayState);
        Response oidcResponse = Requests.followLoginRedirects(flow, location);
        String token = Requests.getIdToken(flow, OpenIdConnectUtils.getCode(flow, oidcResponse.getHeader("location")));
        return Steps.verifyTokenAndReturnSignedJwtObject(flow, token);
    }

    @Step("Initiate eIDAS Authentication")
    public static Response initiateEidasAuthentication(OpenIdConnectFlow flow, String personCountry, String scope, Object acr) throws InterruptedException, IOException, URISyntaxException {
        Response taraLoginPage = Requests.getAuthenticationMethodsPageWithScopeAndAcr(flow, scope, acr);

        String execution = taraLoginPage.getBody().htmlPath().getString("**.findAll { it.@name == 'execution' }[0].@value");
        return getEidasSamlRequest(flow, personCountry, execution);
    }

    @Step("Get eIDAS SAML Request")
    public static Response getEidasSamlRequest(OpenIdConnectFlow flow, String personCountry, String execution) {
        Response response = submitEidasLogin(flow, personCountry, execution);

        String samlRequest = response.htmlPath().getString("**.findAll { it.@name == 'SAMLRequest' }[0].@value");
        String relayState = response.htmlPath().getString("**.findAll { it.@name == 'RelayState' }[0].@value");
        String country = response.htmlPath().getString("**.findAll { it.@name == 'country' }[0].@value");
        String url = response.htmlPath().getString("**.findAll { it.@method == 'post' }[0].@action");

        return given()
                .filter(flow.getCookieFilter())
                .filter(new AllureRestAssuredFormParam()).relaxedHTTPSValidation()
                .formParam("country", country)
                .formParam("RelayState", relayState)
                .formParam("SAMLRequest", samlRequest)
                .when()
                .post(url)
                .then()
                .extract().response();
    }

    @Step("Submit eIDAS login")
    public static Response submitEidasLogin(OpenIdConnectFlow flow, String personCountry, String execution) {
        return given()
                .filter(flow.getCookieFilter())
                .filter(new AllureRestAssuredFormParam()).relaxedHTTPSValidation()
                .formParam("execution", execution)
                .formParam("_eventId", "eidassubmit")
                .formParam("country", personCountry)
                .formParam("eidaslang", "")
                .formParam("geolocation", "") //TODO: What for is this?
                .queryParam("client_id", flow.getRelyingParty().getClientId())
                .queryParam("redirect_uri", flow.getRelyingParty().getRedirectUri())
                .when()
                .post(flow.getOpenIDProvider().getLoginUrl())
                .then()
                .extract().response();
    }

    @Step("Return eIDAS response")
    public static String returnEidasResponse(OpenIdConnectFlow flow, String samlResponse, String relayState) {
        Response response = given().
                filter(flow.getCookieFilter())
                .filter(new AllureRestAssuredFormParam()).relaxedHTTPSValidation()
                .formParam("RelayState", relayState)
                .formParam("SAMLResponse", samlResponse)
                .when()
                .post(flow.getTestProperties().getEidasNodeUrl() + flow.getTestProperties().getEidasNodeResponseUrl())
                .then()
                .extract().response();

        samlResponse = response.htmlPath().getString("**.findAll { it.@name == 'SAMLResponse' }[0].@value");
        relayState = response.htmlPath().getString("**.findAll { it.@name == 'RelayState' }[0].@value");
        String url = response.htmlPath().getString("**.findAll { it.@method == 'post' }[0].@action");

        return given()
                .filter(flow.getCookieFilter())
                .filter(new AllureRestAssuredFormParam()).relaxedHTTPSValidation()
                .formParam("RelayState", relayState)
                .formParam("SAMLResponse", samlResponse)
                .when()
                .post(url)
                .then()
                .extract().header("location");
    }

    @Step("Return eIDAS error response")
    public static Response returnEidasErrorResponse(OpenIdConnectFlow flow, String samlResponse, String relayState) {
        Response response = given()
                .filter(flow.getCookieFilter())
                .filter(new AllureRestAssuredFormParam()).relaxedHTTPSValidation()
                .formParam("RelayState", relayState)
                .formParam("SAMLResponse", samlResponse)
                .when()
                .post(flow.getTestProperties().getEidasNodeUrl() + flow.getTestProperties().getEidasNodeResponseUrl())
                .then()
                .extract().response();

        samlResponse = response.htmlPath().getString("**.findAll { it.@name == 'SAMLResponse' }[0].@value");
        relayState = response.htmlPath().getString("**.findAll { it.@name == 'RelayState' }[0].@value");
        String url = response.htmlPath().getString("**.findAll { it.@method == 'post' }[0].@action");

        return given()
                .filter(flow.getCookieFilter())
                .filter(new AllureRestAssuredFormParam()).relaxedHTTPSValidation()
                .formParam("RelayState", relayState)
                .formParam("SAMLResponse", samlResponse)
                .when()
                .post(url)
                .then()
                .extract().response();
    }

    @Step("Return eIDAS failure response")
    public static Response returnEidasFailureResponse(OpenIdConnectFlow flow, String samlResponse, String relayState) {
        return given()
                .filter(flow.getCookieFilter())
                .filter(new AllureRestAssuredFormParam()).relaxedHTTPSValidation()
                .formParam("RelayState", relayState)
                .formParam("SAMLResponse", samlResponse)
                .when()
                .post(flow.getTestProperties().getEidasNodeUrl() + flow.getTestProperties().getEidasNodeResponseUrl())
                .then()
                .extract().response();
    }

    @Step("Initiate eIDAS Authentication with error")
    public static Response initiateEidasAuthenticationWithError(OpenIdConnectFlow flow, String personCountry, String scope, Object acr) throws InterruptedException, IOException, URISyntaxException {
        Response taraLoginPage = Requests.getAuthenticationMethodsPageWithScopeAndAcr(flow, scope, acr);

        String execution = taraLoginPage.getBody().htmlPath().getString("**.findAll { it.@name == 'execution' }[0].@value");
        return submitEidasLogin(flow, personCountry, execution);
    }

    public static String extractError(Response response) {
        return (String) Steps.extractError(response).get(1);
    }
}
