package ee.ria.tara.steps;

import ee.ria.tara.model.OpenIdConnectFlow;
import ee.ria.tara.utils.AllureRestAssuredFormParam;
import io.qameta.allure.Step;
import io.restassured.response.Response;
import org.joda.time.DateTime;

import java.io.IOException;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static ee.ria.tara.config.TaraTestStrings.OIDC_DEF_SCOPE;
import static io.restassured.RestAssured.given;

public class SmartId {
    @Step("{flow.endUser}Authenticates with Smart-ID")
    public static Response authenticateWithSmartId(OpenIdConnectFlow flow, String idCode, Integer pollMillis, String scope) throws InterruptedException, URISyntaxException, IOException {
        Map<String, String> formParams = new HashMap<String, String>();
        formParams.put("scope", scope);
        formParams.put("response_type", "code");
        formParams.put("client_id", flow.getRelyingParty().getClientId());
        formParams.put("redirect_uri", flow.getRelyingParty().getRedirectUri());
        formParams.put("ui_locales", "et");
        Response authenticationResponse = Requests.openIdConnectAuthenticationRequest(flow, formParams); //getBody().htmlPath().getString("**.findAll { it.@name == 'execution' }[0].@value")
        String location = authenticationResponse.then().extract().response()
                .getHeader("location");
        Response taraLoginPageResponse = Requests.followRedirect(flow, location);
        String execution = taraLoginPageResponse.getBody().htmlPath().getString("**.findAll { it.@name == 'execution' }[0].@value");
        Response submitResponse = submitSmartIdLogin(flow, idCode, execution, location);
        String execution2 = submitResponse.getBody().htmlPath().getString("**.findAll { it.@name == 'execution' }[0].@value");
        Response pollResponse = pollForAuthentication(flow, execution2, pollMillis);
        return Requests.followLoginRedirects(flow, pollResponse.getHeader("location"));
    }

    @Step("{flow.endUser}Submit Smart-ID login")
    public static Response submitSmartIdLogin(OpenIdConnectFlow flow, String idCode, String execution, String location) {
        return given()
                .filter(flow.getCookieFilter())
                .filter(new AllureRestAssuredFormParam())
                .relaxedHTTPSValidation()
                .formParam("execution", execution)
                .formParam("_eventId", "smartIdSubmit")
                .formParam("idlang", "")
                .formParam("geolocation", "")
                .formParam("principalCode", idCode)
                .when()
                .post(location)
                .then()
                .extract().response();
    }

    @Step("Poll Smart-ID authentication")
    //TODO: same as Mobile-Id polling
    public static Response pollForAuthentication(OpenIdConnectFlow flow, String execution, Integer intervalMillis) throws InterruptedException {
        DateTime endTime = new DateTime().plusMillis(intervalMillis * 3 + 200);
        while (new DateTime().isBefore(endTime)) {
            Thread.sleep(intervalMillis);
            Response response = given()
                    .filter(flow.getCookieFilter())
                    .filter(new AllureRestAssuredFormParam())
                    .relaxedHTTPSValidation()
                    .redirects().follow(false)
                    .formParam("execution", execution)
                    .formParam("_eventId", "check")
                    .queryParam("client_id", flow.getRelyingParty().getClientId())
                    .queryParam("redirect_uri", flow.getRelyingParty().getRedirectUri())
                    .when()
                    .post(flow.getOpenIDProvider().getLoginUrl())
                    .then()
                    .extract().response();
            if (response.statusCode() == 302) {
                return response;
            }
        }
        throw new RuntimeException("No Smart-ID response in: " + (intervalMillis * 3 + 200) + " millis");
    }

    @Step("{flow.endUser}Authenticates with Smart-ID and poll for errors")
    public static Response authenticatePollError(OpenIdConnectFlow flow, String idCode, Integer pollMillis) throws InterruptedException {
        Map<String, String> formParams = new HashMap<String, String>();
        formParams.put("scope", OIDC_DEF_SCOPE);
        formParams.put("response_type", "code");
        formParams.put("client_id", flow.getRelyingParty().getClientId());
        formParams.put("redirect_uri", flow.getRelyingParty().getRedirectUri());
        formParams.put("ui_locales", "et");
        Response authenticationResponse = Requests.openIdConnectAuthenticationRequest(flow, formParams); //getBody().htmlPath().getString("**.findAll { it.@name == 'execution' }[0].@value")
        String location = authenticationResponse.then().extract().response()
                .getHeader("location");
        Response taraLoginPageResponse = Requests.followRedirect(flow, location);
        String execution = taraLoginPageResponse.getBody().htmlPath().getString("**.findAll { it.@name == 'execution' }[0].@value");
        Response submitResponse = submitSmartIdLogin(flow, idCode, execution, location);
        String execution2 = submitResponse.getBody().htmlPath().getString("**.findAll { it.@name == 'execution' }[0].@value");
        Response pollResponse = pollForAuthenticationError(flow, execution2, pollMillis);
        return pollResponse;
    }

    @Step("Poll Smart-ID authentication error")
    public static Response pollForAuthenticationError(OpenIdConnectFlow flow, String execution, Integer intervalMillis) throws InterruptedException {
        DateTime endTime = new DateTime().plusMillis(intervalMillis * 3 + 200);
        while (new DateTime().isBefore(endTime)) {
            Thread.sleep(intervalMillis);
            Response response = given()
                    .filter(flow.getCookieFilter())
                    .filter(new AllureRestAssuredFormParam())
                    .relaxedHTTPSValidation()
                    .redirects().follow(false)
                    .formParam("execution", execution)
                    .formParam("_eventId", "check")
                    .queryParam("client_id", flow.getRelyingParty().getClientId())
                    .queryParam("redirect_uri", flow.getRelyingParty().getRedirectUri())
                    .when()
                    .post(flow.getOpenIDProvider().getLoginUrl())
                    .then()
                    .extract().response();
            if ((response.statusCode() != 302) & (response.statusCode() != 200)) {
                return response;
            }
        }
        throw new RuntimeException("No MID response in: " + (intervalMillis * 3 + 200) + " millis");
    }

    @Step("Authenticates with Smart-ID and receives error instantly")
    public static Response authenticateWithSmartIdError(OpenIdConnectFlow flow, String idCode, String scope) {
        Map<String, String> formParams = new HashMap<String, String>();
        formParams.put("scope", scope);
        formParams.put("response_type", "code");
        formParams.put("client_id", flow.getRelyingParty().getClientId());
        formParams.put("redirect_uri", flow.getRelyingParty().getRedirectUri());
        formParams.put("ui_locales", "et");
        Response authenticationResponse = Requests.openIdConnectAuthenticationRequest(flow, formParams); //getBody().htmlPath().getString("**.findAll { it.@name == 'execution' }[0].@value")
        String location = authenticationResponse.then().extract().response()
                .getHeader("location");
        Response taraLoginPageResponse = Requests.followRedirect(flow, location);
        String execution = taraLoginPageResponse.getBody().htmlPath().getString("**.findAll { it.@name == 'execution' }[0].@value");
        return submitSmartIdLogin(flow, idCode, execution, location);
    }

    public static String extractError(Response response) {
        return (String) Steps.extractError(response).get(1);
    }
}
