package ee.ria.tara.steps;

import ee.ria.tara.model.OpenIdConnectFlow;
import ee.ria.tara.utils.AllureRestAssuredCorrectHeaders;
import ee.ria.tara.utils.AllureRestAssuredFormParam;
import io.qameta.allure.Step;
import io.restassured.response.Response;

import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;

import static io.restassured.RestAssured.given;

public class Banklink {
    @Step("Start Banklink authenticcation")
    public static Map<String, String> startBankAuthentication(OpenIdConnectFlow flow, String bank, String scope, String locales) throws InterruptedException, URISyntaxException {
        Map<String, String> formParams = new HashMap<String, String>();
        formParams.put("scope", scope);
        formParams.put("response_type", "code");
        formParams.put("client_id", flow.getRelyingParty().getClientId());
        formParams.put("redirect_uri", flow.getRelyingParty().getRedirectUri());
        formParams.put("ui_locales", locales);
        Response authenticationResponse = Requests.openIdConnectAuthenticationRequest(flow, formParams);

        Response taraLoginPageResponse = Requests.followRedirect(flow, authenticationResponse.getHeader("location"));
        String execution = taraLoginPageResponse.getBody().htmlPath().getString("**.findAll { it.@name == 'execution' }[0].@value");
        Map execution2 = submitBanklink(flow, execution, bank)
                .htmlPath().getMap("**.find { it.@id == 'authenticationRedirectForm' }.div.input.collectEntries { [it.@name, it.@value] }");

        Map<String, String> newMap = new HashMap<>();
        execution2.forEach((k, v) -> newMap.put(k.toString(), v.toString()));
        return newMap;
    }

    @Step("Submit Banklink")
    public static Response submitBanklink(OpenIdConnectFlow flow, String execution, String bank) {
        return given()
                .filter(flow.getCookieFilter()).relaxedHTTPSValidation()
                .filter(new AllureRestAssuredFormParam())
                .formParam("execution", execution)
                .formParam("_eventId", "banksubmit")
                //.formParam("geolocation", "")
                .formParam("bank", bank)
                //TODO: actually used? .queryParam("service",flow.getOpenIDProvider().getServiceUrl, testTaraProperties.getServiceUrl())
                //TODO: testTaraProperties.getCasClientId()
                .queryParam("client_name", "CasOAuthClient")
                .queryParam("client_id", flow.getRelyingParty().getClientId())
                .queryParam("redirect_uri", flow.getRelyingParty().getRedirectUri())
                .when()
                .post(flow.getOpenIDProvider().getLoginUrl())
                .then()
                .extract().response();
    }

    @Step("Banklink callback POST")
    public static String banklinkCallbackPOST(OpenIdConnectFlow flow, Map bankResponseParams) {
        return given().filter(flow.getCookieFilter())
                .filter(new AllureRestAssuredFormParam()).relaxedHTTPSValidation().formParams(bankResponseParams)
                .post(flow.getOpenIDProvider().getLoginUrl()).then().extract().response()
                .getHeader("location");
    }

    @Step("Banklink callback GET")
    public static String banklinkCallbackGET(OpenIdConnectFlow flow, Map bankResponseParams) {
        return given().redirects().follow(false).filter(flow.getCookieFilter())
                .filter(new AllureRestAssuredCorrectHeaders()).relaxedHTTPSValidation().queryParams(bankResponseParams)
                .get(flow.getOpenIDProvider().getLoginUrl()).then().extract().response()
                .getHeader("location");
    }

    @Step("Start Banklink authenticcation and receive an error")
    public static Response startBankAuthenticationWithError(OpenIdConnectFlow flow, String bank, String scope, String locales) throws InterruptedException, URISyntaxException {
        Map<String, String> formParams = new HashMap<String, String>();
        formParams.put("scope", scope);
        formParams.put("response_type", "code");
        formParams.put("client_id", flow.getRelyingParty().getClientId());
        formParams.put("redirect_uri", flow.getRelyingParty().getRedirectUri());
        formParams.put("ui_locales", locales);
        Response authenticationResponse = Requests.openIdConnectAuthenticationRequest(flow, formParams);

        Response taraLoginPageResponse = Requests.followRedirect(flow, authenticationResponse.getHeader("location"));
        String execution = taraLoginPageResponse.getBody().htmlPath().getString("**.findAll { it.@name == 'execution' }[0].@value");
        return submitBanklink(flow, execution, bank);
    }

    public static String extractError(Response response) {
        return (String) Steps.extractError(response).get(1);
    }
}
