package ee.ria.tara.steps;

import ee.ria.tara.model.OpenIdConnectFlow;
import ee.ria.tara.utils.AllureRestAssuredFormParam;
import ee.ria.tara.utils.OpenIdConnectUtils;
import io.qameta.allure.Allure;
import io.qameta.allure.Step;
import io.qameta.allure.restassured.AllureRestAssured;
import io.restassured.response.Response;
import org.apache.http.cookie.Cookie;

import java.io.IOException;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;

import static io.restassured.RestAssured.given;

public class IdCard {

    @Step("{flow.endUser}Authenticates with ID-card")
    public static Response authenticateWithIdCard(OpenIdConnectFlow flow, String certificateFile, String scope, String language) throws InterruptedException, URISyntaxException, IOException {
        Map<String, String> formParams = new HashMap<String, String>();
        formParams.put("scope", scope);
        formParams.put("response_type", "code");
        formParams.put("client_id", flow.getRelyingParty().getClientId());
        formParams.put("redirect_uri", flow.getRelyingParty().getRedirectUri());
        formParams.put("lang", language);
        Response authenticationResponse = Requests.openIdConnectAuthenticationRequest(flow, formParams); //getBody().htmlPath().getString("**.findAll { it.@name == 'execution' }[0].@value")
        String location = authenticationResponse.then().extract().response()
                .getHeader("location");
        Response taraLoginPageResponse = Requests.followRedirect(flow, location);
        String execution = taraLoginPageResponse.getBody().htmlPath().getString("**.findAll { it.@name == 'execution' }[0].@value");
        Response idcardResponse = idcard(flow, OpenIdConnectUtils.getResourceFileAsString(flow.getResourceLoader(), certificateFile));
        flow.updateSessionId(idcardResponse.cookie("JSESSIONID"));
        Response submitResponse = submitIdCardLogin(flow, execution, location);
        return Requests.followLoginRedirects(flow, submitResponse.getHeader("location"));
    }

    @Step("{flow.endUser}Submit ID-Card login")
    public static Response submitIdCardLogin(OpenIdConnectFlow flow, String execution, String location) {
        return given()
                .filter(flow.getCookieFilter())
                .filter(new AllureRestAssuredFormParam())
                .relaxedHTTPSValidation()
                .formParam("execution", execution)
                .formParam("_eventId", "idsubmit")
                .formParam("idlang", "")
                .formParam("geolocation", "")
                .when()
                .post(location)
                .then()
                .extract().response();
    }

    @Step("{flow.endUser}Certificate POST to backend /idcard")
    public static Response idcard(OpenIdConnectFlow flow, String certificate) {
        Allure.addLinks(new io.qameta.allure.model.Link()
                .withName("View Certificate in lapo.it")
                .withUrl("https://lapo.it/asn1js/#" + certificate));
        String jSessionId = "";
        for (Cookie cookie : flow.getCookieFilter().cookieStore.getCookies()) {
            if (cookie.getName().equalsIgnoreCase("JSESSIONID")) {
                jSessionId = cookie.getValue();
            }
        }
        return given().cookie("JSESSIONID", jSessionId).header("XCLIENTCERTIFICATE", certificate)
                .filter(new AllureRestAssured())
                .relaxedHTTPSValidation()
                .when()
                .redirects().follow(false)
                .get(flow.getTestProperties().getBackendUrl()+"/idcard")
                .then().extract().response();
    }
}
