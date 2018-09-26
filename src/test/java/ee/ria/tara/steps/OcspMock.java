package ee.ria.tara.steps;

import ee.ria.tara.model.OpenIdConnectFlow;
import io.qameta.allure.Step;
import io.qameta.allure.restassured.AllureRestAssured;
import io.restassured.http.ContentType;

import java.util.Map;

import static io.restassured.RestAssured.given;

public class OcspMock {
    @Step("Configure OCSP response {serialNumber}")
    public static void setStatus(OpenIdConnectFlow flow, String serialNumber, Map responseData) throws Exception {
        given()
                .contentType(ContentType.JSON).
                filter(new AllureRestAssured())
                .body(responseData)
                .when()
                .post(flow.getTestProperties().getOcspMockUrl() + "/set_status/" + serialNumber)
                .then()
                .statusCode(200);
    }
}
