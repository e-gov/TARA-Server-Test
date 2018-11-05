package ee.ria.tara.steps;

import ee.ria.tara.model.OpenIdConnectFlow;
import ee.ria.tara.utils.AllureRestAssuredCorrectHeaders;
import io.qameta.allure.Step;
import org.springframework.core.io.Resource;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import static io.restassured.RestAssured.given;

public class BanklinkMock {
    @Step("Configure bank {id} key")
    public static void createBank(OpenIdConnectFlow flow, String id, String privatekeyAlias) throws Exception {
        Resource resource = flow.getResourceLoader().getResource("classpath:bank.p12");
        KeyStore keystore = KeyStore.getInstance("PKCS12" == null ? KeyStore.getDefaultType() : "PKCS12");

        keystore.load(resource.getInputStream(), "s3cr3t".toCharArray());
        PrivateKey key = (PrivateKey) keystore.getKey(privatekeyAlias, "s3cr3t".toCharArray());
        String privateKey = Base64.getEncoder().encodeToString(key.getEncoded());
        given().filter(new AllureRestAssuredCorrectHeaders())
                .when().put(flow.getTestProperties().getBanklinkMockUrl() + "/banks?id=" + id + "&key=" + privateKey)
                .then().statusCode(200);
    }

    @Step("Set {bank} {parameter}={value}")
    public static void setBankDefault(OpenIdConnectFlow flow, String bank, String parameter, String value) {
        given().filter(new AllureRestAssuredCorrectHeaders())
                .when().put(flow.getTestProperties().getBanklinkMockUrl() + "/banks/" + bank + "/defaults?" + parameter + "=" + value)
                .then().statusCode(200);
    }

    @Step("Get bank response")
    public static Map getBankResponse(OpenIdConnectFlow flow, Map bankRequestParams) {
        Map execution = given()
                .filter(new AllureRestAssuredCorrectHeaders())
                .formParams(bankRequestParams)
                .when().post(flow.getTestProperties().getBanklinkMockUrl() + "/auth")
                .then()
                .extract().response().htmlPath().getMap("**.find { it.@id == 'submitForm' }.input.collectEntries { [it.@name, it.@value] }");

        Map<String, String> newMap = new HashMap<>();
        execution.forEach((k, v) -> newMap.put(k.toString(), v.toString()));
        return newMap;
    }
}
