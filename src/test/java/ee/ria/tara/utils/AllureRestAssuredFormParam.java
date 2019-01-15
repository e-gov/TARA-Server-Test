package ee.ria.tara.utils;

import io.qameta.allure.attachment.DefaultAttachmentProcessor;
import io.qameta.allure.attachment.FreemarkerAttachmentRenderer;
import io.qameta.allure.attachment.http.HttpRequestAttachment;
import io.qameta.allure.attachment.http.HttpResponseAttachment;
import io.restassured.filter.FilterContext;
import io.restassured.filter.OrderedFilter;
import io.restassured.http.Headers;
import io.restassured.internal.NameAndValue;
import io.restassured.internal.support.Prettifier;
import io.restassured.response.Response;
import io.restassured.specification.FilterableRequestSpecification;
import io.restassured.specification.FilterableResponseSpecification;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import static io.qameta.allure.attachment.http.HttpResponseAttachment.Builder.create;

/**
 * Allure logger filter for Rest-assured with request form parameters.
 */
public class AllureRestAssuredFormParam implements OrderedFilter {

    @Override
    public Response filter(final FilterableRequestSpecification requestSpec,
                           final FilterableResponseSpecification responseSpec,
                           final FilterContext filterContext) {
        final Prettifier prettifier = new Prettifier();


        final HttpFormRequestAttachment.Builder requestAttachmentBuilder = HttpFormRequestAttachment.Builder.create("Request", requestSpec.getURI())
                .setMethod(requestSpec.getMethod())
                .setHeaders(toMapConverter(requestSpec.getHeaders()))
                .setCookies(toMapConverter(requestSpec.getCookies()));

        if (Objects.nonNull(requestSpec.getFormParams())) {
            requestAttachmentBuilder.setFormParameters(requestSpec.getFormParams());
        }

        final HttpFormRequestAttachment requestAttachment = requestAttachmentBuilder.build();

        new DefaultAttachmentProcessor().addAttachment(
                requestAttachment,
                new FreemarkerAttachmentRenderer("http-request.ftl")
        );

        final Response response = filterContext.next(requestSpec, responseSpec);
        final HttpResponseAttachment responseAttachment = create(response.getStatusLine())
                .withResponseCode(response.getStatusCode())
                .withHeaders(toMapConverterHeaders(response.getHeaders()))
                .withBody(prettifier.getPrettifiedBodyIfPossible(response, response.getBody()))
                .build();

        new DefaultAttachmentProcessor().addAttachment(
                responseAttachment,
                new FreemarkerAttachmentRenderer("http-response.ftl")
        );

        return response;
    }

    private static Map<String, String> toMapConverter(final Iterable<? extends NameAndValue> items) {
        final Map<String, String> result = new HashMap<>();
        items.forEach(h -> result.put(h.getName(), h.getValue()));
        return result;
    }

    private static Map<String, String> toMapConverterHeaders(Headers items) {
        final Map<String, String> result = new HashMap<>();
        items.forEach(h -> result.put(h.getName(), String.join("; ", items.getValues(h.getName()))));
        return result;
    }

    @Override
    public int getOrder() {
        return Integer.MAX_VALUE;
    }

}