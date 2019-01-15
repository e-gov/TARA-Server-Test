package ee.ria.tara.utils;

import io.qameta.allure.attachment.AttachmentData;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * Copied from https://raw.githubusercontent.com/allure-framework/allure-java/master/allure-attachments/src/main/java/io/qameta/allure/attachment/http/HttpRequestAttachment.java
 * Fixed getCurl to work with form parameters
 */
public class HttpFormRequestAttachment implements AttachmentData {

    private final String name;

    private final String url;

    private final String method;

    private final String body;

    private final String curl;

    private final Map<String, String> headers;

    private final Map<String, String> cookies;

    public HttpFormRequestAttachment(final String name, final String url, final String method,
                                     final String body, final String curl, final Map<String, String> headers,
                                     final Map<String, String> cookies) {
        this.name = name;
        this.url = url;
        this.method = method;
        this.body = body;
        this.curl = curl;
        this.headers = headers;
        this.cookies = cookies;
    }

    public String getUrl() {
        return url;
    }

    public String getMethod() {
        return method;
    }

    public String getBody() {
        return body;
    }

    public Map<String, String> getHeaders() {
        return headers;
    }

    public Map<String, String> getCookies() {
        return cookies;
    }

    public String getCurl() {
        return curl;
    }

    @Override
    public String getName() {
        return name;
    }

    /**
     * Builder for HttpFormRequestAttachment.
     */
    @SuppressWarnings("PMD.AvoidFieldNameMatchingMethodName")
    public static final class Builder {

        private final String name;

        private final String url;

        private String method;

        private Map<String, String> formParameters = new HashMap<>();

        private final Map<String, String> headers = new HashMap<>();

        private final Map<String, String> cookies = new HashMap<>();

        private Builder(final String name, final String url) {
            Objects.requireNonNull(name, "Name must not be null value");
            Objects.requireNonNull(url, "Url must not be null value");
            this.name = name;
            this.url = url;
        }

        public static Builder create(final String attachmentName, final String url) {
            return new Builder(attachmentName, url);
        }

        public Builder setMethod(final String method) {
            Objects.requireNonNull(method, "Method must not be null value");
            this.method = method;
            return this;
        }

        public Builder setHeader(final String name, final String value) {
            Objects.requireNonNull(name, "Header name must not be null value");
            Objects.requireNonNull(value, "Header value must not be null value");
            this.headers.put(name, value);
            return this;
        }

        public Builder setHeaders(final Map<String, String> headers) {
            Objects.requireNonNull(headers, "Headers must not be null value");
            this.headers.putAll(headers);
            return this;
        }

        public Builder setCookie(final String name, final String value) {
            Objects.requireNonNull(name, "Cookie name must not be null value");
            Objects.requireNonNull(value, "Cookie value must not be null value");
            this.cookies.put(name, value);
            return this;
        }

        public Builder setCookies(final Map<String, String> cookies) {
            Objects.requireNonNull(cookies, "Cookies must not be null value");
            this.cookies.putAll(cookies);
            return this;
        }

        public Builder setFormParameter(final String name, final String value) {
            Objects.requireNonNull(name, "Form parameter name must not be null value");
            Objects.requireNonNull(value, "Form parameter must not be null value");
            this.formParameters.put(name, value);
            return this;
        }

        public Builder setFormParameters(final Map<String, String> parameters) {
            Objects.requireNonNull(cookies, "Parameters must not be null value");
            this.formParameters.putAll(parameters);
            return this;
        }

        public HttpFormRequestAttachment build() {
            return new HttpFormRequestAttachment(name, url, method, getBody(), getCurl(), headers, cookies);
        }

        private String getBody() {
            return formParameters.entrySet()
                    .stream()
                    .map(entry -> entry.getKey() + ": " + (entry.getValue() instanceof String ? entry.getValue() : "")) //value can be io.restassured.internal.NoParameterValue
                    .collect(Collectors.joining("\n"));
        }

        private String getCurl() {
            final StringBuilder builder = new StringBuilder("curl -v");
            if (Objects.nonNull(method)) {
                builder.append(" -X ").append(method);
            }
            builder.append(" '").append(url).append('\'');
            headers.forEach((key, value) -> appendHeader(builder, key, value));
            cookies.forEach((key, value) -> appendCookie(builder, key, value));

            if (Objects.nonNull(formParameters)) {
                formParameters.forEach((key, value) -> appendFormParameter(builder, key, value));
            }
            return builder.toString();
        }

        private static void appendHeader(final StringBuilder builder, final String key, final String value) {
            builder.append(" -H '")
                    .append(key)
                    .append(": ")
                    .append(value)
                    .append('\'');
        }

        private static void appendCookie(final StringBuilder builder, final String key, final String value) {
            builder.append(" -b '")
                    .append(key)
                    .append('=')
                    .append(value)
                    .append('\'');
        }
        private static void appendFormParameter(final StringBuilder builder, final String key, final String value) {
            builder.append(" --data-urlencode '")
                    .append(key)
                    .append('=')
                    .append(value)
                    .append('\'');
        }
    }
}