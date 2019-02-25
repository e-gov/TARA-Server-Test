package ee.ria.tara.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties({
        TestTaraProperties.class
})
public class TestConfiguration {

    public static int ALLOWED_TIME_DIFFERENCE_IN_SECONDS = 30;
}
