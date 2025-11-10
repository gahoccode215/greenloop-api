package com.greenloop.order.ghn.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

@Configuration
@ConfigurationProperties(prefix = "ghn.api")
@Data
public class GHNConfig {
    private String baseUrl;
    private String devUrl;
    private String token;
    private Integer shopId;
    private Integer timeout;

    @Bean
    public RestTemplate ghnRestTemplate() {
        return new RestTemplate();
    }
}
