package com.greenloop.order.ghn.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

@Configuration
@ConfigurationProperties(prefix = "ghn")
@Data
public class GHNConfig {
    private ApiConfig api;

    @Data
    public static class ApiConfig {
        private String baseUrl;
        private String token;
        private Integer shopId;
    }

}

