package com.greenloop.order.ghn.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Data
@Configuration
@ConfigurationProperties(prefix = "ghn")
public class GHNProperties {

    private String baseUrl;
    private String tokenApi;
    private String shopId;
    private String clientId;
}
