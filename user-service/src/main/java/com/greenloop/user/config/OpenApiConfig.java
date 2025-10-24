package com.greenloop.user.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
public class OpenApiConfig {

    @Value("${GATEWAY_HOST}")
    private String gatewayHost;

    @Value("${SERVICE_HOST}")
    private String serviceHost;

    @Value("${server.port}")
    private String servicePort;

    @Value("${spring.application.name}")
    private String serviceName;

    @Bean
    public OpenAPI customOpenAPI() {
        Server gatewayServer = new Server();
        gatewayServer.setUrl("http://" + gatewayHost + ":8080");
        gatewayServer.setDescription("Gateway (Production)");

        Server directServer = new Server();
        directServer.setUrl("http://" + serviceHost + ":" + servicePort);
        directServer.setDescription("Direct (Internal)");

        return new OpenAPI()
                .info(new Info().title("GreenLoop " + serviceName + " API").version("1.0.0"))
                .servers(List.of(gatewayServer, directServer))
                .components(
                        new Components()
                                .addSecuritySchemes(
                                        "bearerAuth",
                                        new SecurityScheme()
                                                .type(SecurityScheme.Type.HTTP)
                                                .scheme("bearer")
                                                .bearerFormat("JWT")))
                .security(List.of(new SecurityRequirement().addList("bearerAuth")));
    }
}
