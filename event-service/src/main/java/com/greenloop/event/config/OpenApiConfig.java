package com.greenloop.event.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;
import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OpenApiConfig {

  @Value("${GATEWAY_HOST:localhost}")
  private String gatewayHost;

  @Value("${SERVICE_HOST:localhost}")
  private String serviceHost;

  @Value("${spring.application.name}")
  private String serviceName;

  @Value("${server.port}")
  private String servicePort;

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
