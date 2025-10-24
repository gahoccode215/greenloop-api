package com.greenloop.user.config;

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

  @Value("${springdoc.server.url}")
  private String serverUrl;

  @Value("${springdoc.server.description}")
  private String serverDescription;

  @Bean
  public OpenAPI customOpenAPI() {

    Server gatewayServer = new Server();
    gatewayServer.setUrl("http://localhost:8080");
    gatewayServer.setDescription("Gateway Server (Production)");

    Server directServer = new Server();
    directServer.setUrl("http://localhost:8081");
    directServer.setDescription("Direct Service (Development)");

    return new OpenAPI()
        .info(new Info().title("GreenLoop User Service API").version("1.0.0"))
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
