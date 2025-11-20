package com.greenloop.gateway.config;

import com.greenloop.gateway.filter.JwtAuthFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@RequiredArgsConstructor
public class GatewayConfig {

    private final JwtAuthFilter jwtAuthFilter;

    @Bean
    public RouteLocator customRouteLocator(RouteLocatorBuilder builder) {
        return builder
                .routes()
                .route(
                        "user-service",
                        r ->
                                r.path(
                                                "/api/v1/users/**",
                                                "/oauth2/**",
                                                "/login/**",
                                                "/api/v1/auth/**",
                                                "/api/v1/admin/**",
                                                "/api/v1/addresses/**")
                                        .filters(f -> f.filter(jwtAuthFilter.apply(new JwtAuthFilter.Config())))
                                        .uri("lb://user-service"))
                .route(
                        "user-service-docs",
                        r ->
                                r.path("/user-service/v3/api-docs")
                                        .filters(f -> f.rewritePath("/user-service/v3/api-docs", "/v3/api-docs"))
                                        .uri("lb://user-service"))
                .route(
                        "product-service",
                        r ->
                                r.path("/api/v1/products/**", "/api/v1/categories/**", "/api/v1/donations/**")
                                        .filters(f -> f.filter(jwtAuthFilter.apply(new JwtAuthFilter.Config())))
                                        .uri("lb://product-service"))
                .route(
                        "product-service-docs",
                        r ->
                                r.path("/product-service/v3/api-docs")
                                        .filters(f -> f.rewritePath("/product-service/v3/api-docs", "/v3/api-docs"))
                                        .uri("lb://product-service"))
                .route(
                        "event-service",
                        r ->
                                r.path(
                                                "/api/v1/events/**",
                                                "/api/v1/event-staff/**",
                                                "/api/v1/event-registration/**")
                                        .filters(f -> f.filter(jwtAuthFilter.apply(new JwtAuthFilter.Config())))
                                        .uri("lb://event-service"))
                .route(
                        "event-service-docs",
                        r ->
                                r.path("/event-service/v3/api-docs")
                                        .filters(f -> f.rewritePath("/event-service/v3/api-docs", "/v3/api-docs"))
                                        .uri("lb://event-service"))
                .route(
                        "reward-service",
                        r ->
                                r.path("/api/v1/eco-points/**")
                                        .filters(f -> f.filter(jwtAuthFilter.apply(new JwtAuthFilter.Config())))
                                        .uri("lb://reward-service"))
                .route(
                        "reward-service-docs",
                        r ->
                                r.path("/reward-service/v3/api-docs")
                                        .filters(f -> f.rewritePath("/reward-service/v3/api-docs", "/v3/api-docs"))
                                        .uri("lb://reward-service"))
                .route(
                        "order-service",
                        r ->
                                r.path(
                                                "/api/v1/orders/**",
                                                "/api/v1/carts/**",
                                                "/api/v1/checkout/**",
                                                "/api/v1/goship/**",
                                                "/api/v1/admin/orders/**",
                                                "/api/v1/webhooks/goship/**",
                                                "/api/v1/ghn/**")
                                        .filters(f -> f.filter(jwtAuthFilter.apply(new JwtAuthFilter.Config())))
                                        .uri("lb://order-service"))
                .route(
                        "order-service-docs",
                        r ->
                                r.path("/order-service/v3/api-docs")
                                        .filters(f -> f.rewritePath("/order-service/v3/api-docs", "/v3/api-docs"))
                                        .uri("lb://order-service"))
                .build();
    }
}
