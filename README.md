# GreenLoop — API (greenloop-api)

GreenLoop is a Spring Boot microservices platform that provides the backend APIs for the GreenLoop application. This repository is a multi-module Maven project containing several Spring Boot services (Eureka server, API Gateway, and multiple business microservices) with OpenAPI documentation, security, messaging, and integrations for storage, AI and more.

## Table of contents
- Architecture & technologies
- Modules / services
- Prerequisites
- Build & run (quickstart)
- Environment variables & configuration notes
- API documentation
- Testing
- Contributing
- Troubleshooting & common commands
- License & contact

## Architecture & technologies
GreenLoop is implemented as a set of Spring Boot microservices using the Spring Cloud ecosystem. Key technologies and patterns used across the codebase:

- Java 17
- Spring Boot (3.x)
- Spring Cloud (Netflix Eureka for service discovery, Spring Cloud Gateway)
- Spring Security (JWT, OAuth2 support)
- Springdoc / OpenAPI for API docs
- Spring Data JPA + MySQL for persistence
- Redis for caching/session store
- RabbitMQ / Spring Cloud Stream for messaging
- Feign clients for inter-service HTTP calls
- Cloudinary for media storage integrations
- Google Vision + Spring AI (Vertex/Gemini starters) for AI/vision related services
- Lombok for boilerplate reduction
- Maven multi-module project

Main application entry points can be found in each module's `src/main/java` package (example: `gateway/src/main/java/com/greenloop/gateway/GatewayApplication.java`).

## Modules / services (discovered in repository)
The repository contains multiple modules / services. Each module is a Spring Boot application. Modules found include (not necessarily exhaustive):

- eureka — Discovery server (Eureka)
- gateway — API Gateway (Spring Cloud Gateway)
- user-service — User, authentication and authorization endpoints
- notification-service — Email / notifications (SMTP + templates)
- event-service — Event domain and APIs
- reward-service — Reward domain and APIs
- ai-service — AI/vision service (Google Vision, Spring AI)
- product-service — Product domain; Cloudinary integration
- order-service — Orders / payments integration

Each service typically includes an `OpenApiConfig` class (OpenAPI config) and a Spring Boot application entry point.

## Prerequisites
- Java 17 (JDK 17)
- Maven 3.6+ (recommended)
- MySQL (or other RDBMS configured in service properties)
- Redis (if using caching/session features)
- RabbitMQ (if using messaging features / Spring Cloud Stream)
- (Optional) Cloudinary account + credentials (media upload)
- (Optional) Google Cloud credentials and API access for AI/vision features (set appropriate environment variables or service account)
- (Optional) SMTP credentials for notification/email service

## Build & run — Quickstart

1. Clone repository
   git clone https://github.com/gahoccode215/greenloop-api.git
   cd greenloop-api

2. Build the whole multi-module project
   mvn -T 1C clean install

   - If you want to skip tests for a faster build:
     mvn -T 1C clean install -DskipTests

3. Run services locally
   Recommended order:
   - Start the discovery server (Eureka):
     cd eureka && mvn spring-boot:run
   - Start required infrastructure services (MySQL, Redis, RabbitMQ)
   - Start each backend service one-by-one (example):
     cd user-service && mvn spring-boot:run
     cd ../event-service && mvn spring-boot:run
     cd ../product-service && mvn spring-boot:run
   - Start the gateway last:
     cd ../gateway && mvn spring-boot:run

   Alternatively, run a single module from the project root:
   mvn -pl user-service -am spring-boot:run

4. Accessing services
   - Each service runs on the configured port (see each module's `application.yml` / `application.properties` or override with `-Dserver.port=...`)
   - API docs: visit a service's OpenAPI UI (see "API documentation" below)

## Environment variables & configuration
Services include OpenAPI configuration that reads variables such as:
- GATEWAY_HOST (default example value found in code)
- SERVICE_HOST
- spring.application.name
- server.port

Common configuration properties (you will typically set these in each service's `application-*.yml` or environment):
- spring.datasource.url / username / password (MySQL)
- spring.redis.host / port
- spring.rabbitmq.host / port / username / password
- jwt.secret / jwt.expiration (the repository uses JWT for auth — set secure secret)
- cloudinary configuration (for Cloudinary integration)
- google credentials (e.g., `GOOGLE_APPLICATION_CREDENTIALS`) for AI/vision service
- spring.mail.* for notification/email service SMTP settings

Because the repository uses standard Spring Boot configuration files, you can provide these as environment variables or as files (application.yml/profile files). Inspect each service's `src/main/resources` for default/example configuration and profile usage.

## API documentation
Most services register OpenAPI (springdoc) and expose:
- Swagger UI: /swagger-ui/index.html (or `/swagger-ui.html` depending on version)
- OpenAPI JSON: /v3/api-docs

Example (when service runs on localhost:8081):
- http://localhost:8081/swagger-ui/index.html
- http://localhost:8081/v3/api-docs

OpenAPI configuration classes were added in many services (e.g., `OpenApiConfig.java`) and set up server entries for direct and gateway access.
