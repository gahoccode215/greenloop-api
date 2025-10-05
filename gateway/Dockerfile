# Stage 1: Build JAR
FROM maven:3.9.4-eclipse-temurin-17 AS build
WORKDIR /app
COPY pom.xml .
COPY src ./src
RUN mvn clean package -DskipTests

# Stage 2: Run application
FROM openjdk:17-jdk-slim
WORKDIR /app
COPY --from=build /app/target/gateway-*.jar gateway.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "gateway.jar"]
