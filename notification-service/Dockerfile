# Stage 1: Build JAR
FROM maven:3.9.4-eclipse-temurin-17 AS build
WORKDIR /app
COPY pom.xml .
COPY src ./src
RUN mvn clean package -DskipTests

# Stage 2: Run application
FROM openjdk:17-jdk-slim
WORKDIR /app
COPY --from=build /app/target/notification-service-*.jar notification-service.jar
EXPOSE 8084
ENTRYPOINT ["java", "-jar", "notification-service.jar"]
