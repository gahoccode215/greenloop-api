FROM maven:3.9.4-eclipse-temurin-17 AS build
WORKDIR /app

COPY pom.xml .
RUN mvn dependency:go-offline

COPY src ./src

RUN mvn clean package -DskipTests

FROM eclipse-temurin:17-jdk-alpine
WORKDIR /app

COPY --from=build /app/target/reward-service-*.jar reward-service.jar

EXPOSE 8087

ENTRYPOINT ["java", "-jar", "reward-service.jar"]
