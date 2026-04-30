FROM maven:3.9.9-eclipse-temurin-17 AS build
WORKDIR /workspace
COPY pom.xml .
RUN mvn -q -DskipTests dependency:go-offline
COPY src ./src
RUN mvn -q -DskipTests package

FROM eclipse-temurin:17-jre
WORKDIR /app
RUN addgroup --system vulnwatch && adduser --system --ingroup vulnwatch vulnwatch
COPY --from=build /workspace/target/vulnwatch-backend-*.jar /app/vulnwatch-backend.jar
USER vulnwatch:vulnwatch
EXPOSE 8080
ENV JAVA_OPTS=""
ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -jar /app/vulnwatch-backend.jar"]
