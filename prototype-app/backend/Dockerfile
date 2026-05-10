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
ENV JAVA_TOOL_OPTIONS=""
ENV JAVA_OPTS="-XX:MaxRAMPercentage=60.0 -XX:InitialRAMPercentage=10.0 -XX:MaxMetaspaceSize=192m -XX:+ExitOnOutOfMemoryError"
ENTRYPOINT ["sh", "-c", "java $JAVA_TOOL_OPTIONS $JAVA_OPTS -jar /app/vulnwatch-backend.jar"]
