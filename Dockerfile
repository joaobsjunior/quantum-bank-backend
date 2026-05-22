FROM eclipse-temurin:17-jdk-jammy AS build

WORKDIR /workspace

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates perl unzip \
    && rm -rf /var/lib/apt/lists/*

COPY gradlew build.gradle.kts settings.gradle.kts ./
COPY src ./src

RUN chmod +x ./gradlew && ./gradlew --no-daemon clean bootJar

FROM eclipse-temurin:17-jre-jammy

WORKDIR /app

RUN groupadd --system quantumbank \
    && useradd --system --gid quantumbank --home-dir /app quantumbank

COPY --from=build /workspace/build/libs/*.jar /app/quantum-bank-backend.jar

USER quantumbank
EXPOSE 8080

ENTRYPOINT ["java", "-jar", "/app/quantum-bank-backend.jar"]
