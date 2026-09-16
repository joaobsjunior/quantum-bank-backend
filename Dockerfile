FROM eclipse-temurin:17-jdk-jammy AS build

WORKDIR /workspace

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates perl unzip \
    && rm -rf /var/lib/apt/lists/*

COPY gradlew build.gradle.kts settings.gradle.kts ./
COPY src ./src

RUN chmod +x ./gradlew && ./gradlew --no-daemon clean bootJar

# Alpine 3.24 ships OpenSSL 3.5 (native ML-DSA), which the PKI sign script
# mounted into this container requires to verify and issue post-quantum
# certificates; bash and flock are the script's other dependencies.
FROM eclipse-temurin:17-jre-alpine

WORKDIR /app

RUN apk add --no-cache openssl bash util-linux-misc \
    && addgroup -S quantumbank \
    && adduser -S -G quantumbank -h /app -s /sbin/nologin quantumbank

COPY --from=build /workspace/build/libs/*.jar /app/quantum-bank-backend.jar

USER quantumbank
EXPOSE 8080

ENTRYPOINT ["java", "-jar", "/app/quantum-bank-backend.jar"]
