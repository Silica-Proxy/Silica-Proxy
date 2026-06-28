# Stage 1: Build
FROM eclipse-temurin:25-jdk AS builder
WORKDIR /app

# Copy gradle config and wrapper
COPY gradle/ /app/gradle/
COPY gradlew /app/
COPY settings.gradle /app/
COPY build.gradle /app/

# Build dependencies offline/cache-friendly first
RUN ./gradlew dependencies --no-daemon || true

# Copy source code and build
COPY src/ /app/src/
RUN ./gradlew bootJar --no-daemon -x test

# Stage 2: CDS training run (loads all Spring classes, exits before connecting to external services)
FROM eclipse-temurin:25-jre-alpine AS training
WORKDIR /app
COPY --from=builder /app/build/libs/*.jar /app/silicaproxy.jar
RUN java \
    -XX:ArchiveClassesAtExit=/app/silicaproxy.jsa \
    -Dspring.context.exit=onRefresh \
    -Dspring.main.lazy-initialization=true \
    -jar /app/silicaproxy.jar || true

# Stage 3: Runtime
FROM eclipse-temurin:25-jre-alpine
WORKDIR /app

COPY --from=builder /app/build/libs/*.jar /app/silicaproxy.jar
COPY --from=training /app/silicaproxy.jsa /app/silicaproxy.jsa

# Run as non-root user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser

EXPOSE 3128

ENTRYPOINT ["java", "-XX:SharedArchiveFile=/app/silicaproxy.jsa", "-XX:+UseZGC", "-XX:MaxRAMPercentage=75.0", "-XX:+UseCompactObjectHeaders", "-XX:+UseStringDeduplication", "-Dsun.net.inetaddr.ttl=60", "-jar", "silicaproxy.jar"]
