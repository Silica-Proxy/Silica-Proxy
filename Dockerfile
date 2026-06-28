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

# Stage 2: Minimal JRE with jlink (alpine = musl, matches runtime base)
FROM eclipse-temurin:25-jdk-alpine AS jre-builder
COPY --from=builder /app/build/libs/*.jar /app/silicaproxy.jar
RUN mkdir -p /tmp/app && \
    cd /tmp/app && \
    jar xf /app/silicaproxy.jar && \
    MODULES=$(jdeps \
        --ignore-missing-deps \
        --print-module-deps \
        --multi-release 25 \
        --class-path '/tmp/app/BOOT-INF/lib/*' \
        /tmp/app/BOOT-INF/classes \
        2>/dev/null) && \
    echo "Detected modules: $MODULES" && \
    jlink \
        --add-modules "${MODULES},jdk.crypto.ec,jdk.crypto.cryptoki" \
        --strip-debug \
        --no-man-pages \
        --no-header-files \
        --compress=zip-6 \
        --output /opt/jre

# Stage 3: Runtime
FROM alpine:3
ENV JAVA_HOME=/opt/jre
ENV PATH="$JAVA_HOME/bin:$PATH"
WORKDIR /app

COPY --from=jre-builder /opt/jre /opt/jre
COPY --from=builder /app/build/libs/*.jar /app/silicaproxy.jar

# Run as non-root user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup && \
    mkdir -p /app/logs /app/work && chown -R appuser:appgroup /app/logs /app/work
USER appuser

EXPOSE 8080

ENTRYPOINT ["java", "-XX:+UseZGC", "-XX:MaxRAMPercentage=75.0", "-XX:+UseCompactObjectHeaders", "-XX:+UseStringDeduplication", "-Dsun.net.inetaddr.ttl=60", "-jar", "silicaproxy.jar"]
