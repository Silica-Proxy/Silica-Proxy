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

# Stage 2: Runtime
FROM eclipse-temurin:25-jre-alpine
WORKDIR /app

# Copy packaged jar
COPY --from=builder /app/build/libs/*.jar /app/artifactsentry.jar

# Run as non-root user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser

EXPOSE 3128

ENTRYPOINT ["java", "-XX:MaxRAMPercentage=75.0", "-XX:+UseCompactObjectHeaders", "-XX:+UseStringDeduplication", "-jar", "artifactsentry.jar"]
