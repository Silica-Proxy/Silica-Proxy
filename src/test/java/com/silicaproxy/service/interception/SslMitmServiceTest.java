/*
 * Copyright 2026 SilicaProxy Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


package com.silicaproxy.service.interception;

import com.silicaproxy.properties.SilicaProxyProperties;
import net.javacrumbs.shedlock.core.LockConfiguration;
import net.javacrumbs.shedlock.core.LockProvider;
import net.javacrumbs.shedlock.core.SimpleLock;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReentrantLock;
import java.util.stream.Collectors;
import javax.net.ssl.SSLContext;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.doCallRealMethod;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.spy;

@NullMarked
class SslMitmServiceTest {

    @TempDir
    Path tempDir;

    private SilicaProxyProperties makeProperties(@Nullable String keystorePath, @Nullable String password) {
        return new SilicaProxyProperties(
            new SilicaProxyProperties.QuarantineProperties(false, 0, true, Map.of()),
            new SilicaProxyProperties.DeprecationProperties(false, Map.of()),
            new SilicaProxyProperties.SeverityThresholdProperties(false, "NONE", 11.0, Map.of()),
            Map.of(),
            new SilicaProxyProperties.GitOpsProperties(false, "http://example.com", "/rules", null, 60),
            new SilicaProxyProperties.CorporateProxyProperties(false, "proxy.example.com", 8080, "localhost",
                new SilicaProxyProperties.CorporateProxyScopeProperties(false, false, false, false, false)),
            new SilicaProxyProperties.RegistriesProperties("http://npm.example.com", "http://pypi.example.com", "http://maven.example.com"),
            new SilicaProxyProperties.ProxyProperties(0),
            new SilicaProxyProperties.SecurityProperties(new SilicaProxyProperties.SsrfProtectionProperties(false)),
            new SilicaProxyProperties.HttpClientProperties(5, 5, 5, 1),
            new SilicaProxyProperties.SslMitmProperties(keystorePath, password, null),
            new SilicaProxyProperties.ApiCacheProperties(true, 1440, 1440),
            new SilicaProxyProperties.OsvIncrementalProperties(false, "http://example.com", 25),
            new SilicaProxyProperties.ApiCallLogProperties(false, 30, 100),
            new SilicaProxyProperties.ExternalValidationProperties(null, false, Map.of())
        );
    }

    /** Grants the lock immediately, every time — the uncontended, single-instance case. */
    private static final class AlwaysAvailableLockProvider implements LockProvider {
        @Override
        public Optional<SimpleLock> lock(LockConfiguration lockConfiguration) {
            return Optional.of(() -> { });
        }
    }

    /** Real mutual exclusion (blocking) plus bookkeeping of how many holders overlapped. */
    private static final class RecordingLockProvider implements LockProvider {
        private final ReentrantLock lock = new ReentrantLock();
        private final AtomicInteger concurrentHolders = new AtomicInteger();
        private final AtomicInteger maxConcurrentHolders = new AtomicInteger();

        @Override
        public Optional<SimpleLock> lock(LockConfiguration lockConfiguration) {
            lock.lock();
            int holders = concurrentHolders.incrementAndGet();
            maxConcurrentHolders.updateAndGet(max -> Math.max(max, holders));
            return Optional.of(() -> {
                concurrentHolders.decrementAndGet();
                lock.unlock();
            });
        }
    }

    @Test
    void shouldGetCaCertPem() throws Exception {
        SslMitmService service = new SslMitmService(makeProperties(null, null), new MitmCertificateFactory(), new AlwaysAvailableLockProvider());
        service.init();

        assertThat(service.getCaCertPem())
            .startsWith("-----BEGIN CERTIFICATE-----")
            .contains("-----END CERTIFICATE-----");
    }

    @Test
    void shouldGenerateAndSaveKeystoreWhenPathNotExists() throws Exception {
        Path keystorePath = tempDir.resolve("ca.p12");
        SslMitmService service = new SslMitmService(
            makeProperties(keystorePath.toString(), null), new MitmCertificateFactory(), new AlwaysAvailableLockProvider());
        service.init();

        assertThat(keystorePath).exists();
        assertThat(service.getCaCertPem()).startsWith("-----BEGIN CERTIFICATE-----");
    }

    @Test
    void shouldGenerateAndSaveKeystoreWithPassword() throws Exception {
        Path keystorePath = tempDir.resolve("ca-pwd.p12");
        SslMitmService service = new SslMitmService(
            makeProperties(keystorePath.toString(), "changeit"), new MitmCertificateFactory(), new AlwaysAvailableLockProvider());
        service.init();

        assertThat(keystorePath).exists();
        assertThat(service.getCaCertPem()).startsWith("-----BEGIN CERTIFICATE-----");
    }

    @Test
    void shouldLoadCaFromExistingKeystore() throws Exception {
        Path keystorePath = tempDir.resolve("ca.p12");
        MitmCertificateFactory factory = new MitmCertificateFactory();

        SslMitmService service1 = new SslMitmService(
            makeProperties(keystorePath.toString(), "changeit"), factory, new AlwaysAvailableLockProvider());
        service1.init();
        String pemFirst = service1.getCaCertPem();

        SslMitmService service2 = new SslMitmService(
            makeProperties(keystorePath.toString(), "changeit"), factory, new AlwaysAvailableLockProvider());
        service2.init();

        assertThat(service2.getCaCertPem()).isEqualTo(pemFirst);
    }

    @Test
    void shouldCacheSSLContextPerHost() throws Exception {
        SslMitmService service = new SslMitmService(makeProperties(null, null), new MitmCertificateFactory(), new AlwaysAvailableLockProvider());
        service.init();

        SSLContext ctx1 = service.getContextForHost("example.com");
        SSLContext ctx2 = service.getContextForHost("example.com");

        assertThat(ctx1).isSameAs(ctx2);
    }

    @Test
    void shouldWrapExceptionInGetContextForHost() throws Exception {
        MitmCertificateFactory factory = spy(new MitmCertificateFactory());
        doCallRealMethod()
            .doThrow(new RuntimeException("key gen failed"))
            .when(factory)
            .generateKeyPair();

        SslMitmService service = new SslMitmService(makeProperties(null, null), factory, new AlwaysAvailableLockProvider());
        service.init();

        assertThatThrownBy(() -> service.getContextForHost("fail.com"))
            .isInstanceOf(RuntimeException.class)
            .hasMessageContaining("SSL context generation failed for fail.com");
    }

    @Test
    void shouldSerializeCaGenerationAcrossConcurrentInstancesSharingAKeystore() throws Exception {
        Path keystorePath = tempDir.resolve("shared-ca.p12");
        MitmCertificateFactory factory = new MitmCertificateFactory();
        RecordingLockProvider lockProvider = new RecordingLockProvider();
        CountDownLatch startLatch = new CountDownLatch(1);

        List<Callable<String>> tasks = List.of(
            () -> {
                startLatch.await();
                SslMitmService service = new SslMitmService(makeProperties(keystorePath.toString(), null), factory, lockProvider);
                service.init();
                return service.getCaCertPem();
            },
            () -> {
                startLatch.await();
                SslMitmService service = new SslMitmService(makeProperties(keystorePath.toString(), null), factory, lockProvider);
                service.init();
                return service.getCaCertPem();
            }
        );

        ExecutorService executor = Executors.newFixedThreadPool(2);
        try {
            List<Future<String>> futures = tasks.stream().map(executor::submit).collect(Collectors.toList());
            startLatch.countDown();

            String pem1 = futures.get(0).get(10, TimeUnit.SECONDS);
            String pem2 = futures.get(1).get(10, TimeUnit.SECONDS);

            assertThat(pem1).isEqualTo(pem2);
            assertThat(lockProvider.maxConcurrentHolders.get()).isEqualTo(1);
            assertThat(keystorePath).exists();
        } finally {
            executor.shutdownNow();
        }
    }

    @Test
    void shouldLoadKeystoreThatAppearedWhileWaitingForTheLock() throws Exception {
        Path keystorePath = tempDir.resolve("late-ca.p12");
        MitmCertificateFactory factory = new MitmCertificateFactory();
        AtomicReference<String> otherInstancePem = new AtomicReference<>();

        // Simulates a concurrent instance that holds the lock and finishes generating the CA
        // exactly while our instance is asking for the lock.
        LockProvider raceWinnerAlreadyDone = lockConfiguration -> {
            try {
                SslMitmService other = new SslMitmService(
                    makeProperties(keystorePath.toString(), null), factory, new AlwaysAvailableLockProvider());
                other.init();
                otherInstancePem.set(other.getCaCertPem());
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
            return Optional.empty();
        };

        SslMitmService service = new SslMitmService(
            makeProperties(keystorePath.toString(), null), factory, raceWinnerAlreadyDone,
            Duration.ofSeconds(2), Duration.ofMillis(20));
        service.init();

        assertThat(service.getCaCertPem()).isEqualTo(otherInstancePem.get());
    }

    @Test
    void shouldFailWhenLockNeverBecomesAvailableAndKeystoreNeverAppears() {
        Path keystorePath = tempDir.resolve("never-ca.p12");
        LockProvider neverGrants = lockConfiguration -> Optional.empty();

        SslMitmService service = new SslMitmService(
            makeProperties(keystorePath.toString(), null), new MitmCertificateFactory(), neverGrants,
            Duration.ofMillis(150), Duration.ofMillis(20));

        assertThatThrownBy(service::init)
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("Timed out waiting");
    }
}
