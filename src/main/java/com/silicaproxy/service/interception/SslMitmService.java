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
import jakarta.annotation.PostConstruct;
import net.javacrumbs.shedlock.core.LockConfiguration;
import net.javacrumbs.shedlock.core.LockProvider;
import net.javacrumbs.shedlock.core.SimpleLock;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

@Component
@NullMarked
public class SslMitmService {

    private static final Logger LOG = LoggerFactory.getLogger(SslMitmService.class);
    private static final String CA_ALIAS = "silicaproxy-ca";

    // Coordinates CA generation across instances sharing the same keystore file/path — see
    // the "Production — Multiple instances / load balancing" section of the README for why
    // this matters: without it, every instance mints its own CA and clients trust none of them
    // reliably behind a load balancer.
    private static final String CA_INIT_LOCK_NAME = "silicaproxy_ca_init_lock";
    private static final Duration LOCK_AT_MOST_FOR = Duration.ofMinutes(2);
    private static final Duration DEFAULT_LOCK_WAIT_TIMEOUT = Duration.ofSeconds(30);
    private static final Duration DEFAULT_LOCK_POLL_INTERVAL = Duration.ofMillis(200);

    private final SilicaProxyProperties properties;
    private final MitmCertificateFactory certFactory;
    private final LockProvider lockProvider;
    private final HostSslContextCache hostSslContextCache;
    private final Duration lockWaitTimeout;
    private final Duration lockPollInterval;

    private KeyPair caKeyPair;
    private X509Certificate caCert;
    private String caCertPem;

    @Autowired
    public SslMitmService(SilicaProxyProperties properties, MitmCertificateFactory certFactory,
            LockProvider lockProvider, HostSslContextCache hostSslContextCache) {
        this(properties, certFactory, lockProvider, hostSslContextCache, DEFAULT_LOCK_WAIT_TIMEOUT, DEFAULT_LOCK_POLL_INTERVAL);
    }

    SslMitmService(SilicaProxyProperties properties, MitmCertificateFactory certFactory, LockProvider lockProvider,
            HostSslContextCache hostSslContextCache, Duration lockWaitTimeout, Duration lockPollInterval) {
        this.properties = properties;
        this.certFactory = certFactory;
        this.lockProvider = lockProvider;
        this.hostSslContextCache = hostSslContextCache;
        this.lockWaitTimeout = lockWaitTimeout;
        this.lockPollInterval = lockPollInterval;
    }

    @PostConstruct
    public void init() throws Exception {
        String keystorePath = properties.sslMitm().caKeystorePath();
        if (keystorePath != null && !keystorePath.isBlank()) {
            Path path = Path.of(keystorePath);
            if (!tryLoadIfExists(path)) {
                generateUnderLock(path);
            }
        } else {
            generateNewCA();
        }

        if (caCert == null) {
            throw new IllegalStateException("CA certificate initialization failed");
        }

        caCertPem = certFactory.buildPem(caCert);
        exportCACert();
    }

    /** Returns {@code true} if a valid CA was loaded from {@code path}. */
    private boolean tryLoadIfExists(Path path) {
        if (!Files.exists(path)) {
            return false;
        }
        try {
            loadFromKeystore(path);
            if (caCert != null) {
                LOG.info("CA certificate loaded from existing keystore {}", path.toAbsolutePath());
                return true;
            }
            LOG.warn("Keystore exists but certificate not found, generating new CA");
        } catch (Exception e) {
            LOG.warn("Failed to load keystore, generating new CA: {}", e.getMessage());
        }
        return false;
    }

    /**
     * Generates and persists a new CA, coordinated through a distributed lock so that when
     * several instances share the same keystore path, only one of them ever generates it —
     * the others wait for the lock (or notice the file appear) and load it instead.
     */
    private void generateUnderLock(Path path) throws Exception {
        Instant deadline = Instant.now().plus(lockWaitTimeout);
        while (true) {
            Optional<SimpleLock> lock = lockProvider.lock(
                new LockConfiguration(Instant.now(), CA_INIT_LOCK_NAME, LOCK_AT_MOST_FOR, Duration.ZERO));
            if (lock.isPresent()) {
                try {
                    // Another instance may have generated it while we were waiting for the lock.
                    if (!tryLoadIfExists(path)) {
                        generateNewCA();
                        saveToKeystore(path);
                        LOG.info("CA certificate generated and saved to new keystore {}", path.toAbsolutePath());
                    }
                    return;
                } finally {
                    lock.get().unlock();
                }
            }

            if (tryLoadIfExists(path)) {
                return;
            }
            if (Instant.now().isAfter(deadline)) {
                throw new IllegalStateException("Timed out waiting for another instance to generate the CA keystore at " + path);
            }
            Thread.sleep(lockPollInterval.toMillis());
        }
    }

    public String getCaCertPem() {
        return caCertPem;
    }

    // Null only in the narrow window before init() has run (or if it failed and threw, in
    // which case the application never finishes starting) -- callers (SslMitmMetrics,
    // MonitoringService) treat null as "not yet known" rather than assuming it is always set.
    public @Nullable Instant getCaCertNotAfter() {
        return caCert != null ? caCert.getNotAfter().toInstant() : null;
    }

    public SSLContext getContextForHost(String host) {
        return hostSslContextCache.getOrCompute(host, this::buildSSLContextOrThrow);
    }

    private SSLContext buildSSLContextOrThrow(String host) {
        try {
            return buildSSLContext(host);
        } catch (Exception e) {
            throw new RuntimeException("SSL context generation failed for " + host, e);
        }
    }

    private void generateNewCA() throws Exception {
        caKeyPair = certFactory.generateKeyPair();
        caCert = certFactory.buildCACertificate(caKeyPair);
    }

    private void loadFromKeystore(Path path) throws Exception {
        char[] password = keystorePassword();
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(path)) {
            ks.load(in, password);
        }
        PrivateKey privateKey = (PrivateKey) ks.getKey(CA_ALIAS, password);
        if (privateKey == null) {
            // getKey returns null silently (wrong password, wrong alias, or a cert-only entry)
            // rather than throwing -- left unchecked, caKeyPair would end up with a null
            // private key and only fail much later, deep in a host cert signing call.
            throw new IllegalStateException("CA private key not found in keystore " + path.toAbsolutePath());
        }
        caCert = (X509Certificate) ks.getCertificate(CA_ALIAS);
        caKeyPair = new KeyPair(caCert.getPublicKey(), privateKey);
    }

    private void saveToKeystore(Path path) throws Exception {
        Path keystoreParent = path.getParent();
        if (keystoreParent != null) {
            Files.createDirectories(keystoreParent);
        }
        char[] password = keystorePassword();
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry(CA_ALIAS, caKeyPair.getPrivate(), password, new Certificate[]{caCert});
        try (OutputStream out = Files.newOutputStream(path)) {
            ks.store(out, password);
        }
    }

    private char[] keystorePassword() {
        String pwd = properties.sslMitm().caKeystorePassword();
        return (pwd != null && !pwd.isBlank()) ? pwd.toCharArray() : new char[0];
    }

    private SSLContext buildSSLContext(String host) throws Exception {
        KeyPair hostKeyPair = certFactory.generateKeyPair();
        X509Certificate hostCert = certFactory.buildHostCertificate(host, hostKeyPair, caKeyPair);

        char[] password = new char[0];
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry("host", hostKeyPair.getPrivate(), password, new Certificate[]{hostCert, caCert});

        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(ks, password);

        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(kmf.getKeyManagers(), null, null);
        return ctx;
    }

    private void exportCACert() throws Exception {
        String exportPath = properties.sslMitm().caCertExportPath();
        Path certPath;
        if (exportPath != null && !exportPath.isBlank()) {
            certPath = Path.of(exportPath);
        } else {
            String keystorePath = properties.sslMitm().caKeystorePath();
            if (keystorePath != null && !keystorePath.isBlank()) {
                Path parent = Path.of(keystorePath).getParent();
                certPath = parent != null ? parent.resolve("silicaproxy-ca.crt") : Path.of("silicaproxy-ca.crt");
            } else {
                certPath = Path.of("silicaproxy-ca.crt");
            }
        }
        Path certParent = certPath.getParent();
        if (certParent != null) {
            Files.createDirectories(certParent);
        }
        Files.writeString(certPath, caCertPem);
        LOG.info("CA certificate exported to {} — import it into your artifact repository's trust store",
                certPath.toAbsolutePath());
    }
}
