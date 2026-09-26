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

import com.silicaproxy.config.Metrics;
import com.silicaproxy.dao.audit.ApiCallLogDao;
import com.silicaproxy.dao.client.DepsDevClient;
import com.silicaproxy.dao.identification.FileDigestIndexDao;
import com.silicaproxy.dao.identification.FileDigestIndexDao.DigestEntry;
import com.silicaproxy.model.dto.HashLookup;
import com.silicaproxy.model.dto.HashType;
import com.silicaproxy.properties.ResponseIdentificationProperties;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.util.EnumMap;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

/**
 * Last-resort identification of a download whose URL names no package version, from the upstream
 * response the proxy is about to relay : the file digest the upstream announces
 * ({@code X-Checksum-Sha256} / {@code X-Checksum-Sha1} on Artifactory and Maven Central,
 * {@code ETag: "<sha1>"} on Nexus 3) is looked up on deps.dev. Needs no extra upstream call :
 * the status and headers are known before the body is relayed.
 *
 * <p>The announced digest is only trusted because the caller recomputes it while relaying
 * ({@link ChecksumVerifyingRelay}) : otherwise a malicious upstream could announce the digest of a
 * harmless package. The file name ({@code Content-Disposition}) is not used, as nothing verifies
 * it ; nor is {@code Last-Modified}, which on a proxy repository is the caching date.
 *
 * <p>Identified digests are stored in {@code file_digest_index} ({@link FileDigestIndexDao}),
 * shared by all instances and looked up before deps.dev. Digests deps.dev does not identify are
 * not stored and are queried again on every download ; an unavailable deps.dev leaves the request
 * unidentified (relayed unchecked, as before). A database failure never fails the download : the
 * lookup goes on without the table.
 */
@Service
@NullMarked
public class ResponseIdentificationService {

    private static final Logger LOG = LoggerFactory.getLogger(ResponseIdentificationService.class);
    private static final String API_SOURCE = "DEPS_DEV_HASH";
    private static final String OUTCOME_SKIPPED = "skipped";
    private static final String OUTCOME_IDENTIFIED_FROM_DATABASE = "identified_from_database";

    private final DepsDevClient depsDevClient;
    private final ApiCallLogDao apiCallLogDao;
    private final FileDigestIndexDao fileDigestIndexDao;
    private final ResponseIdentificationProperties properties;
    private final Map<HashLookup.Status, Counter> outcomeCounters = new EnumMap<>(HashLookup.Status.class);
    private final Counter skippedCounter;
    private final Counter identifiedFromDatabaseCounter;

    /**
     * @param pkg    package version the body is a file of
     * @param digest digest the relayed body must have
     */
    public record ResponseIdentification(ParsedPackage pkg, ExpectedDigest digest) {}

    public ResponseIdentificationService(DepsDevClient depsDevClient, ApiCallLogDao apiCallLogDao,
            FileDigestIndexDao fileDigestIndexDao, ResponseIdentificationProperties properties,
            MeterRegistry meterRegistry) {
        this.depsDevClient = depsDevClient;
        this.apiCallLogDao = apiCallLogDao;
        this.fileDigestIndexDao = fileDigestIndexDao;
        this.properties = properties;
        for (HashLookup.Status status : HashLookup.Status.values()) {
            String outcome = status == HashLookup.Status.FOUND ? "identified" : status.name().toLowerCase(Locale.ROOT);
            outcomeCounters.put(status, outcomeCounter(meterRegistry, outcome));
        }
        this.skippedCounter = outcomeCounter(meterRegistry, OUTCOME_SKIPPED);
        this.identifiedFromDatabaseCounter = outcomeCounter(meterRegistry, OUTCOME_IDENTIFIED_FROM_DATABASE);
    }

    private static Counter outcomeCounter(MeterRegistry meterRegistry, String outcome) {
        return Counter.builder(Metrics.RESPONSE_IDENTIFICATION_METRIC)
                .description("Identification attempts from the upstream response digest, by outcome")
                .tag(Metrics.TAG_OUTCOME, outcome)
                .register(meterRegistry);
    }

    public boolean isEnabled() {
        return properties.enabled();
    }

    /**
     * @param status  upstream response status
     * @param headers upstream response headers
     * @return the package version the body is a file of, and the digest to verify it against ;
     *         empty when the response is not a package file, announces no usable digest, or
     *         deps.dev does not (or cannot) tell which package it belongs to
     */
    public Optional<ResponseIdentification> identify(HttpStatus status, HttpHeaders headers) {
        if (!properties.enabled()) {
            return Optional.empty();
        }
        Optional<ExpectedDigest> announced = isPackageFile(status, headers)
                ? announcedDigest(headers) : Optional.empty();
        if (announced.isEmpty()) {
            skippedCounter.increment();
            return Optional.empty();
        }
        ExpectedDigest digest = announced.get();
        Optional<DigestEntry> stored = findStored(digest);
        if (stored.isPresent()) {
            identifiedFromDatabaseCounter.increment();
            DigestEntry entry = stored.get();
            return identified(digest, new ParsedPackage(entry.packageName(), entry.version(), entry.ecosystem()));
        }
        HashLookup lookup = depsDevClient.queryByHash(digest.type(), digest.hex());
        logApiCall(lookup);
        outcomeCounters.get(lookup.status()).increment();
        if (lookup.status() != HashLookup.Status.FOUND) {
            LOG.debug("{} {} not identified by deps.dev : {}", digest.type(), digest.hex(), lookup.status());
            return Optional.empty();
        }
        store(digest, lookup);
        return identified(digest, new ParsedPackage(lookup.packageName(), lookup.version(), lookup.ecosystem()));
    }

    private static Optional<ResponseIdentification> identified(ExpectedDigest digest, ParsedPackage pkg) {
        LOG.info("Package identified from upstream {} {} : ecosystem={}, package={}, version={}",
                digest.type(), digest.hex(), pkg.ecosystem(), pkg.packageName(), pkg.version());
        return Optional.of(new ResponseIdentification(pkg, digest));
    }

    // A package file : 200 (not a range, not a 304), not re-encoded on the way (the digest is the
    // one of the stored file), and not a metadata document (JSON, HTML, XML, text).
    private static boolean isPackageFile(HttpStatus status, HttpHeaders headers) {
        if (status != HttpStatus.OK) {
            return false;
        }
        String encoding = headers.getFirst(HttpHeaders.CONTENT_ENCODING);
        if (encoding != null && !encoding.isBlank() && !"identity".equalsIgnoreCase(encoding.trim())) {
            return false;
        }
        String contentType = headers.getFirst(HttpHeaders.CONTENT_TYPE);
        if (contentType == null) {
            return true;
        }
        String type = contentType.toLowerCase(Locale.ROOT);
        return !type.contains("json") && !type.contains("html") && !type.contains("xml") && !type.startsWith("text/");
    }

    private static Optional<ExpectedDigest> announcedDigest(HttpHeaders headers) {
        String sha256 = trimmed(headers.getFirst("X-Checksum-Sha256"));
        if (sha256 != null && HashType.SHA256.isValidHex(sha256)) {
            return Optional.of(new ExpectedDigest(HashType.SHA256, sha256));
        }
        String sha1 = trimmed(headers.getFirst("X-Checksum-Sha1"));
        if (sha1 != null && HashType.SHA1.isValidHex(sha1)) {
            return Optional.of(new ExpectedDigest(HashType.SHA1, sha1));
        }
        // Nexus 3 : ETag is the quoted SHA-1 of the file. Anything else (weak ETag, MD5 as on
        // Maven Central, opaque value) is not a digest the proxy can use.
        String etag = trimmed(headers.getFirst(HttpHeaders.ETAG));
        if (etag != null && etag.length() > 2 && etag.startsWith("\"") && etag.endsWith("\"")) {
            String value = etag.substring(1, etag.length() - 1);
            if (HashType.SHA1.isValidHex(value)) {
                return Optional.of(new ExpectedDigest(HashType.SHA1, value));
            }
        }
        return Optional.empty();
    }

    private static @Nullable String trimmed(@Nullable String value) {
        return value == null ? null : value.trim();
    }

    // The table only spares a deps.dev call : on a database failure, the lookup goes on without it.
    private Optional<DigestEntry> findStored(ExpectedDigest digest) {
        try {
            return fileDigestIndexDao.find(digest.type(), digest.hex());
        } catch (DataAccessException e) {
            LOG.warn("Could not read file_digest_index for {} {}, asking deps.dev : {}",
                    digest.type(), digest.hex(), e.getMessage());
            return Optional.empty();
        }
    }

    private void store(ExpectedDigest digest, HashLookup lookup) {
        try {
            fileDigestIndexDao.save(digest.type(), digest.hex(), lookup.ecosystem(), lookup.packageName(),
                    lookup.version());
        } catch (DataAccessException e) {
            LOG.warn("Could not store {} {} in file_digest_index : {}", digest.type(), digest.hex(), e.getMessage());
        }
    }

    private void logApiCall(HashLookup lookup) {
        String verdict = lookup.status() == HashLookup.Status.UNAVAILABLE ? "ERROR" : lookup.status().name();
        apiCallLogDao.logCall(API_SOURCE, lookup.packageName(), lookup.ecosystem(), lookup.version(), verdict,
                lookup.call());
    }
}
