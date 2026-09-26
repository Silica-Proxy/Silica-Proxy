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
import com.silicaproxy.model.dto.ApiCheckResult;
import com.silicaproxy.model.dto.HashLookup;
import com.silicaproxy.model.dto.HashType;
import com.silicaproxy.properties.ResponseIdentificationProperties;
import com.silicaproxy.service.interception.ResponseIdentificationService.ResponseIdentification;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ResponseIdentificationServiceTest {

    private static final String SHA1 = "7cf2726fdcfbc8610f9a71fb3ed639871f315340";
    private static final String SHA256 = "8a3c1b0f5e2d4c6b9a7f1e3d5c7b9a1f3e5d7c9b1a3f5e7d9c1b3a5f7e9d1c3b";
    private static final ApiCheckResult CALL = new ApiCheckResult(false, 0, 200, 5, null);

    private final DepsDevClient depsDevClient = mock(DepsDevClient.class);
    private final ApiCallLogDao apiCallLogDao = mock(ApiCallLogDao.class);
    private final FileDigestIndexDao fileDigestIndexDao = mock(FileDigestIndexDao.class);
    private final SimpleMeterRegistry meterRegistry = new SimpleMeterRegistry();
    private final ResponseIdentificationService service = service(true);

    private ResponseIdentificationService service(boolean enabled) {
        return new ResponseIdentificationService(depsDevClient, apiCallLogDao, fileDigestIndexDao,
                new ResponseIdentificationProperties(enabled), meterRegistry);
    }

    private static HttpHeaders headers(String... namesAndValues) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(org.springframework.http.MediaType.APPLICATION_OCTET_STREAM);
        for (int i = 0; i < namesAndValues.length; i += 2) {
            headers.set(namesAndValues[i], namesAndValues[i + 1]);
        }
        return headers;
    }

    private void depsDevFinds(HashType type, String hex) {
        when(depsDevClient.queryByHash(type, hex))
                .thenReturn(HashLookup.found("maven", "org.slf4j:slf4j-api", "2.0.9", CALL));
    }

    private double outcomeCount(String outcome) {
        return meterRegistry.get(Metrics.RESPONSE_IDENTIFICATION_METRIC).tag(Metrics.TAG_OUTCOME, outcome)
                .counter().count();
    }

    @Test
    void shouldIdentifyFromSha1Header() {
        depsDevFinds(HashType.SHA1, SHA1);

        Optional<ResponseIdentification> found = service.identify(HttpStatus.OK, headers("X-Checksum-Sha1", SHA1));

        assertThat(found).get().extracting(ResponseIdentification::pkg)
                .isEqualTo(new ParsedPackage("org.slf4j:slf4j-api", "2.0.9", "maven"));
        assertThat(found.get().digest()).isEqualTo(new ExpectedDigest(HashType.SHA1, SHA1));
        assertThat(outcomeCount("identified")).isEqualTo(1.0);
        verify(apiCallLogDao).logCall("DEPS_DEV_HASH", "org.slf4j:slf4j-api", "maven", "2.0.9", "FOUND", CALL);
    }

    @Test
    void shouldPreferSha256OverSha1() {
        depsDevFinds(HashType.SHA256, SHA256);

        Optional<ResponseIdentification> found = service.identify(HttpStatus.OK,
                headers("X-Checksum-Sha1", SHA1, "X-Checksum-Sha256", SHA256.toUpperCase()));

        assertThat(found).get().extracting(ResponseIdentification::digest)
                .isEqualTo(new ExpectedDigest(HashType.SHA256, SHA256));
        verify(depsDevClient, never()).queryByHash(eq(HashType.SHA1), anyString());
    }

    @Test
    void shouldFallBackToSha1WhenSha256HeaderIsMalformed() {
        depsDevFinds(HashType.SHA1, SHA1);

        assertThat(service.identify(HttpStatus.OK, headers("X-Checksum-Sha256", "abc", "X-Checksum-Sha1", SHA1)))
                .get().extracting(ResponseIdentification::digest).isEqualTo(new ExpectedDigest(HashType.SHA1, SHA1));
    }

    @Test
    void shouldIdentifyFromNexusEtag() {
        depsDevFinds(HashType.SHA1, SHA1);

        assertThat(service.identify(HttpStatus.OK, headers("ETag", "\"" + SHA1 + "\"")))
                .get().extracting(ResponseIdentification::digest).isEqualTo(new ExpectedDigest(HashType.SHA1, SHA1));
    }

    @Test
    void shouldIgnoreEtagThatIsNotAQuotedSha1() {
        // Maven Central : quoted MD5 ; weak ETag ; unquoted value ; opaque value of the right length.
        for (String etag : new String[] {"\"45630e54b0f0ac2b3c80462515ad8fda\"", "W/\"" + SHA1 + "\"", SHA1,
                "\"" + "z".repeat(40) + "\""}) {
            assertThat(service.identify(HttpStatus.OK, headers("ETag", etag))).as(etag).isEmpty();
        }
        verify(depsDevClient, never()).queryByHash(any(), anyString());
        assertThat(outcomeCount("skipped")).isEqualTo(4.0);
    }

    @Test
    void shouldNotUseContentDispositionAlone() {
        assertThat(service.identify(HttpStatus.OK,
                headers("Content-Disposition", "attachment; filename=\"slf4j-api-2.0.9.jar\""))).isEmpty();
        verify(depsDevClient, never()).queryByHash(any(), anyString());
    }

    @Test
    void shouldNotIdentifyAmbiguousNotFoundOrUnavailableDigests() {
        String ambiguous = "a".repeat(40);
        String unknown = "b".repeat(40);
        String unavailable = "c".repeat(40);
        when(depsDevClient.queryByHash(HashType.SHA1, ambiguous)).thenReturn(HashLookup.ambiguous(CALL));
        when(depsDevClient.queryByHash(HashType.SHA1, unknown)).thenReturn(HashLookup.notFound(CALL));
        when(depsDevClient.queryByHash(HashType.SHA1, unavailable))
                .thenReturn(HashLookup.unavailable(new ApiCheckResult(false, 0, 503, 5, "down")));

        assertThat(service.identify(HttpStatus.OK, headers("X-Checksum-Sha1", ambiguous))).isEmpty();
        assertThat(service.identify(HttpStatus.OK, headers("X-Checksum-Sha1", unknown))).isEmpty();
        assertThat(service.identify(HttpStatus.OK, headers("X-Checksum-Sha1", unavailable))).isEmpty();

        assertThat(outcomeCount("ambiguous")).isEqualTo(1.0);
        assertThat(outcomeCount("not_found")).isEqualTo(1.0);
        assertThat(outcomeCount("unavailable")).isEqualTo(1.0);
        verify(apiCallLogDao).logCall(eq("DEPS_DEV_HASH"), anyString(), anyString(), anyString(), eq("ERROR"), any());
    }

    @Test
    void shouldNotAttemptOnNonPackageResponses() {
        assertThat(service.identify(HttpStatus.NOT_FOUND, headers("X-Checksum-Sha1", SHA1))).isEmpty();
        assertThat(service.identify(HttpStatus.PARTIAL_CONTENT, headers("X-Checksum-Sha1", SHA1))).isEmpty();
        assertThat(service.identify(HttpStatus.NOT_MODIFIED, headers("X-Checksum-Sha1", SHA1))).isEmpty();
        assertThat(service.identify(HttpStatus.OK,
                headers("X-Checksum-Sha1", SHA1, "Content-Type", "application/json"))).isEmpty();
        assertThat(service.identify(HttpStatus.OK,
                headers("X-Checksum-Sha1", SHA1, "Content-Type", "text/xml"))).isEmpty();
        assertThat(service.identify(HttpStatus.OK,
                headers("X-Checksum-Sha1", SHA1, "Content-Type", "text/html; charset=utf-8"))).isEmpty();
        assertThat(service.identify(HttpStatus.OK,
                headers("X-Checksum-Sha1", SHA1, "Content-Encoding", "gzip"))).isEmpty();

        verify(depsDevClient, never()).queryByHash(any(), anyString());
    }

    @Test
    void shouldAttemptWithIdentityEncodingOrWithoutContentType() {
        depsDevFinds(HashType.SHA1, SHA1);
        HttpHeaders noContentType = new HttpHeaders();
        noContentType.set("X-Checksum-Sha1", SHA1);

        assertThat(service.identify(HttpStatus.OK, headers("X-Checksum-Sha1", SHA1, "Content-Encoding", "identity")))
                .isPresent();
        assertThat(service.identify(HttpStatus.OK, noContentType)).isPresent();
    }

    @Test
    void shouldIdentifyFromDatabaseWithoutCallingDepsDev() {
        when(fileDigestIndexDao.find(HashType.SHA1, SHA1))
                .thenReturn(Optional.of(new DigestEntry("maven", "org.slf4j:slf4j-api", "2.0.9")));

        Optional<ResponseIdentification> found = service.identify(HttpStatus.OK,
                headers("X-Checksum-Sha1", SHA1.toUpperCase()));

        assertThat(found).get().extracting(ResponseIdentification::pkg)
                .isEqualTo(new ParsedPackage("org.slf4j:slf4j-api", "2.0.9", "maven"));
        assertThat(found.get().digest()).isEqualTo(new ExpectedDigest(HashType.SHA1, SHA1));
        assertThat(outcomeCount("identified_from_database")).isEqualTo(1.0);
        verify(depsDevClient, never()).queryByHash(any(), anyString());
        verify(apiCallLogDao, never()).logCall(anyString(), anyString(), anyString(), anyString(), anyString(), any());
        verify(fileDigestIndexDao, never()).save(any(), anyString(), anyString(), anyString(), anyString());
    }

    @Test
    void shouldStoreDigestIdentifiedByDepsDev() {
        depsDevFinds(HashType.SHA1, SHA1);

        service.identify(HttpStatus.OK, headers("X-Checksum-Sha1", SHA1));

        verify(fileDigestIndexDao).find(HashType.SHA1, SHA1);
        verify(fileDigestIndexDao).save(HashType.SHA1, SHA1, "maven", "org.slf4j:slf4j-api", "2.0.9");
    }

    @Test
    void shouldNotStoreAndQueryAgainWhenNotIdentified() {
        String ambiguous = "a".repeat(40);
        String unknown = "b".repeat(40);
        String unavailable = "c".repeat(40);
        when(depsDevClient.queryByHash(HashType.SHA1, ambiguous)).thenReturn(HashLookup.ambiguous(CALL));
        when(depsDevClient.queryByHash(HashType.SHA1, unknown)).thenReturn(HashLookup.notFound(CALL));
        when(depsDevClient.queryByHash(HashType.SHA1, unavailable))
                .thenReturn(HashLookup.unavailable(new ApiCheckResult(false, 0, 0, 5, "timeout")));

        for (String digest : new String[] {ambiguous, unknown, unavailable}) {
            service.identify(HttpStatus.OK, headers("X-Checksum-Sha1", digest));
            service.identify(HttpStatus.OK, headers("X-Checksum-Sha1", digest));
            verify(depsDevClient, times(2)).queryByHash(HashType.SHA1, digest);
        }
        verify(fileDigestIndexDao, never()).save(any(), anyString(), anyString(), anyString(), anyString());
    }

    @Test
    void shouldAskDepsDevWhenDatabaseCannotBeRead() {
        when(fileDigestIndexDao.find(any(), anyString())).thenThrow(new DataAccessResourceFailureException("down"));
        depsDevFinds(HashType.SHA1, SHA1);

        assertThat(service.identify(HttpStatus.OK, headers("X-Checksum-Sha1", SHA1))).isPresent();
        verify(depsDevClient).queryByHash(HashType.SHA1, SHA1);
    }

    @Test
    void shouldStillIdentifyWhenDigestCannotBeStored() {
        depsDevFinds(HashType.SHA1, SHA1);
        doThrow(new DataAccessResourceFailureException("down")).when(fileDigestIndexDao)
                .save(any(), anyString(), anyString(), anyString(), anyString());

        assertThat(service.identify(HttpStatus.OK, headers("X-Checksum-Sha1", SHA1))).isPresent();
    }

    @Test
    void shouldDoNothingWhenDisabled() {
        ResponseIdentificationService disabled = service(false);

        assertThat(disabled.isEnabled()).isFalse();
        assertThat(disabled.identify(HttpStatus.OK, headers("X-Checksum-Sha1", SHA1))).isEmpty();
        verify(depsDevClient, never()).queryByHash(any(), anyString());
        verify(fileDigestIndexDao, never()).find(any(), anyString());
    }
}
