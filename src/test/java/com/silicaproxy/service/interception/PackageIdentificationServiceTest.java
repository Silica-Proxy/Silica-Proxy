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

import com.silicaproxy.properties.NpmPackumentIndexProperties;
import com.silicaproxy.properties.NpmPackumentIndexProperties.UnidentifiedTarballAction;
import com.silicaproxy.service.interception.PackageIdentificationService.Identification;
import com.silicaproxy.service.interception.PackageIdentificationService.Outcome;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Detection cascade (URL parser → npm metadata detector → packument index) and classification of
 * the request (EVALUATE / BLOCK_UNIDENTIFIED_TARBALL / BYPASS).
 */
class PackageIdentificationServiceTest {

    private static final String FULL_URL = "http://npm.jsr.io/~/11/@jsr/zerun__group-deps/0.1.5.tgz";
    private static final String FORWARD_URL = "https://npm.jsr.io/~/11/@jsr/zerun__group-deps/0.1.5.tgz";

    private final UrlParserService urlParserService = mock(UrlParserService.class);
    private final NpmPackumentIndex npmPackumentIndex = mock(NpmPackumentIndex.class);
    private final HttpHeaders headers = new HttpHeaders();

    private PackageIdentificationService service(UnidentifiedTarballAction action) {
        when(npmPackumentIndex.isEnabled()).thenReturn(true);
        return new PackageIdentificationService(urlParserService, npmPackumentIndex,
                new NpmPackumentIndexProperties(true, 1000, 60, 1024 * 1024, action));
    }

    private void parserReturns(String packageName, String version, String ecosystem) {
        when(urlParserService.parseUrl(anyString())).thenReturn(new ParsedPackage(packageName, version, ecosystem));
    }

    @Test
    void shouldEvaluatePackageIdentifiedByUrlParser() {
        parserReturns("lodash", "4.17.21", "npm");

        Identification id = service(UnidentifiedTarballAction.ALLOW).identify(
                "http://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz", headers);

        assertThat(id.outcome()).isEqualTo(Outcome.EVALUATE);
        assertThat(id.pkg()).isEqualTo(new ParsedPackage("lodash", "4.17.21", "npm"));
        assertThat(id.learnPackument()).isFalse();
        verify(urlParserService, never()).detectNpmMetadata(anyString(), any(HttpHeaders.class));
        verify(npmPackumentIndex, never()).lookup(anyString());
    }

    @Test
    void shouldBypassWithoutLearningWhenNothingIsRecognised() {
        parserReturns("unknown", "unknown", "unknown");
        when(urlParserService.detectNpmMetadata(anyString(), any(HttpHeaders.class))).thenReturn(Optional.empty());

        Identification id = service(UnidentifiedTarballAction.BLOCK).identify(
                "http://unknown-host.example/some/random/path", "https://unknown-host.example/some/random/path", headers);

        assertThat(id.outcome()).isEqualTo(Outcome.BYPASS);
        assertThat(id.pkg().hasEcosystem()).isFalse();
        assertThat(id.learnPackument()).isFalse();
        verify(npmPackumentIndex, never()).lookup(anyString());
    }

    @Test
    void shouldBypassNonNpmMetadataWithoutConsultingNpmLayers() {
        parserReturns("unknown", "unknown", "maven");

        Identification id = service(UnidentifiedTarballAction.BLOCK).identify(
                "http://repo1.maven.org/api/system/version", "https://repo1.maven.org/api/system/version", headers);

        assertThat(id.outcome()).isEqualTo(Outcome.BYPASS);
        assertThat(id.pkg().ecosystem()).isEqualTo("maven");
        assertThat(id.learnPackument()).isFalse();
        verify(urlParserService, never()).detectNpmMetadata(anyString(), any(HttpHeaders.class));
        verify(npmPackumentIndex, never()).lookup(anyString());
    }

    // Moved from ProxyControllerTest.shouldTagBypassWithNpmWhenMetadataDetectorRecognisesUnknownHost :
    // the detector is fed the intercepted URL and the client headers.
    @Test
    void shouldTagBypassWithNpmAndLearnPackumentWhenMetadataDetectorRecognisesUnknownHost() {
        parserReturns("unknown", "unknown", "unknown");
        when(urlParserService.detectNpmMetadata(anyString(), any(HttpHeaders.class)))
                .thenReturn(Optional.of(new ParsedPackage("@jsr/zerun__group-deps", "unknown", "npm")));
        when(npmPackumentIndex.lookup(anyString())).thenReturn(Optional.empty());
        headers.add("Accept", "application/vnd.npm.install-v1+json");

        Identification id = service(UnidentifiedTarballAction.ALLOW).identify(
                "http://npm.jsr.io/@jsr/zerun__group-deps", "https://npm.jsr.io/@jsr/zerun__group-deps", headers);

        verify(urlParserService).detectNpmMetadata(eq("http://npm.jsr.io/@jsr/zerun__group-deps"), eq(headers));
        assertThat(id.outcome()).isEqualTo(Outcome.BYPASS);
        assertThat(id.pkg()).isEqualTo(new ParsedPackage("@jsr/zerun__group-deps", "unknown", "npm"));
        assertThat(id.learnPackument()).isTrue();
    }

    @Test
    void shouldNotLearnPackumentWhenIndexIsDisabled() {
        parserReturns("unknown", "unknown", "npm");
        when(npmPackumentIndex.lookup(anyString())).thenReturn(Optional.empty());
        PackageIdentificationService service = service(UnidentifiedTarballAction.ALLOW);
        when(npmPackumentIndex.isEnabled()).thenReturn(false);

        Identification id = service.identify("http://registry.npmjs.org/express", "https://registry.npmjs.org/express", headers);

        assertThat(id.outcome()).isEqualTo(Outcome.BYPASS);
        assertThat(id.learnPackument()).isFalse();
    }

    @Test
    void shouldEvaluateTarballResolvedByPackumentIndexUsingForwardUrl() {
        parserReturns("unknown", "unknown", "unknown");
        when(urlParserService.detectNpmMetadata(anyString(), any(HttpHeaders.class)))
                .thenReturn(Optional.of(ParsedPackage.unknown("npm")));
        when(npmPackumentIndex.lookup(FORWARD_URL))
                .thenReturn(Optional.of(new ParsedPackage("@jsr/zerun__group-deps", "0.1.5", "npm")));

        Identification id = service(UnidentifiedTarballAction.BLOCK).identify(FULL_URL, FORWARD_URL, headers);

        verify(urlParserService).parseUrl(FULL_URL);
        verify(npmPackumentIndex).lookup(FORWARD_URL);
        assertThat(id.outcome()).isEqualTo(Outcome.EVALUATE);
        assertThat(id.pkg()).isEqualTo(new ParsedPackage("@jsr/zerun__group-deps", "0.1.5", "npm"));
        assertThat(id.learnPackument()).isFalse();
    }

    // Moved from NpmPackumentIndexPersistenceTest.shouldExposeUnidentifiedTarballAction : the
    // unidentified-tarball-action policy now lives here.
    @Test
    void shouldBlockUnidentifiedNpmTarballWhenPolicyIsBlock() {
        parserReturns("unknown", "unknown", "npm");
        when(npmPackumentIndex.lookup(anyString())).thenReturn(Optional.empty());

        Identification id = service(UnidentifiedTarballAction.BLOCK).identify(
                "http://registry.corp.example/pool/abc/internal-lib.tgz",
                "https://registry.corp.example/pool/abc/internal-lib.tgz", headers);

        assertThat(id.outcome()).isEqualTo(Outcome.BLOCK_UNIDENTIFIED_TARBALL);
        assertThat(id.pkg().ecosystem()).isEqualTo("npm");
        assertThat(id.learnPackument()).isFalse();
    }

    @Test
    void shouldBypassUnidentifiedNpmTarballWhenPolicyIsAllow() {
        parserReturns("unknown", "unknown", "npm");
        when(npmPackumentIndex.lookup(anyString())).thenReturn(Optional.empty());

        Identification id = service(UnidentifiedTarballAction.ALLOW).identify(
                "http://registry.corp.example/pool/abc/internal-lib.tgz",
                "https://registry.corp.example/pool/abc/internal-lib.tgz", headers);

        assertThat(id.outcome()).isEqualTo(Outcome.BYPASS);
        assertThat(id.learnPackument()).isTrue();
    }

    @Test
    void shouldBypassNpmMetadataEvenWhenBlockingUnidentifiedTarballs() {
        parserReturns("unknown", "unknown", "npm");
        when(npmPackumentIndex.lookup(anyString())).thenReturn(Optional.empty());

        Identification id = service(UnidentifiedTarballAction.BLOCK).identify(
                "http://registry.corp.example/internal-lib", "https://registry.corp.example/internal-lib", headers);

        assertThat(id.outcome()).isEqualTo(Outcome.BYPASS);
        assertThat(id.learnPackument()).isTrue();
    }
}
