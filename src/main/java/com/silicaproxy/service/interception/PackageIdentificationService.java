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
import org.jspecify.annotations.NullMarked;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Service;

/**
 * Answers "which package is this request for, and must it be evaluated ?" for {@code ProxyController},
 * before any security decision.
 *
 * <p>Three detection layers, each consulted only while the previous one left a gap : (1)
 * {@link UrlParserService#parseUrl} : known host → direct parser, else structural fallback by path
 * pattern for private registries (Verdaccio, devpi, artifact repositories, repo.spring.io…) ; (2)
 * {@link UrlParserService#detectNpmMetadata}, when no ecosystem was found : an npm-only hint from
 * the client headers (Accept / User-Agent / npm-* headers) or from an unambiguous npm registry path
 * shape. It never yields a version : it only tags metadata traffic (packuments, dist-tags, search)
 * with the right ecosystem so bypass logs and metrics stop reporting it as "unknown" ; (3)
 * {@link NpmPackumentIndex#lookup}, for an npm request without version : a tarball whose URL layout
 * the parser does not know (npm.jsr.io, Artifactory prefixes…) but that a relayed packument
 * declared in {@code dist.tarball}.
 *
 * <p>A request left unidentified bypasses the security check, except an npm {@code .tgz} tarball
 * when {@code npm-packument-index.unidentified-tarball-action=BLOCK}.
 */
@Service
@NullMarked
public class PackageIdentificationService {

    private static final Logger LOG = LoggerFactory.getLogger(PackageIdentificationService.class);

    private final UrlParserService urlParserService;
    private final NpmPackumentIndex npmPackumentIndex;
    private final boolean blockUnidentifiedTarballs;

    /** What the proxy must do with the request. */
    public enum Outcome {
        /** Package version identified : ask {@code SecurityService} for a decision. */
        EVALUATE,
        /** npm tarball identified neither by its URL nor by a relayed packument, and policy says BLOCK. */
        BLOCK_UNIDENTIFIED_TARBALL,
        /** Not a package version (metadata, index, unknown resource) : relay without a security check. */
        BYPASS
    }

    /**
     * @param pkg            what could be identified, {@link ParsedPackage#UNKNOWN} parts included
     * @param learnPackument whether the relayed response may be an npm packument whose tarball URLs
     *                       must be indexed on the way
     */
    public record Identification(ParsedPackage pkg, Outcome outcome, boolean learnPackument) {}

    public PackageIdentificationService(UrlParserService urlParserService, NpmPackumentIndex npmPackumentIndex,
            NpmPackumentIndexProperties npmPackumentIndexProperties) {
        this.urlParserService = urlParserService;
        this.npmPackumentIndex = npmPackumentIndex;
        this.blockUnidentifiedTarballs =
                npmPackumentIndexProperties.unidentifiedTarballAction() == UnidentifiedTarballAction.BLOCK;
    }

    /**
     * @param fullUrl    URL as intercepted, read by the parser and the npm metadata detector
     * @param forwardUrl URL relayed upstream (https-upgraded), the one packuments declare and the
     *                   index is keyed on
     * @param headers    client request headers, read by the npm metadata detector
     */
    public Identification identify(String fullUrl, String forwardUrl, HttpHeaders headers) {
        ParsedPackage parsed = urlParserService.parseUrl(fullUrl);
        if (!parsed.hasEcosystem()) {
            parsed = urlParserService.detectNpmMetadata(fullUrl, headers).orElse(parsed);
        }
        boolean npm = "npm".equals(parsed.ecosystem());
        if (npm && ParsedPackage.UNKNOWN.equals(parsed.version())) {
            parsed = npmPackumentIndex.lookup(forwardUrl).orElse(parsed);
        }

        if (parsed.isIdentified()) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Package detected : ecosystem={}, package={}, version={}",
                        parsed.ecosystem(), parsed.packageName(), parsed.version());
            }
            return new Identification(parsed, Outcome.EVALUATE, false);
        }
        if (npm && ParsedPackage.UNKNOWN.equals(parsed.version())
                && blockUnidentifiedTarballs
                && UrlParserService.hasNpmTarballExtension(forwardUrl)) {
            return new Identification(parsed, Outcome.BLOCK_UNIDENTIFIED_TARBALL, false);
        }
        // Any npm metadata response may be a packument : learn its tarball URLs on the way.
        return new Identification(parsed, Outcome.BYPASS, npm && npmPackumentIndex.isEnabled());
    }
}
