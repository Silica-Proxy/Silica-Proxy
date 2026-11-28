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

package com.silicaproxy.service.decision;

import com.silicaproxy.dao.policy.ExternalValidationCacheDao;
import com.silicaproxy.dao.policy.ExternalValidationVerdictsDao;
import com.silicaproxy.dao.policy.MetadataCacheDao;
import com.silicaproxy.service.interception.ParsedPackage;
import com.silicaproxy.service.interception.PypiNames;
import org.jspecify.annotations.NullMarked;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Locale;
import java.util.Set;

/**
 * Operator-triggered eviction of everything the external validation chain remembers about one
 * package version, so that the next request calls the external services (sync and async) again :
 * <ul>
 *   <li>{@code external_validation_cache} : PENDING / ALLOWED / TIMEOUT state of every service ;</li>
 *   <li>{@code external_validation_verdicts} : permanent BLOCKED verdicts ;</li>
 *   <li>{@code api_cache} : cached ALLOW of the version (written with source
 *       EXTERNAL_VALIDATION_CHAIN when the chain allowed it). Like a BLOCKED callback, only an ALLOW
 *       is dropped : any cached ALLOW is read before the external services and would bypass them,
 *       while a cached BLOCK (OSV, deprecation...) stays correct whatever they answer.</li>
 * </ul>
 */
@Service
@NullMarked
public class ExternalValidationCacheEvictionService {

    private static final Logger LOG = LoggerFactory.getLogger(ExternalValidationCacheEvictionService.class);

    private static final Set<String> ECOSYSTEMS = Set.of(ParsedPackage.NPM, ParsedPackage.PYPI, ParsedPackage.MAVEN);

    private final ExternalValidationCacheDao cacheDao;
    private final ExternalValidationVerdictsDao verdictsDao;
    private final MetadataCacheDao metadataCacheDao;

    public ExternalValidationCacheEvictionService(ExternalValidationCacheDao cacheDao,
            ExternalValidationVerdictsDao verdictsDao, MetadataCacheDao metadataCacheDao) {
        this.cacheDao = cacheDao;
        this.verdictsDao = verdictsDao;
        this.metadataCacheDao = metadataCacheDao;
    }

    public record EvictionResult(int externalValidationCache, int externalValidationVerdicts, int apiCache) {
    }

    /**
     * @throws IllegalArgumentException when a parameter is blank or the ecosystem is not supported
     */
    @Transactional
    public EvictionResult evict(String ecosystem, String packageName, String version) {
        if (ecosystem.isBlank() || packageName.isBlank() || version.isBlank()) {
            throw new IllegalArgumentException("ecosystem, packageName and version must not be blank");
        }
        String eco = ecosystem.trim().toLowerCase(Locale.ROOT);
        if (!ECOSYSTEMS.contains(eco)) {
            throw new IllegalArgumentException("Unsupported ecosystem : " + sanitize(ecosystem));
        }
        // Same keys as the proxy writes : ParsedPackage normalizes PyPI names (PEP 503).
        String name = ParsedPackage.PYPI.equals(eco) ? PypiNames.normalize(packageName.trim()) : packageName.trim();
        String ver = version.trim();

        EvictionResult result = new EvictionResult(
                cacheDao.deleteByPackage(name, eco, ver),
                verdictsDao.deleteByPackage(name, eco, ver),
                metadataCacheDao.deleteApiCacheAllow(name, eco, ver));
        LOG.info("External validation cache evicted for {}/{}@{} : {} cache entries, {} verdicts, {} api_cache ALLOW",
                eco, sanitize(name), sanitize(ver), result.externalValidationCache(),
                result.externalValidationVerdicts(), result.apiCache());
        return result;
    }

    private static String sanitize(String s) {
        return s.replace('\n', ' ').replace('\r', ' ');
    }
}
