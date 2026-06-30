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


package com.silicaproxy.dao.policy;

import com.silicaproxy.model.entity.ExternalValidationCacheEntry;
import io.micrometer.core.annotation.Timed;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Repository
@NullMarked
public class ExternalValidationCacheDao {

    private final JdbcClient jdbcClient;

    public ExternalValidationCacheDao(JdbcClient jdbcClient) {
        this.jdbcClient = jdbcClient;
    }

    @Timed(value = "silicaproxy.dao.extvalidation.cache.find",
            description = "Duration of external validation cache lookup by service and package",
            percentiles = {0.5, 0.9, 0.95, 0.99})
    public Optional<ExternalValidationCacheEntry> findByServiceAndPackage(
            String serviceName, String packageName, String ecosystem, String packageVersion) {
        return jdbcClient.sql("""
                SELECT id, callback_token, service_name, package_name, ecosystem,
                       package_version, mode, status, reason, created_at, updated_at, expires_at
                FROM external_validation_cache
                WHERE service_name = :serviceName
                  AND package_name = :packageName
                  AND ecosystem    = :ecosystem
                  AND package_version = :packageVersion
                """)
                .param("serviceName", serviceName)
                .param("packageName", packageName)
                .param("ecosystem", ecosystem)
                .param("packageVersion", packageVersion)
                .query(ExternalValidationCacheEntry.class)
                .optional();
    }

    @Timed(value = "silicaproxy.dao.extvalidation.cache.upsert.sync",
            description = "Duration of external validation cache upsert (sync pending)",
            percentiles = {0.5, 0.9, 0.95, 0.99})
    public void upsertPendingSync(
            String serviceName, String packageName, String ecosystem,
            String packageVersion, Instant expiresAt) {
        jdbcClient.sql("""
                INSERT INTO external_validation_cache
                    (callback_token, service_name, package_name, ecosystem, package_version,
                     mode, status, expires_at, updated_at)
                VALUES (NULL, :serviceName, :packageName, :ecosystem, :packageVersion,
                        'SYNC', 'PENDING', :expiresAt, CURRENT_TIMESTAMP)
                ON CONFLICT (service_name, package_name, ecosystem, package_version)
                DO UPDATE SET
                    callback_token  = NULL,
                    mode            = 'SYNC',
                    status          = 'PENDING',
                    reason          = NULL,
                    expires_at      = EXCLUDED.expires_at,
                    updated_at      = CURRENT_TIMESTAMP
                """)
                .param("serviceName", serviceName)
                .param("packageName", packageName)
                .param("ecosystem", ecosystem)
                .param("packageVersion", packageVersion)
                .param("expiresAt", Timestamp.from(expiresAt))
                .update();
    }

    @Timed(value = "silicaproxy.dao.extvalidation.cache.upsert.async",
            description = "Duration of external validation cache upsert (async pending)",
            percentiles = {0.5, 0.9, 0.95, 0.99})
    public void upsertPendingAsync(
            UUID callbackToken, String serviceName, String packageName,
            String ecosystem, String packageVersion, Instant expiresAt) {
        jdbcClient.sql("""
                INSERT INTO external_validation_cache
                    (callback_token, service_name, package_name, ecosystem, package_version,
                     mode, status, expires_at, updated_at)
                VALUES (:token, :serviceName, :packageName, :ecosystem, :packageVersion,
                        'ASYNC', 'PENDING', :expiresAt, CURRENT_TIMESTAMP)
                ON CONFLICT (service_name, package_name, ecosystem, package_version)
                DO UPDATE SET
                    callback_token  = EXCLUDED.callback_token,
                    mode            = 'ASYNC',
                    status          = 'PENDING',
                    reason          = NULL,
                    expires_at      = EXCLUDED.expires_at,
                    updated_at      = CURRENT_TIMESTAMP
                """)
                .param("token", callbackToken)
                .param("serviceName", serviceName)
                .param("packageName", packageName)
                .param("ecosystem", ecosystem)
                .param("packageVersion", packageVersion)
                .param("expiresAt", Timestamp.from(expiresAt))
                .update();
    }

    @Timed(value = "silicaproxy.dao.extvalidation.cache.update.allowed",
            description = "Duration of external validation cache update to ALLOWED by package key",
            percentiles = {0.5, 0.9, 0.95, 0.99})
    public void updateToAllowed(
            String serviceName, String packageName, String ecosystem,
            String packageVersion, @Nullable String reason, Instant cacheExpiresAt) {
        jdbcClient.sql("""
                UPDATE external_validation_cache
                SET status     = 'ALLOWED',
                    reason     = :reason,
                    expires_at = :expiresAt,
                    updated_at = CURRENT_TIMESTAMP
                WHERE service_name   = :serviceName
                  AND package_name   = :packageName
                  AND ecosystem      = :ecosystem
                  AND package_version = :packageVersion
                """)
                .param("serviceName", serviceName)
                .param("packageName", packageName)
                .param("ecosystem", ecosystem)
                .param("packageVersion", packageVersion)
                .param("reason", reason)
                .param("expiresAt", Timestamp.from(cacheExpiresAt))
                .update();
    }

    @Timed(value = "silicaproxy.dao.extvalidation.cache.update.timeout",
            description = "Duration of external validation cache update to TIMEOUT",
            percentiles = {0.5, 0.9, 0.95, 0.99})
    public void updateToTimeout(
            String serviceName, String packageName, String ecosystem, String packageVersion) {
        jdbcClient.sql("""
                UPDATE external_validation_cache
                SET status     = 'TIMEOUT',
                    expires_at = CURRENT_TIMESTAMP,
                    updated_at = CURRENT_TIMESTAMP
                WHERE service_name   = :serviceName
                  AND package_name   = :packageName
                  AND ecosystem      = :ecosystem
                  AND package_version = :packageVersion
                """)
                .param("serviceName", serviceName)
                .param("packageName", packageName)
                .param("ecosystem", ecosystem)
                .param("packageVersion", packageVersion)
                .update();
    }

    @Timed(value = "silicaproxy.dao.extvalidation.cache.update.allowed.token",
            description = "Duration of external validation cache update to ALLOWED by callback token",
            percentiles = {0.5, 0.9, 0.95, 0.99})
    public boolean updateToAllowedByToken(
            UUID callbackToken, @Nullable String reason, Instant cacheExpiresAt) {
        int updated = jdbcClient.sql("""
                UPDATE external_validation_cache
                SET status     = 'ALLOWED',
                    reason     = :reason,
                    expires_at = :expiresAt,
                    updated_at = CURRENT_TIMESTAMP
                WHERE callback_token = :token
                  AND status         = 'PENDING'
                """)
                .param("token", callbackToken)
                .param("reason", reason)
                .param("expiresAt", Timestamp.from(cacheExpiresAt))
                .update();
        return updated > 0;
    }

    @Timed(value = "silicaproxy.dao.extvalidation.cache.find.token",
            description = "Duration of external validation cache lookup by callback token",
            percentiles = {0.5, 0.9, 0.95, 0.99})
    public Optional<ExternalValidationCacheEntry> findByCallbackToken(UUID callbackToken) {
        return jdbcClient.sql("""
                SELECT id, callback_token, service_name, package_name, ecosystem,
                       package_version, mode, status, reason, created_at, updated_at, expires_at
                FROM external_validation_cache
                WHERE callback_token = :token
                """)
                .param("token", callbackToken)
                .query(ExternalValidationCacheEntry.class)
                .optional();
    }

    @Timed(value = "silicaproxy.dao.extvalidation.cache.delete.token",
            description = "Duration of external validation cache delete by callback token",
            percentiles = {0.5, 0.9, 0.95, 0.99})
    public boolean deleteByToken(UUID callbackToken) {
        int deleted = jdbcClient.sql("""
                DELETE FROM external_validation_cache
                WHERE callback_token = :token
                """)
                .param("token", callbackToken)
                .update();
        return deleted > 0;
    }

    @Timed(value = "silicaproxy.dao.extvalidation.cache.expire.pending",
            description = "Duration of external validation pending-to-timeout sweep",
            percentiles = {0.5, 0.9, 0.95, 0.99})
    public int expireTimedOutPending() {
        return jdbcClient.sql("""
                UPDATE external_validation_cache
                SET status     = 'TIMEOUT',
                    updated_at = CURRENT_TIMESTAMP
                WHERE status   = 'PENDING'
                  AND expires_at <= CURRENT_TIMESTAMP
                """)
                .update();
    }

    @Timed(value = "silicaproxy.dao.extvalidation.cache.delete.expired",
            description = "Duration of external validation expired-entries deletion sweep",
            percentiles = {0.5, 0.9, 0.95, 0.99})
    public int deleteExpiredEntries() {
        return jdbcClient.sql("""
                DELETE FROM external_validation_cache
                WHERE status != 'PENDING'
                  AND expires_at <= CURRENT_TIMESTAMP
                """)
                .update();
    }
}
