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

import com.silicaproxy.model.entity.ExternalValidationVerdictEntry;
import io.micrometer.core.annotation.Timed;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
@NullMarked
public class ExternalValidationVerdictsDao {

    private final JdbcClient jdbcClient;

    public ExternalValidationVerdictsDao(JdbcClient jdbcClient) {
        this.jdbcClient = jdbcClient;
    }

    @Timed(value = "silicaproxy.dao.extvalidation.verdicts.find",
            description = "Duration of external validation verdicts lookup",
            percentiles = {0.5, 0.9, 0.95, 0.99})
    public Optional<ExternalValidationVerdictEntry> findByServiceAndPackage(
            String serviceName, String packageName, String ecosystem, String packageVersion) {
        return jdbcClient.sql("""
                SELECT id, service_name, package_name, ecosystem, package_version, reason, created_at
                FROM external_validation_verdicts
                WHERE service_name   = :serviceName
                  AND package_name   = :packageName
                  AND ecosystem      = :ecosystem
                  AND package_version = :packageVersion
                """)
                .param("serviceName", serviceName)
                .param("packageName", packageName)
                .param("ecosystem", ecosystem)
                .param("packageVersion", packageVersion)
                .query(ExternalValidationVerdictEntry.class)
                .optional();
    }

    @Timed(value = "silicaproxy.dao.extvalidation.verdicts.save",
            description = "Duration of external validation verdict save",
            percentiles = {0.5, 0.9, 0.95, 0.99})
    public void save(
            String serviceName, String packageName, String ecosystem,
            String packageVersion, @Nullable String reason) {
        jdbcClient.sql("""
                INSERT INTO external_validation_verdicts
                    (service_name, package_name, ecosystem, package_version, reason)
                VALUES (:serviceName, :packageName, :ecosystem, :packageVersion, :reason)
                ON CONFLICT (service_name, package_name, ecosystem, package_version)
                DO NOTHING
                """)
                .param("serviceName", serviceName)
                .param("packageName", packageName)
                .param("ecosystem", ecosystem)
                .param("packageVersion", packageVersion)
                .param("reason", reason)
                .update();
    }
}
