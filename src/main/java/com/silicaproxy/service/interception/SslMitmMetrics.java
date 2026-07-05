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
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import org.jspecify.annotations.NullMarked;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;

/**
 * Registers the freshness/expiry gauge for {@link SslMitmService}'s MITM CA certificate,
 * extracted to its own collaborator following the same pattern as the other {@code *Metrics}
 * classes in this codebase. An expired (or silently-about-to-expire) CA breaks TLS interception
 * for every client that trusts it, with no other signal until then.
 */
@Component
@NullMarked
public class SslMitmMetrics {

    public SslMitmMetrics(MeterRegistry meterRegistry, SslMitmService sslMitmService) {
        Gauge.builder(Metrics.CA_CERT_EXPIRY_METRIC, sslMitmService, SslMitmMetrics::secondsUntilExpiry)
                .description("Seconds until the MITM CA certificate expires (NaN if the CA hasn't been "
                        + "initialized yet)")
                .register(meterRegistry);
    }

    private static double secondsUntilExpiry(SslMitmService sslMitmService) {
        Instant notAfter = sslMitmService.getCaCertNotAfter();
        return notAfter != null ? (double) Duration.between(Instant.now(), notAfter).getSeconds() : Double.NaN;
    }
}
