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

import com.silicaproxy.model.dto.HashType;
import org.jspecify.annotations.NullMarked;

/**
 * Digest a relayed body must have, as announced by the upstream response headers : the proxy
 * recomputes it while streaming ({@link ChecksumVerifyingRelay}).
 *
 * @param hex lower-case hex digest
 */
@NullMarked
public record ExpectedDigest(HashType type, String hex) {

    public ExpectedDigest {
        hex = HashType.normalizeHex(hex);
    }
}
