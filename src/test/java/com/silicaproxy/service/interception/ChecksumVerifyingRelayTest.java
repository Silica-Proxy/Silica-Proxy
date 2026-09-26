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
import com.silicaproxy.service.interception.ChecksumVerifyingRelay.ChecksumMismatchException;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Random;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ChecksumVerifyingRelayTest {

    private static final int BLOCK = ChecksumVerifyingRelay.BLOCK_SIZE;

    private static byte[] body(int size) {
        byte[] body = new byte[size];
        new Random(42).nextBytes(body);
        return body;
    }

    private static ExpectedDigest sha256Of(byte[] body) throws Exception {
        return new ExpectedDigest(HashType.SHA256,
                HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(body)));
    }

    private static ExpectedDigest sha1Of(byte[] body) throws Exception {
        return new ExpectedDigest(HashType.SHA1,
                HexFormat.of().formatHex(MessageDigest.getInstance("SHA-1").digest(body)));
    }

    @Test
    void shouldRelayWholeBodyWhenDigestMatches() throws Exception {
        byte[] body = body(3 * BLOCK + 123);
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        ChecksumVerifyingRelay.relay(new ByteArrayInputStream(body), out, sha256Of(body));

        assertThat(out.toByteArray()).isEqualTo(body);
    }

    @Test
    void shouldRelayBodyOfExactlyTwoBlocks() throws Exception {
        byte[] body = body(2 * BLOCK);
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        ChecksumVerifyingRelay.relay(new ByteArrayInputStream(body), out, sha1Of(body));

        assertThat(out.toByteArray()).isEqualTo(body);
    }

    @Test
    void shouldAcceptUpperCaseExpectedDigest() throws Exception {
        byte[] body = body(100);
        ExpectedDigest expected = new ExpectedDigest(HashType.SHA1, sha1Of(body).hex().toUpperCase());
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        ChecksumVerifyingRelay.relay(new ByteArrayInputStream(body), out, expected);

        assertThat(out.toByteArray()).isEqualTo(body);
    }

    @Test
    void shouldHoldBackTailAndThrowWhenDigestDiffers() throws Exception {
        byte[] announced = body(3 * BLOCK + 123);
        byte[] served = announced.clone();
        served[served.length - 1] ^= 1;
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        assertThatThrownBy(() -> ChecksumVerifyingRelay.relay(new ByteArrayInputStream(served), out, sha256Of(announced)))
                .isInstanceOf(ChecksumMismatchException.class)
                .hasMessageContaining("SHA-256 mismatch");

        // The last full block and the partial one after it are held back.
        assertThat(out.toByteArray()).isEqualTo(Arrays.copyOf(served, 2 * BLOCK));
    }

    @Test
    void shouldWriteNothingWhenBodySmallerThanOneBlockDiffers() throws Exception {
        byte[] served = body(500);
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        assertThatThrownBy(() -> ChecksumVerifyingRelay.relay(new ByteArrayInputStream(served), out,
                sha1Of("something else".getBytes())))
                .isInstanceOf(ChecksumMismatchException.class);

        assertThat(out.size()).isZero();
    }

    @Test
    void shouldRelaySmallBodyWhenDigestMatches() throws Exception {
        byte[] body = body(500);
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        ChecksumVerifyingRelay.relay(new ByteArrayInputStream(body), out, sha1Of(body));

        assertThat(out.toByteArray()).isEqualTo(body);
    }

    @Test
    void shouldRelayEmptyBodyWhenDigestMatches() throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        ChecksumVerifyingRelay.relay(new ByteArrayInputStream(new byte[0]), out, sha1Of(new byte[0]));

        assertThat(out.size()).isZero();
    }

    @Test
    void shouldRejectEmptyBodyWhenDigestIsOfAnotherFile() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        assertThatThrownBy(() -> ChecksumVerifyingRelay.relay(new ByteArrayInputStream(new byte[0]), out,
                sha1Of("lib".getBytes())))
                .isInstanceOf(ChecksumMismatchException.class);
        assertThat(out.size()).isZero();
    }
}
