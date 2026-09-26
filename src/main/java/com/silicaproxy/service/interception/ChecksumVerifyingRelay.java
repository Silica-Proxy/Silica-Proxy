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

import org.jspecify.annotations.NullMarked;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * Relays a body while recomputing its digest, and never lets the client receive the whole of a
 * body whose digest differs from the one announced : the tail of the body (the last full block
 * plus whatever follows it, i.e. at least {@value #BLOCK_SIZE} bytes, or the whole body when it is
 * smaller) is held back until the end of the stream and only written once the digest matches.
 * On a mismatch the client is left with a truncated body, which fails the download.
 */
@NullMarked
public final class ChecksumVerifyingRelay {

    static final int BLOCK_SIZE = 16 * 1024;

    private ChecksumVerifyingRelay() {
    }

    /** Thrown once the whole body was read and its digest is not the expected one. */
    public static final class ChecksumMismatchException extends IOException {

        private static final long serialVersionUID = 1L;

        public ChecksumMismatchException(ExpectedDigest expected, String actualHex) {
            super(expected.type().algorithm() + " mismatch : upstream announced " + expected.hex()
                    + ", body digest is " + actualHex);
        }
    }

    /**
     * Copies {@code in} to {@code out}, holding back the tail of the body until its digest is
     * checked. Neither stream is closed.
     *
     * @throws ChecksumMismatchException when the digest of the body is not {@code expected} ;
     *                                   the tail was not written
     */
    public static void relay(InputStream in, OutputStream out, ExpectedDigest expected) throws IOException {
        MessageDigest digest = newDigest(expected);
        byte[] pending = new byte[BLOCK_SIZE];
        byte[] next = new byte[BLOCK_SIZE];
        int pendingLength = in.readNBytes(pending, 0, BLOCK_SIZE);
        digest.update(pending, 0, pendingLength);
        int nextLength = pendingLength == BLOCK_SIZE ? in.readNBytes(next, 0, BLOCK_SIZE) : 0;
        // readNBytes only returns a partial block at the end of the stream : while the next block
        // is full, the pending one is not part of the tail and can be written.
        while (nextLength == BLOCK_SIZE) {
            digest.update(next, 0, nextLength);
            out.write(pending, 0, pendingLength);
            byte[] swap = pending;
            pending = next;
            next = swap;
            nextLength = in.readNBytes(next, 0, BLOCK_SIZE);
        }
        digest.update(next, 0, nextLength);

        String actual = HexFormat.of().formatHex(digest.digest());
        if (!actual.equals(expected.hex())) {
            throw new ChecksumMismatchException(expected, actual);
        }
        out.write(pending, 0, pendingLength);
        out.write(next, 0, nextLength);
        out.flush();
    }

    private static MessageDigest newDigest(ExpectedDigest expected) {
        try {
            return MessageDigest.getInstance(expected.type().algorithm());
        } catch (NoSuchAlgorithmException e) {
            // SHA-1 and SHA-256 are mandatory in every Java platform implementation.
            throw new IllegalStateException(e);
        }
    }
}
