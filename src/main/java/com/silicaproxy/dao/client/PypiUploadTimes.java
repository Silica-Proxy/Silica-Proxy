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


package com.silicaproxy.dao.client;

import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.net.URI;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Picks the publication date of a PyPI download out of the {@code releases[version]} file list
 * of the PyPI JSON API. A release can receive new files long after it was first published, so
 * the upload time of the requested file (matched by filename) is used ; when it can't be
 * matched, the most recent upload of the release -- never the first file's.
 */
@NullMarked
final class PypiUploadTimes {

    private PypiUploadTimes() {
    }

    static Optional<Instant> publishedAt(List<Map<String, Object>> files, String fullUrl) {
        return requestedFileUploadTime(files, fullUrl).or(() -> latestUploadTime(files));
    }

    private static Optional<Instant> requestedFileUploadTime(List<Map<String, Object>> files, String fullUrl) {
        @Nullable String requestedFilename = requestedFilename(fullUrl);
        if (requestedFilename == null) {
            return Optional.empty();
        }
        for (Map<String, Object> file : files) {
            if (requestedFilename.equals(file.get("filename"))) {
                return uploadTimeOf(file);
            }
        }
        return Optional.empty();
    }

    private static Optional<Instant> latestUploadTime(List<Map<String, Object>> files) {
        Optional<Instant> latest = Optional.empty();
        for (Map<String, Object> file : files) {
            Optional<Instant> uploadTime = uploadTimeOf(file);
            if (uploadTime.isPresent() && (latest.isEmpty() || uploadTime.get().isAfter(latest.get()))) {
                latest = uploadTime;
            }
        }
        return latest;
    }

    // Last path segment of the intercepted download URL (URI.getPath() already percent-decodes
    // it), e.g. "PyYAML-5.3.1-cp39-cp39-win_amd64.whl". Null when there is no usable URL.
    private static @Nullable String requestedFilename(String fullUrl) {
        if (fullUrl.isBlank()) {
            return null;
        }
        try {
            String path = URI.create(fullUrl).getPath();
            if (path == null) {
                return null;
            }
            String filename = path.substring(path.lastIndexOf('/') + 1);
            return filename.isEmpty() ? null : filename;
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    // upload_time_iso_8601 when present, else the legacy upload_time (naive UTC, no offset).
    // A file carrying no parsable time is skipped rather than failing the whole release.
    private static Optional<Instant> uploadTimeOf(Map<String, Object> file) {
        Object uploadTime = file.get("upload_time_iso_8601");
        if (uploadTime == null) {
            uploadTime = file.get("upload_time");
        }
        if (!(uploadTime instanceof String uploadTimeStr)) {
            return Optional.empty();
        }
        String normalized = uploadTimeStr.endsWith("Z") || uploadTimeStr.contains("+")
                ? uploadTimeStr : uploadTimeStr + "Z";
        try {
            return Optional.of(Instant.parse(normalized));
        } catch (DateTimeParseException e) {
            return Optional.empty();
        }
    }
}
