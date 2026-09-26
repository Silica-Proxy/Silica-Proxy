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

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * PyPI files served by a repository manager must be identified : a wheel whatever its path (its
 * name is self-describing), an sdist behind a known PyPI prefix.
 */
class UrlParserServicePypiLayoutsTest {

    private final UrlParserService urlParserService = new UrlParserService();

    @ParameterizedTest
    @CsvSource({
        // Nexus 3, with and without the "/nexus" context path
        "https://nexus.corp/repository/pypi-proxy/packages/requests/2.31.0/requests-2.31.0-py3-none-any.whl, requests, 2.31.0",
        "https://nexus.corp/repository/pypi-proxy/packages/requests/2.31.0/requests-2.31.0.tar.gz, requests, 2.31.0",
        "https://corp.example/nexus/repository/pypi-group/packages/flask/3.0.0/flask-3.0.0.tar.gz, flask, 3.0.0",
        // Artifactory remote repository ("/packages/packages/…")
        "https://artifactory.corp/artifactory/api/pypi/pypi-remote/packages/packages/ab/cd/ef01/requests-2.31.0-py3-none-any.whl, requests, 2.31.0",
        "https://artifactory.corp/artifactory/api/pypi/pypi-remote/packages/packages/ab/cd/ef01/requests-2.31.0.tar.gz, requests, 2.31.0",
        // devpi
        "https://devpi.corp/root/pypi/+f/abc/def0123/requests-2.31.0-py3-none-any.whl, requests, 2.31.0",
        "https://devpi.corp/root/pypi/+f/abc/def0123/requests-2.31.0.tar.gz, requests, 2.31.0",
        // GitLab, with and without a relative URL root
        "https://gitlab.corp/api/v4/projects/42/packages/pypi/files/0a1b2c3d/acme_lib-1.2.0.tar.gz, acme_lib, 1.2.0",
        "https://corp.example/gitlab/api/v4/projects/42/packages/pypi/files/0a1b2c3d/acme_lib-1.2.0-py3-none-any.whl, acme_lib, 1.2.0",
        // wheel on an arbitrary path
        "https://cdn.corp/wheels/requests-2.31.0-py3-none-any.whl, requests, 2.31.0",
        // build tag and repeated ABI tag behind a prefix
        "https://nexus.corp/repository/pypi-proxy/packages/sentry/22.3.0/sentry-22.3.0-0-py38-none-any.whl, sentry, 22.3.0",
        "https://nexus.corp/repository/pypi-proxy/packages/tf/1.6.0/tensorflow-1.6.0-cp27-cp27m-macosx_10_11_x86_64.whl, tensorflow, 1.6.0"
    })
    void shouldIdentifyFileBehindRepositoryPrefix(String url, String expectedName, String expectedVersion) {
        ParsedPackage parsed = urlParserService.parseUrl(url);

        assertThat(parsed.ecosystem()).isEqualTo("pypi");
        assertThat(parsed.packageName()).isEqualTo(expectedName);
        assertThat(parsed.version()).isEqualTo(expectedVersion);
    }

    @ParameterizedTest
    @ValueSource(strings = {
        // sdist-shaped archive with no PyPI context
        "https://downloads.corp/tools/foo-1.0.tar.gz",
        // ".whl" without a valid Python tag
        "https://cdn.corp/wheels/requests-2.31.0-xx3-none-any.whl",
        // simple index page behind Nexus
        "https://nexus.corp/repository/pypi-proxy/simple/requests/"
    })
    void shouldNotIdentifyWithoutPypiContext(String url) {
        ParsedPackage parsed = urlParserService.parseUrl(url);

        assertThat(parsed.isIdentified()).isFalse();
        assertThat(parsed.ecosystem()).isNotEqualTo("pypi");
    }
}
