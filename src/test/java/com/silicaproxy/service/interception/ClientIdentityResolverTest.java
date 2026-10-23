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

import com.silicaproxy.model.dto.ClientIdentity;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ClientIdentityResolverTest {

    private static HttpHeaders headers(String... namesAndValues) {
        HttpHeaders headers = new HttpHeaders();
        for (int i = 0; i < namesAndValues.length; i += 2) {
            headers.add(namesAndValues[i], namesAndValues[i + 1]);
        }
        return headers;
    }

    private static String basic(String credentials) {
        return "Basic " + Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void shouldUseTheClientRegisteredByLoomProxyServerForItsLoopbackConnection() {
        ProxyConnectionRegistry registry = new ProxyConnectionRegistry();
        registry.register(51000, new ProxyConnectionRegistry.Peer("10.1.2.3", "ci-runner", true));

        ClientIdentity identity = ClientIdentityResolver.fromCsv("", registry).resolve("127.0.0.1", 51000,
                headers("User-Agent", "npm/10.8.2 node/v22.11.0"));

        assertThat(identity).isEqualTo(new ClientIdentity("10.1.2.3", "npm/10.8.2 node/v22.11.0", "ci-runner"));
    }

    @Test
    void shouldKeepTheRemoteAddressOfAConnectionNotRelayedByLoomProxyServer() {
        ProxyConnectionRegistry registry = new ProxyConnectionRegistry();
        registry.register(51000, new ProxyConnectionRegistry.Peer("10.1.2.3", "ci-runner", true));
        ClientIdentityResolver resolver = ClientIdentityResolver.fromCsv("", registry);

        // Same source port, but not a loopback connection : a client reaching the Tomcat port directly.
        assertThat(resolver.resolve("192.168.1.20", 51000, headers())).isEqualTo(new ClientIdentity("192.168.1.20", null, null));
        assertThat(resolver.resolve("127.0.0.1", 51001, headers())).isEqualTo(new ClientIdentity("127.0.0.1", null, null));
    }

    @Test
    void shouldForgetAConnectionOnceUnregistered() {
        ProxyConnectionRegistry registry = new ProxyConnectionRegistry();
        registry.register(51000, new ProxyConnectionRegistry.Peer("10.1.2.3", null, false));
        registry.unregister(51000);

        assertThat(ClientIdentityResolver.fromCsv("", registry).resolve("127.0.0.1", 51000, headers()).clientIp())
                .isEqualTo("127.0.0.1");
    }

    @Test
    void shouldHonourXForwardedForOfATrustedPeerRelayedInPlainHttpOnly() {
        ProxyConnectionRegistry registry = new ProxyConnectionRegistry();
        registry.register(51000, new ProxyConnectionRegistry.Peer("10.0.0.5", null, false));
        registry.register(51001, new ProxyConnectionRegistry.Peer("10.0.0.5", null, true));
        ClientIdentityResolver resolver = ClientIdentityResolver.fromCsv("10.0.0.0/8", registry);
        HttpHeaders forwarded = headers("X-Forwarded-For", "203.0.113.7");

        assertThat(resolver.resolve("127.0.0.1", 51000, forwarded).clientIp()).isEqualTo("203.0.113.7");
        // Inside a tunnel, X-Forwarded-For was written by the end client itself.
        assertThat(resolver.resolve("127.0.0.1", 51001, forwarded).clientIp()).isEqualTo("10.0.0.5");
    }

    @Test
    void shouldRecognizeAnIpv6LoopbackConnection() {
        ProxyConnectionRegistry registry = new ProxyConnectionRegistry();
        registry.register(51000, new ProxyConnectionRegistry.Peer("10.1.2.3", null, false));

        assertThat(ClientIdentityResolver.fromCsv("", registry).resolve("0:0:0:0:0:0:0:1", 51000, headers()).clientIp())
                .isEqualTo("10.1.2.3");
    }

    @Test
    void shouldPreferTheXSilicaClientHeaderOverTheConnectUser() {
        ProxyConnectionRegistry registry = new ProxyConnectionRegistry();
        registry.register(51000, new ProxyConnectionRegistry.Peer("10.1.2.3", "ci-runner", true));

        assertThat(ClientIdentityResolver.fromCsv("", registry).resolve("127.0.0.1", 51000,
                headers("X-Silica-Client", "project-a")).clientId()).isEqualTo("project-a");
    }

    @Test
    void shouldIgnoreXForwardedForWhenNoProxyIsTrusted() {
        ClientIdentity identity = ClientIdentityResolver.untrusting().resolve("10.1.2.3", 40000,
                headers("X-Forwarded-For", "1.2.3.4"));

        assertThat(identity.clientIp()).isEqualTo("10.1.2.3");
    }

    @Test
    void shouldIgnoreXForwardedForFromAPeerThatIsNotTrusted() {
        ClientIdentity identity = ClientIdentityResolver.fromCsv("10.0.0.0/8", new ProxyConnectionRegistry()).resolve("192.168.1.20", 40000,
                headers("X-Forwarded-For", "1.2.3.4"));

        assertThat(identity.clientIp()).isEqualTo("192.168.1.20");
    }

    @Test
    void shouldTakeTheRightMostUntrustedHopOfXForwardedFor() {
        ClientIdentityResolver resolver = ClientIdentityResolver.fromCsv("10.0.0.0/8, 172.16.0.1", new ProxyConnectionRegistry());

        // "6.6.6.6" was written by the client itself : only the hops appended by trusted proxies count.
        ClientIdentity identity = resolver.resolve("10.0.0.5", 40000, headers(
                "X-Forwarded-For", "6.6.6.6, 203.0.113.7",
                "X-Forwarded-For", "172.16.0.1"));

        assertThat(identity.clientIp()).isEqualTo("203.0.113.7");
    }

    @Test
    void shouldTakeTheLeftMostHopWhenEveryHopIsTrusted() {
        ClientIdentity identity = ClientIdentityResolver.fromCsv("10.0.0.0/8", new ProxyConnectionRegistry()).resolve("10.0.0.5", 40000,
                headers("X-Forwarded-For", "10.9.9.9, 10.0.0.4"));

        assertThat(identity.clientIp()).isEqualTo("10.9.9.9");
    }

    @Test
    void shouldStopAtAHopThatIsNotAnIpLiteral() {
        ClientIdentity identity = ClientIdentityResolver.fromCsv("10.0.0.0/8", new ProxyConnectionRegistry()).resolve("10.0.0.5", 40000,
                headers("X-Forwarded-For", "evil.example.com, 10.0.0.4"));

        assertThat(identity.clientIp()).isEqualTo("10.0.0.4");
    }

    @Test
    void shouldMatchIpv6TrustedRanges() {
        ClientIdentity identity = ClientIdentityResolver.fromCsv("2001:db8::/32", new ProxyConnectionRegistry()).resolve("2001:db8::1", 40000,
                headers("X-Forwarded-For", "[2001:db9::7]:4711"));

        assertThat(identity.clientIp()).isEqualTo("2001:db9:0:0:0:0:0:7");
    }

    @Test
    void shouldRejectAnInvalidTrustedProxiesEntry() {
        assertThatThrownBy(() -> ClientIdentityResolver.fromCsv("proxy.internal", new ProxyConnectionRegistry()))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> ClientIdentityResolver.fromCsv("10.0.0.0/33", new ProxyConnectionRegistry()))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void shouldPreferTheXSilicaClientHeaderAsClientId() {
        ClientIdentity identity = ClientIdentityResolver.untrusting().resolve("10.1.2.3", 40000, headers(
                "X-Silica-Client", "project-a",
                "Proxy-Authorization", basic("alice:secret")));

        assertThat(identity.clientId()).isEqualTo("project-a");
    }

    @Test
    void shouldKeepOnlyTheUsernameOfABasicProxyAuthorization() {
        ClientIdentity identity = ClientIdentityResolver.untrusting().resolve("10.1.2.3", 40000,
                headers("Proxy-Authorization", basic("alice:secret")));

        assertThat(identity.clientId()).isEqualTo("alice");
        assertThat(identity.toString()).doesNotContain("secret");
    }

    @Test
    void shouldIgnoreAProxyAuthorizationWithoutUsername() {
        assertThat(ClientIdentityResolver.untrusting().resolve("10.1.2.3", 40000,
                headers("Proxy-Authorization", "Bearer abc.def")).clientId()).isNull();
        assertThat(ClientIdentityResolver.untrusting().resolve("10.1.2.3", 40000,
                headers("Proxy-Authorization", "Basic !!not-base64!!")).clientId()).isNull();
        assertThat(ClientIdentityResolver.untrusting().resolve("10.1.2.3", 40000,
                headers("Proxy-Authorization", basic("evil\r\nX-Injected: 1:pw"))).clientId()).isNull();
        // Empty user-id, or no colon at all : the value may be a bare secret, never stored.
        assertThat(ClientIdentityResolver.untrusting().resolve("10.1.2.3", 40000,
                headers("Proxy-Authorization", basic(":secret"))).clientId()).isNull();
        assertThat(ClientIdentityResolver.untrusting().resolve("10.1.2.3", 40000,
                headers("Proxy-Authorization", basic("token-without-colon"))).clientId()).isNull();
    }

    @Test
    void shouldTruncateLongHeaderValuesToTheirColumnLength() {
        ClientIdentity identity = ClientIdentityResolver.untrusting().resolve("10.1.2.3", 40000, headers(
                "User-Agent", "a".repeat(2000),
                "X-Silica-Client", "c".repeat(1000)));

        assertThat(identity.userAgent()).hasSize(ClientIdentity.MAX_USER_AGENT_LENGTH);
        assertThat(identity.clientId()).hasSize(ClientIdentity.MAX_CLIENT_ID_LENGTH);
    }

    @Test
    void shouldReplaceControlCharactersAndDropBlankValues() {
        ClientIdentity identity = ClientIdentityResolver.untrusting().resolve("10.1.2.3", 40000, headers(
                "User-Agent", "npm/10\u0000\r\u0085forged",
                "X-Silica-Client", "   "));

        assertThat(identity.userAgent()).isEqualTo("npm/10   forged");
        assertThat(identity.clientId()).isNull();
    }

    @Test
    void shouldRejectMalformedForwardedHopsAndPorts() {
        assertThat(ClientIdentityResolver.parseHop("[::1]garbage")).isNull();
        assertThat(ClientIdentityResolver.parseHop("1.2.3.4:http")).isNull();
        assertThat(ClientIdentityResolver.parseHop("999.1.1.1")).isNull();
        assertThat(ClientIdentityResolver.parseHop("1.2.3")).isNull();
        assertThat(ClientIdentityResolver.parseHop("dead.beef:1")).isNull();
        assertThat(ClientIdentityResolver.parseHop("1.2.3.4:8080")).isNotNull();
        assertThat(ClientIdentityResolver.parseHop("fe80::1%eth0")).isNotNull();
        // A port is a hop decoration, not part of a trusted-proxies entry.
        assertThatThrownBy(() -> ClientIdentityResolver.fromCsv("10.0.0.1:8080", new ProxyConnectionRegistry()))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void shouldNotSplitASurrogatePairWhenTruncating() {
        String userAgent = "a".repeat(ClientIdentity.MAX_USER_AGENT_LENGTH - 1) + "😀";

        assertThat(new ClientIdentity(null, userAgent, null).userAgent())
                .isEqualTo("a".repeat(ClientIdentity.MAX_USER_AGENT_LENGTH - 1));
    }
}
