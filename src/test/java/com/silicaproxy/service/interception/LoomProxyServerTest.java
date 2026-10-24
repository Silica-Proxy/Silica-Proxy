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

import com.silicaproxy.BaseIntegrationTest;
import com.silicaproxy.model.dto.ClientIdentity;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.Socket;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;

// Reduced from the 30s/60s production defaults so the idle-timeout test below runs in ~1s
// instead of 30s. A distinct property set gives this class its own (not shared) Spring context,
// so it doesn't affect the timeouts other test classes see.
@TestPropertySource(properties = {
        "silicaproxy.proxy.header-read-timeout-seconds=1",
        "silicaproxy.proxy.relay-idle-timeout-seconds=1"
})
class LoomProxyServerTest extends BaseIntegrationTest {

    private final LoomProxyServer loomProxyServer;

    @Autowired
    private ProxyConnectionRegistry connectionRegistry;

    @MockitoSpyBean
    private ClientIdentityResolver clientIdentityResolver;

    @Autowired
    LoomProxyServerTest(LoomProxyServer loomProxyServer) {
        this.loomProxyServer = loomProxyServer;
    }

    @Test
    void shouldEstablishConnectTunnelSuccessfully() throws Exception {
        // 1. Stub a path in WireMock
        wireMock.stubFor(get(urlEqualTo("/hello-connect"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "text/plain")
                        .withBody("Hello from WireMock Tunnel!")));

        int wiremockPort = wireMock.port();

        // 2. Open a MITM tunnel through the LoomProxyServer
        try (Socket socket = new Socket("127.0.0.1", loomProxyServer.getProxyPort())) {
            SSLSocket sslSocket = openMitmTunnel(socket, "");

            OutputStream sslOut = sslSocket.getOutputStream();
            BufferedReader sslIn = new BufferedReader(new InputStreamReader(sslSocket.getInputStream(), StandardCharsets.UTF_8));

            // 3. Send a proxied GET with an absolute URL through the decrypted channel
            String getRequest = "GET http://127.0.0.1:" + wiremockPort + "/hello-connect HTTP/1.1\r\n"
                    + "Host: 127.0.0.1:" + wiremockPort + "\r\n"
                    + "Connection: close\r\n\r\n";
            sslOut.write(getRequest.getBytes(StandardCharsets.UTF_8));
            sslOut.flush();

            // 4. Assert target response
            StringBuilder targetResponse = new StringBuilder();
            String line;
            while ((line = sslIn.readLine()) != null) {
                targetResponse.append(line).append("\n");
            }

            assertThat(targetResponse.toString()).contains("200");
            assertThat(targetResponse.toString()).contains("Hello from WireMock Tunnel!");
        }
    }

    @Test
    void shouldResolveTheClientOfTheConnectForEveryRequestOfTheTunnel() throws Exception {
        wireMock.stubFor(get(urlEqualTo("/hello-identity")).willReturn(aResponse().withStatus(200).withBody("identity-response-end")));
        List<ClientIdentity> resolved = new CopyOnWriteArrayList<>();
        doAnswer(invocation -> {
            ClientIdentity identity = (ClientIdentity) invocation.callRealMethod();
            resolved.add(identity);
            return identity;
        }).when(clientIdentityResolver).resolve(anyString(), anyInt(), any(HttpHeaders.class));
        int wiremockPort = wireMock.port();
        String credentials = Base64.getEncoder().encodeToString("ci-runner:s3cret".getBytes(StandardCharsets.UTF_8));
        String request = "GET http://127.0.0.1:" + wiremockPort + "/hello-identity HTTP/1.1\r\n"
                + "Host: 127.0.0.1:" + wiremockPort + "\r\n"
                + "User-Agent: pip/24.2\r\n";

        try (Socket socket = new Socket("127.0.0.1", loomProxyServer.getProxyPort())) {
            SSLSocket sslSocket = openMitmTunnel(socket, "Proxy-Authorization: Basic " + credentials + "\r\n");
            OutputStream sslOut = sslSocket.getOutputStream();
            InputStream sslIn = sslSocket.getInputStream();
            // Two requests on the same keep-alive tunnel : only the first one went through the
            // request-line parsing of LoomProxyServer, the second one is relayed as raw bytes.
            sslOut.write((request + "\r\n").getBytes(StandardCharsets.UTF_8));
            sslOut.flush();
            assertThat(readUntil(sslIn, "identity-response-end")).contains("200");
            sslOut.write((request + "Connection: close\r\n\r\n").getBytes(StandardCharsets.UTF_8));
            sslOut.flush();
            assertThat(readUntil(sslIn, "identity-response-end")).contains("200");
        }

        ClientIdentity expected = new ClientIdentity("127.0.0.1", "pip/24.2", "ci-runner");
        assertThat(resolved).containsExactly(expected, expected);
        wireMock.verify(2, getRequestedFor(urlEqualTo("/hello-identity")).withoutHeader("Proxy-Authorization"));
        // The relay is forgotten once the tunnel is closed : a later connection reusing the same
        // loopback port never inherits this client.
        long deadline = System.currentTimeMillis() + 5_000;
        while (connectionRegistry.size() > 0 && System.currentTimeMillis() < deadline) {
            Thread.sleep(20);
        }
        assertThat(connectionRegistry.size()).isZero();
    }

    @Test
    void shouldResolveTheClientOfAPlainHttpProxyRequest() throws Exception {
        wireMock.stubFor(get(urlEqualTo("/hello-plain")).willReturn(aResponse().withStatus(200).withBody("plain-response-end")));
        List<ClientIdentity> resolved = new CopyOnWriteArrayList<>();
        doAnswer(invocation -> {
            ClientIdentity identity = (ClientIdentity) invocation.callRealMethod();
            resolved.add(identity);
            return identity;
        }).when(clientIdentityResolver).resolve(anyString(), anyInt(), any(HttpHeaders.class));
        int wiremockPort = wireMock.port();
        String credentials = Base64.getEncoder().encodeToString("alice:s3cret".getBytes(StandardCharsets.UTF_8));

        try (Socket socket = new Socket("127.0.0.1", loomProxyServer.getProxyPort())) {
            socket.setSoTimeout(10_000);
            OutputStream out = socket.getOutputStream();
            out.write(("GET http://127.0.0.1:" + wiremockPort + "/hello-plain HTTP/1.1\r\n"
                    + "Host: 127.0.0.1:" + wiremockPort + "\r\n"
                    + "User-Agent: Apache-Maven/3.9.9\r\n"
                    + "Proxy-Authorization: Basic " + credentials + "\r\n"
                    + "Connection: close\r\n\r\n").getBytes(StandardCharsets.UTF_8));
            out.flush();
            assertThat(readUntil(socket.getInputStream(), "plain-response-end")).contains("200");
        }

        assertThat(resolved).containsExactly(new ClientIdentity("127.0.0.1", "Apache-Maven/3.9.9", "alice"));
        // The proxy credential is never relayed to the registry.
        wireMock.verify(getRequestedFor(urlEqualTo("/hello-plain")).withoutHeader("Proxy-Authorization"));
        long deadline = System.currentTimeMillis() + 5_000;
        while (connectionRegistry.size() > 0 && System.currentTimeMillis() < deadline) {
            Thread.sleep(20);
        }
        assertThat(connectionRegistry.size()).isZero();
    }

    @Test
    void shouldExtractOnlyTheUsernameOfABasicProxyAuthorizationLine() {
        String credentials = Base64.getEncoder().encodeToString("alice:p@ss:word".getBytes(StandardCharsets.UTF_8));
        assertThat(LoomProxyServer.proxyAuthorizationUser("proxy-authorization: Basic " + credentials)).isEqualTo("alice");
        assertThat(LoomProxyServer.proxyAuthorizationUser("Proxy-Authorization: Bearer abc")).isNull();
        assertThat(LoomProxyServer.proxyAuthorizationUser("Authorization: Basic " + credentials)).isNull();
        assertThat(LoomProxyServer.proxyAuthorizationUser("Host: example.com")).isNull();
        assertThat(LoomProxyServer.proxyAuthorizationUser("Proxy-Authorization: Basic !!not-base64!!")).isNull();
        assertThat(LoomProxyServer.proxyAuthorizationUser("Proxy-Authorization: Basic "
                + Base64.getEncoder().encodeToString(":secret".getBytes(StandardCharsets.UTF_8)))).isNull();
    }

    @Test
    void shouldCloseConnectionWhenRequestLineExceedsMaxLength() throws Exception {
        int proxyPort = loomProxyServer.getProxyPort();

        try (Socket socket = new Socket("127.0.0.1", proxyPort)) {
            socket.setSoTimeout(5000);
            OutputStream out = socket.getOutputStream();

            // No '\n' anywhere in this line, and it's larger than the 8192-byte cap : readLine()
            // must give up instead of growing its buffer forever (SOUCIS.md #3).
            byte[] junk = new byte[9000];
            Arrays.fill(junk, (byte) 'A');
            out.write(junk);
            out.flush();

            assertConnectionWasClosedByServer(socket);
        }
    }

    @Test
    void shouldCloseConnectionWhenTooManyHeaderLinesAreSent() throws Exception {
        int proxyPort = loomProxyServer.getProxyPort();

        try (Socket socket = new Socket("127.0.0.1", proxyPort)) {
            socket.setSoTimeout(5000);
            OutputStream out = socket.getOutputStream();

            try {
                out.write("CONNECT 127.0.0.1:9999 HTTP/1.1\r\n".getBytes(StandardCharsets.UTF_8));
                // More than MAX_HEADER_LINES (100), and the terminating blank line is never sent :
                // readConnectUser() must give up instead of consuming header lines forever.
                for (int i = 0; i < 150; i++) {
                    out.write(("X-Filler-" + i + ": value\r\n").getBytes(StandardCharsets.UTF_8));
                }
                out.flush();
            } catch (SocketException expected) {
                // The server now buffers its header reads, so on a loaded CI box it can count past
                // MAX_HEADER_LINES and reset the connection before this loop finishes writing --
                // a broken pipe here is the same "server closed the connection" signal as the
                // read() == -1 / reset checked below, just observed from the write side.
                return;
            }

            // The 100+ header lines make readConnectUser() throw before the "200 Connection
            // Established" response is ever written, so the client sees the connection close.
            assertConnectionWasClosedByServer(socket);
        }
    }

    @Test
    void shouldParseConnectHostForIpv6Literal() {
        assertThat(LoomProxyServer.parseConnectHost("[::1]:443")).isEqualTo("::1");
        assertThat(LoomProxyServer.parseConnectHost("[2001:db8::1]:8443")).isEqualTo("2001:db8::1");
    }

    @Test
    void shouldParseConnectHostForRegularHostAndPort() {
        assertThat(LoomProxyServer.parseConnectHost("example.com:443")).isEqualTo("example.com");
        assertThat(LoomProxyServer.parseConnectHost("127.0.0.1:443")).isEqualTo("127.0.0.1");
    }

    @Test
    void shouldCloseIdleConnectionAfterHeaderReadTimeout() throws Exception {
        int proxyPort = loomProxyServer.getProxyPort();

        try (Socket socket = new Socket("127.0.0.1", proxyPort)) {
            // Connects but never sends anything. With header-read-timeout-seconds=1 (overridden
            // for this test class), the server must give up and close the connection instead of
            // holding the virtual thread and socket open indefinitely (SOUCIS.md #4).
            socket.setSoTimeout(5000);
            assertConnectionWasClosedByServer(socket);
        }
    }

    // Sends a CONNECT (with extra, CRLF-terminated, headers) and layers a TLS client over the
    // tunnel, trusting the self-signed SilicaProxy CA.
    private static SSLSocket openMitmTunnel(Socket socket, String connectHeaders) throws Exception {
        // Fails the test instead of hanging the build if the proxy never answers.
        socket.setSoTimeout(10_000);
        int wiremockPort = wireMock.port();
        SSLContext trustAllCtx = SSLContext.getInstance("TLS");
        trustAllCtx.init(null, new TrustManager[]{new X509TrustManager() {
            @Override
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }

            @Override
            public void checkClientTrusted(X509Certificate[] c, String a) {}

            @Override
            public void checkServerTrusted(X509Certificate[] c, String a) {}
        }}, new SecureRandom());

        OutputStream out = socket.getOutputStream();
        out.write(("CONNECT 127.0.0.1:" + wiremockPort + " HTTP/1.1\r\nHost: 127.0.0.1:" + wiremockPort + "\r\n"
                + connectHeaders + "\r\n").getBytes(StandardCharsets.UTF_8));
        out.flush();

        // "200 Connection Established" then a blank line, read byte by byte so that no TLS byte
        // is consumed by a reader buffer.
        InputStream in = socket.getInputStream();
        StringBuilder head = new StringBuilder();
        while (!head.toString().endsWith("\r\n\r\n")) {
            int b = in.read();
            if (b == -1) {
                break;
            }
            head.append((char) b);
        }
        assertThat(head.toString()).contains("200 Connection Established");

        SSLSocket sslSocket = (SSLSocket) trustAllCtx.getSocketFactory()
                .createSocket(socket, "127.0.0.1", wiremockPort, false);
        sslSocket.setUseClientMode(true);
        sslSocket.startHandshake();
        return sslSocket;
    }

    private static String readUntil(InputStream in, String suffix) throws IOException {
        StringBuilder read = new StringBuilder();
        int b;
        while (!read.toString().endsWith(suffix) && (b = in.read()) != -1) {
            read.append((char) b);
        }
        return read.toString();
    }

    // The server closing a socket that still has unread bytes buffered on the wire (the "junk"
    // sent past the cap, or headers past the count limit) triggers a TCP reset rather than a
    // graceful FIN on some platforms -- surfacing here as SocketException rather than a clean
    // read() == -1. Both outcomes equally confirm the server closed the connection instead of
    // hanging, which is the only thing these tests care about.
    private void assertConnectionWasClosedByServer(Socket socket) throws IOException {
        try {
            assertThat(socket.getInputStream().read()).isEqualTo(-1);
        } catch (SocketException expected) {
            // Connection reset: also an acceptable sign the server closed the connection.
        }
    }
}
