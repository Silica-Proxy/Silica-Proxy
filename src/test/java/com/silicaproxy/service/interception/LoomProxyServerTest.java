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
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.TestPropertySource;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.Socket;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.assertj.core.api.Assertions.assertThat;

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

        int proxyPort = loomProxyServer.getProxyPort();
        int wiremockPort = wireMock.port();

        // Trust-all SSLContext to accept the self-signed ArtifactSentry CA
        SSLContext trustAllCtx = SSLContext.getInstance("TLS");
        trustAllCtx.init(null, new TrustManager[]{new X509TrustManager() {
            @Override
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }

            @Override
            public void checkClientTrusted(X509Certificate[] c, String a) {}

            @Override
            public void checkServerTrusted(X509Certificate[] c, String a) {}
        }}, new SecureRandom());

        // 2. Open socket to the LoomProxyServer
        try (Socket socket = new Socket("127.0.0.1", proxyPort)) {
            OutputStream out = socket.getOutputStream();
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));

            // 3. Send CONNECT request to the proxy
            String connectRequest = "CONNECT 127.0.0.1:" + wiremockPort + " HTTP/1.1\r\nHost: 127.0.0.1:" + wiremockPort + "\r\n\r\n";
            out.write(connectRequest.getBytes(StandardCharsets.UTF_8));
            out.flush();

            // 4. Read response from proxy (should be 200 Connection Established)
            String responseLine = in.readLine();
            assertThat(responseLine).contains("200 Connection Established");

            // Skip remaining headers until blank line
            String line;
            while ((line = in.readLine()) != null && !line.isEmpty()) {
                // Skip
            }

            // 5. Perform TLS handshake with the MITM proxy (layered over the existing socket)
            SSLSocket sslSocket = (SSLSocket) trustAllCtx.getSocketFactory()
                    .createSocket(socket, "127.0.0.1", wiremockPort, false);
            sslSocket.setUseClientMode(true);
            sslSocket.startHandshake();

            OutputStream sslOut = sslSocket.getOutputStream();
            BufferedReader sslIn = new BufferedReader(new InputStreamReader(sslSocket.getInputStream(), StandardCharsets.UTF_8));

            // 6. Send a proxied GET with an absolute URL through the decrypted channel
            String getRequest = "GET http://127.0.0.1:" + wiremockPort + "/hello-connect HTTP/1.1\r\n"
                    + "Host: 127.0.0.1:" + wiremockPort + "\r\n"
                    + "Connection: close\r\n\r\n";
            sslOut.write(getRequest.getBytes(StandardCharsets.UTF_8));
            sslOut.flush();

            // 7. Assert target response
            StringBuilder targetResponse = new StringBuilder();
            while ((line = sslIn.readLine()) != null) {
                targetResponse.append(line).append("\n");
            }

            assertThat(targetResponse.toString()).contains("200");
            assertThat(targetResponse.toString()).contains("Hello from WireMock Tunnel!");
        }
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

            out.write("CONNECT 127.0.0.1:9999 HTTP/1.1\r\n".getBytes(StandardCharsets.UTF_8));
            // More than MAX_HEADER_LINES (100), and the terminating blank line is never sent :
            // skipHeaders() must give up instead of consuming header lines forever.
            for (int i = 0; i < 150; i++) {
                out.write(("X-Filler-" + i + ": value\r\n").getBytes(StandardCharsets.UTF_8));
            }
            out.flush();

            // The 100+ header lines make skipHeaders() throw before the "200 Connection
            // Established" response is ever written, so the client sees the connection close.
            assertConnectionWasClosedByServer(socket);
        }
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
