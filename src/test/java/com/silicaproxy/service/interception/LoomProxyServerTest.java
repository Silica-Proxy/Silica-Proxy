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

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.assertj.core.api.Assertions.assertThat;

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
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
            public void checkClientTrusted(X509Certificate[] c, String a) {}
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
}
