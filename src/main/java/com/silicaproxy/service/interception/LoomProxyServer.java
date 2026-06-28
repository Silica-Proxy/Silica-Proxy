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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.web.server.context.WebServerInitializedEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.stereotype.Component;

import com.silicaproxy.properties.SilicaProxyProperties;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import java.util.concurrent.TimeUnit;
import jakarta.annotation.PreDestroy;

import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Raw TCP server based on Loom virtual threads, listening on the external public port
 *  to overcome the lack of native support for HTTP {@code CONNECT}
 * method by Tomcat. Started once at application startup (on {@link WebServerInitializedEvent}) ;
 * then relays each incoming connection either directly to Tomcat (standard HTTP requests),
 * or by intercepting TLS via MITM (CONNECT/HTTPS) to go through ProxyController.
 */
@Component
@NullMarked
public class LoomProxyServer implements ApplicationListener<WebServerInitializedEvent> {

    private static final Logger LOG = LoggerFactory.getLogger(LoomProxyServer.class);

    private int proxyPort;
    private int tomcatPort;
    private ServerSocket serverSocket;
    private final ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor();
    private final AtomicBoolean started = new AtomicBoolean(false);
    private final SslMitmService sslMitmService;
    private final Timer sslHandshakeTimer;

    public LoomProxyServer(SilicaProxyProperties properties, SslMitmService sslMitmService, MeterRegistry meterRegistry) {
        this.proxyPort = properties.proxy().port();
        this.sslMitmService = sslMitmService;
        this.sslHandshakeTimer = Timer.builder("silicaproxy.loom.ssl.handshake")
                .description("Duration of TLS MITM handshake in LoomProxyServer")
                .publishPercentiles(0.5, 0.9, 0.95, 0.99)
                .register(meterRegistry);
    }

    @Override
    public void onApplicationEvent(WebServerInitializedEvent event) {
        if (started.compareAndSet(false, true)) {
            this.tomcatPort = event.getWebServer().getPort();
            executor.submit(this::listen);
        }
    }

    private void listen() {
        try {
            serverSocket = new ServerSocket(proxyPort);
            this.proxyPort = serverSocket.getLocalPort();
            LOG.info("Loom TCP Proxy Server listening on port {}, forwarding to Tomcat on port {}", proxyPort, tomcatPort);

            while (!serverSocket.isClosed()) {
                Socket clientSocket = serverSocket.accept();
                executor.submit(() -> handleClient(clientSocket));
            }
        } catch (IOException e) {
            if (serverSocket != null && !serverSocket.isClosed()) {
                LOG.error("Error in TCP Proxy listener", e);
            }
        }
    }

    private void handleClient(Socket clientSocket) {
        try (clientSocket) {
            InputStream clientIn = clientSocket.getInputStream();
            OutputStream clientOut = clientSocket.getOutputStream();

            String firstLine = readLine(clientIn);
            if (firstLine.isEmpty()) {
                return;
            }

            if (firstLine.startsWith("CONNECT")) {
                handleConnect(firstLine, clientSocket, clientIn, clientOut);
            } else {
                forwardToTomcat(firstLine, clientIn, clientOut);
            }
        } catch (IOException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Connection error with client: {}", e.getMessage());
            }
        }
    }

    private void handleConnect(String firstLine, Socket clientSocket, InputStream clientIn, OutputStream clientOut) throws IOException {
        String[] parts = firstLine.split(" ");
        if (parts.length < 2) {
            clientOut.write("HTTP/1.1 400 Bad Request\r\n\r\n".getBytes(StandardCharsets.UTF_8));
            clientOut.flush();
            return;
        }

        String target = parts[1];
        String host = target.contains(":") ? target.split(":")[0] : target;

        skipHeaders(clientIn);

        clientOut.write("HTTP/1.1 200 Connection Established\r\n\r\n".getBytes(StandardCharsets.UTF_8));
        clientOut.flush();

        if (LOG.isDebugEnabled()) {
            LOG.debug("CONNECT MITM for {}", host);
        }

        try {
            SSLSocket sslSocket = (SSLSocket) sslMitmService.getContextForHost(host)
                    .getSocketFactory()
                    .createSocket(clientSocket, clientSocket.getInputStream(), false);
            sslSocket.setUseClientMode(false);
            long t0 = System.nanoTime();
            sslSocket.startHandshake();
            sslHandshakeTimer.record(System.nanoTime() - t0, TimeUnit.NANOSECONDS);
            LOG.info("MITM TLS established for {}", host);

            String httpFirstLine = readLine(sslSocket.getInputStream());
            if (!httpFirstLine.isEmpty()) {
                forwardToTomcat(httpFirstLine, sslSocket.getInputStream(), sslSocket.getOutputStream());
            }
        } catch (Exception e) {
            LOG.warn("SSL MITM failed for {} : {} — is the CA imported in the artifacts repository ?", host, e.getMessage());
        }
    }

    private void forwardToTomcat(String firstLine, InputStream clientIn, OutputStream clientOut) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("HTTP request forwarded to Tomcat: {}", firstLine);
        }

        try (Socket tomcatSocket = new Socket("127.0.0.1", tomcatPort)) {
            OutputStream tomcatOut = tomcatSocket.getOutputStream();
            InputStream tomcatIn = tomcatSocket.getInputStream();

            tomcatOut.write((firstLine + "\r\n").getBytes(StandardCharsets.UTF_8));
            relayBidirectionally(clientIn, tomcatOut, tomcatIn, clientOut);
        } catch (Exception e) {
            LOG.error("Failed to forward to Tomcat on port {}", tomcatPort, e);
            try {
                clientOut.write("HTTP/1.1 502 Bad Gateway\r\n\r\n".getBytes(StandardCharsets.UTF_8));
                clientOut.flush();
            } catch (IOException ignored) {
            }
        }
    }

    private String readLine(InputStream in) throws IOException {
        StringBuilder sb = new StringBuilder();
        int b;
        while ((b = in.read()) != -1) {
            if (b == '\n') {
                break;
            }
            if (b != '\r') {
                sb.append((char) b);
            }
        }
        return sb.toString().trim();
    }

    private void skipHeaders(InputStream in) throws IOException {
        while (!readLine(in).isEmpty()) {
            // consume header lines until blank line
        }
    }

    // Relays both directions of a TCP tunnel in parallel (virtual threads), then closes both 
    // connections as soon as ONE of the directions ends. Without this explicit closure propagation, 
    // the other direction would remain blocked indefinitely in reading if its peer never actively 
    // closes its connection after finishing sending its data - real and frequent case : 
    // an HTTP client keeps its socket open after sending its request, waiting for the 
    // response, while the target (remote registry) closes its own right after responding 
    // (ex: `Connection: close` header).
    private void relayBidirectionally(InputStream in1, OutputStream out1, InputStream in2, OutputStream out2) {
        CompletableFuture<Void> direction1 = CompletableFuture.runAsync(() -> copyStream(in1, out1), executor);
        CompletableFuture<Void> direction2 = CompletableFuture.runAsync(() -> copyStream(in2, out2), executor);

        CompletableFuture.anyOf(direction1, direction2).join();

        closeQuietly(out1);
        closeQuietly(out2);

        CompletableFuture.allOf(direction1, direction2).join();
    }

    private void closeQuietly(OutputStream out) {
        try {
            out.close();
        } catch (IOException e) {
            // Already closed
        }
    }

    private void copyStream(InputStream in, OutputStream out) {
        byte[] buffer = new byte[16384];
        int read;
        try {
            while ((read = in.read(buffer)) != -1) {
                out.write(buffer, 0, read);
                out.flush();
            }
        } catch (IOException e) {
            // Stream closed
        }
    }

    public int getProxyPort() {
        return proxyPort;
    }

    @PreDestroy
    public void stop() {
        try {
            if (serverSocket != null && !serverSocket.isClosed()) {
                serverSocket.close();
            }
        } catch (IOException e) {
            // Ignore
        }
        executor.shutdown();
    }
}
