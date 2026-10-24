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
import org.jspecify.annotations.Nullable;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Hands the client side of each {@link LoomProxyServer} relay over to {@link ClientIdentityResolver}.
 * Tomcat only sees a connection from 127.0.0.1 : the relay registers the real client address (and
 * the CONNECT username) under the local port of its connection to Tomcat, which Tomcat reports as
 * {@code getRemotePort()}. Keyed by connection rather than carried in an injected header, it holds
 * for every request of a keep-alive connection, and a client has no way to forge it.
 */
@Component
@NullMarked
public class ProxyConnectionRegistry {

    /**
     * @param address the client socket peer address
     * @param connectUser the Proxy-Authorization username of the CONNECT, if any
     * @param tunnelled whether the requests come out of a CONNECT tunnel : their headers were then
     *        written by the end client, encrypted end to end, never by a proxy in between
     */
    public record Peer(String address, @Nullable String connectUser, boolean tunnelled) {}

    private final Map<Integer, Peer> peersByTomcatSidePort = new ConcurrentHashMap<>();

    void register(int tomcatSidePort, Peer peer) {
        peersByTomcatSidePort.put(tomcatSidePort, peer);
    }

    void unregister(int tomcatSidePort) {
        peersByTomcatSidePort.remove(tomcatSidePort);
    }

    int size() {
        return peersByTomcatSidePort.size();
    }

    /** The client relayed on the loopback connection whose source port is {@code remotePort}, if any. */
    public @Nullable Peer lookup(int remotePort) {
        return peersByTomcatSidePort.get(remotePort);
    }
}
