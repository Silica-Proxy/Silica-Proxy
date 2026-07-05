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

import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.junit.jupiter.api.Test;

import javax.naming.ldap.LdapName;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class MitmCertificateFactoryTest {

    private final MitmCertificateFactory factory = new MitmCertificateFactory();

    @Test
    void shouldGenerateDifferentNonSequentialSerialsForConsecutiveCerts() throws Exception {
        KeyPair caKeyPair = factory.generateKeyPair();
        X509Certificate cert1 = factory.buildHostCertificate("example.com", factory.generateKeyPair(), caKeyPair);
        X509Certificate cert2 = factory.buildHostCertificate("example.org", factory.generateKeyPair(), caKeyPair);

        assertThat(cert1.getSerialNumber()).isNotEqualTo(cert2.getSerialNumber());
        // Not a small sequential counter (e.g. 2, 3) : should be a large random 128-bit value.
        assertThat(cert1.getSerialNumber().bitLength()).isGreaterThan(32);
    }

    @Test
    void shouldSetServerAuthExtendedKeyUsageOnHostCertificate() throws Exception {
        KeyPair caKeyPair = factory.generateKeyPair();
        X509Certificate cert = factory.buildHostCertificate("example.com", factory.generateKeyPair(), caKeyPair);

        List<String> eku = cert.getExtendedKeyUsage();
        assertThat(eku).contains(KeyPurposeId.id_kp_serverAuth.getId());
    }

    @Test
    void shouldUseDnsNameSanForHostname() throws Exception {
        KeyPair caKeyPair = factory.generateKeyPair();
        X509Certificate cert = factory.buildHostCertificate("example.com", factory.generateKeyPair(), caKeyPair);

        Collection<List<?>> sans = cert.getSubjectAlternativeNames();
        assertThat(sans).hasSize(1);
        List<?> san = sans.iterator().next();
        assertThat((Integer) san.get(0)).isEqualTo(2); // GeneralName.dNSName tag
        assertThat(san.get(1)).isEqualTo("example.com");
    }

    @Test
    void shouldUseIpAddressSanForIpv4Literal() throws Exception {
        KeyPair caKeyPair = factory.generateKeyPair();
        X509Certificate cert = factory.buildHostCertificate("127.0.0.1", factory.generateKeyPair(), caKeyPair);

        Collection<List<?>> sans = cert.getSubjectAlternativeNames();
        List<?> san = sans.iterator().next();
        assertThat((Integer) san.get(0)).isEqualTo(7); // GeneralName.iPAddress tag
        assertThat(san.get(1)).isEqualTo("127.0.0.1");
    }

    @Test
    void shouldUseIpAddressSanForUnbracketedIpv6Literal() throws Exception {
        KeyPair caKeyPair = factory.generateKeyPair();
        // LoomProxyServer.parseConnectHost already strips the brackets before this is called.
        X509Certificate cert = factory.buildHostCertificate("::1", factory.generateKeyPair(), caKeyPair);

        Collection<List<?>> sans = cert.getSubjectAlternativeNames();
        List<?> san = sans.iterator().next();
        assertThat((Integer) san.get(0)).isEqualTo(7); // GeneralName.iPAddress tag
    }

    @Test
    void shouldNotAllowDnInjectionViaHostContainingCommas() throws Exception {
        KeyPair caKeyPair = factory.generateKeyPair();
        String maliciousHost = "evil.com, O=Fake";
        X509Certificate cert = factory.buildHostCertificate(maliciousHost, factory.generateKeyPair(), caKeyPair);

        // The whole string must round-trip as a single escaped CN RDN value, not be parsed
        // into a separate injected "O=Fake" RDN.
        LdapName dn = new LdapName(cert.getSubjectX500Principal().getName());
        assertThat(dn.getRdns()).hasSize(1);
        assertThat(dn.getRdns().get(0).getType()).isEqualToIgnoringCase("CN");
        assertThat(dn.getRdns().get(0).getValue()).isEqualTo(maliciousHost);
    }
}
