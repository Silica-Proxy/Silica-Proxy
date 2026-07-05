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

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.jspecify.annotations.NullMarked;
import org.springframework.stereotype.Component;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;
import java.util.regex.Pattern;

/**
 * Encapsulates the generation of RSA key pairs and X.509 certificates (CA and host) via
 * BouncyCastle. Separated from {@link SslMitmService} to contain BouncyCastle imports and
 * reduce coupling of the main class.
 */
@Component
@NullMarked
public class MitmCertificateFactory {

    private static final String BC_PROVIDER = "BC";
    private static final Pattern IPV4_LITERAL = Pattern.compile("^\\d{1,3}(\\.\\d{1,3}){3}$");
    static final X500Name CA_NAME = new X500Name("CN=SilicaProxy CA, O=SilicaProxy, C=FR");

    private final SecureRandom secureRandom = new SecureRandom();

    public MitmCertificateFactory() {
        Security.addProvider(new BouncyCastleProvider());
    }

    // Random 128-bit serial per host cert: an AtomicLong counter resets to 2 on every JVM
    // restart while the CA itself is persisted across restarts, which can reissue a serial
    // already used under the same CA (a X.509 violation some strict clients reject).
    private BigInteger nextSerial() {
        byte[] bytes = new byte[16];
        secureRandom.nextBytes(bytes);
        return new BigInteger(1, bytes);
    }

    // A CONNECT target reaching here never contains ':' unless it's an unbracketed IPv6
    // literal (LoomProxyServer.parseConnectHost already strips the brackets) -- no legal DNS
    // hostname contains ':', so its presence is an unambiguous signal, same for a dotted-quad.
    private static boolean isIpLiteral(String host) {
        return host.contains(":") || IPV4_LITERAL.matcher(host).matches();
    }

    public KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", BC_PROVIDER);
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    public X509Certificate buildCACertificate(KeyPair caKeyPair) throws Exception {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + 10 * 365L * 24 * 3600 * 1000);

        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                CA_NAME, BigInteger.ONE, now, expiry, CA_NAME, caKeyPair.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));

        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA")
                .setProvider(BC_PROVIDER).build(caKeyPair.getPrivate());
        return new JcaX509CertificateConverter().setProvider(BC_PROVIDER).getCertificate(builder.build(signer));
    }

    public X509Certificate buildHostCertificate(String host, KeyPair hostKeyPair, KeyPair caKeyPair) throws Exception {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + 365L * 24 * 3600 * 1000);

        // X500NameBuilder escapes the RDN value itself, unlike "CN=" + host string
        // concatenation, which lets a host containing ',' / '+' / '"' / etc. inject extra RDNs.
        X500Name subject = new X500NameBuilder(BCStyle.INSTANCE).addRDN(BCStyle.CN, host).build();

        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                CA_NAME, nextSerial(), now, expiry, subject, hostKeyPair.getPublic());
        GeneralName san = isIpLiteral(host)
                ? new GeneralName(GeneralName.iPAddress, host)
                : new GeneralName(GeneralName.dNSName, host);
        builder.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(san));
        builder.addExtension(Extension.extendedKeyUsage, false,
                new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));

        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA")
                .setProvider(BC_PROVIDER).build(caKeyPair.getPrivate());
        return new JcaX509CertificateConverter().setProvider(BC_PROVIDER).getCertificate(builder.build(signer));
    }

    public String buildPem(X509Certificate cert) throws Exception {
        return "-----BEGIN CERTIFICATE-----\n"
                + Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(cert.getEncoded())
                + "\n-----END CERTIFICATE-----\n";
    }
}
