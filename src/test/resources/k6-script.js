// k6 load test script
import http from 'k6/http';
import { check } from 'k6';

export const options = {
  insecureSkipTLSVerify: true,
  stages: [
    { duration: '30s', target: 50 },   // warmup ramp-up
    { duration: '60s', target: 150 },  // steady state
    { duration: '10s', target: 0 },    // ramp-down
  ],
};

export default function () {
  const params = { timeout: '5s' };
  const ratio = Math.random();
  const id = Math.floor(Math.random() * 10000);

  if (ratio < 0.18) {
    // npm HTTP — blocked by company policy (18%)
    const url = `http://registry.npmjs.org/blocked-company-${id}/-/blocked-company-${id}-1.0.0.tgz`;
    const res = http.get(url, params);
    check(res, {
      'npm policy block is 403': (r) => r.status === 403,
      'npm policy error is CompanyPolicy': (r) => r.body && r.body.includes('COMPANY_POLICY'),
    });
  } else if (ratio < 0.30) {
    // npm HTTP — blocked by vulnerability (12%)
    const url = `http://registry.npmjs.org/blocked-vuln-${id}/-/blocked-vuln-${id}-1.0.0.tgz`;
    const res = http.get(url, params);
    check(res, {
      'npm vuln block is 403': (r) => r.status === 403,
      'npm vuln error is PublicVulnerability': (r) => r.body && r.body.includes('PUBLIC_VULN'),
    });
  } else if (ratio < 0.38) {
    // npm HTTP — malicious package (8%)
    const url = `http://registry.npmjs.org/malicious-pkg-${id}/-/malicious-pkg-${id}-1.0.0.tgz`;
    const res = http.get(url, params);
    check(res, {
      'npm malware block is 403': (r) => r.status === 403,
      'npm malware error is PublicVulnerability': (r) => r.body && r.body.includes('PUBLIC_VULN'),
    });
  } else if (ratio < 0.48) {
    // PyPI HTTP — blocked by company policy (10%)
    const url = `http://pypi.org/packages/source/b/blocked-pypi-${id}/blocked-pypi-${id}-1.0.0.tar.gz`;
    const res = http.get(url, params);
    check(res, {
      'pypi policy block is 403': (r) => r.status === 403,
      'pypi policy error is CompanyPolicy': (r) => r.body && r.body.includes('COMPANY_POLICY'),
    });
  } else if (ratio < 0.56) {
    // PyPI HTTP — blocked by vulnerability (8%)
    const url = `http://pypi.org/packages/source/b/blocked-pypi-vuln-${id}/blocked-pypi-vuln-${id}-1.0.0.tar.gz`;
    const res = http.get(url, params);
    check(res, {
      'pypi vuln block is 403': (r) => r.status === 403,
      'pypi vuln error is PublicVulnerability': (r) => r.body && r.body.includes('PUBLIC_VULN'),
    });
  } else if (ratio < 0.64) {
    // Maven HTTP — blocked by company policy (8%)
    const url = `http://repo1.maven.org/maven2/com/example/blocked-maven-${id}/1.0.0/blocked-maven-${id}-1.0.0.jar`;
    const res = http.get(url, params);
    check(res, {
      'maven policy block is 403': (r) => r.status === 403,
      'maven policy error is CompanyPolicy': (r) => r.body && r.body.includes('COMPANY_POLICY'),
    });
  } else if (ratio < 0.72) {
    // Maven HTTP — blocked by vulnerability (8%)
    const url = `http://repo1.maven.org/maven2/com/example/blocked-maven-vuln-${id}/1.0.0/blocked-maven-vuln-${id}-1.0.0.jar`;
    const res = http.get(url, params);
    check(res, {
      'maven vuln block is 403': (r) => r.status === 403,
      'maven vuln error is PublicVulnerability': (r) => r.body && r.body.includes('PUBLIC_VULN'),
    });
  } else if (ratio < 0.82) {
    // npm HTTPS — blocked by company policy via CONNECT tunnel (10%)
    const url = `https://registry.npmjs.org/blocked-company-${id}/-/blocked-company-${id}-1.0.0.tgz`;
    const res = http.get(url, params);
    check(res, {
      'npm HTTPS policy block is 403': (r) => r.status === 403,
    });
  } else if (ratio < 0.90) {
    // PyPI HTTPS — blocked by company policy via CONNECT tunnel (8%)
    const url = `https://pypi.org/packages/source/b/blocked-pypi-${id}/blocked-pypi-${id}-1.0.0.tar.gz`;
    const res = http.get(url, params);
    check(res, {
      'pypi HTTPS policy block is 403': (r) => r.status === 403,
    });
  } else if (ratio < 0.97) {
    // Maven HTTPS — blocked by company policy via CONNECT tunnel (7%)
    const url = `https://repo1.maven.org/maven2/com/example/blocked-maven-${id}/1.0.0/blocked-maven-${id}-1.0.0.jar`;
    const res = http.get(url, params);
    check(res, {
      'maven HTTPS policy block is 403': (r) => r.status === 403,
    });
  } else {
    // npm HTTP — allowed real download (3%)
    // 'ansi-styles' 5.2.0 is a real package (~3 KB tarball)
    const url = 'http://registry.npmjs.org/ansi-styles/-/ansi-styles-5.2.0.tgz';
    const res = http.get(url, params);
    check(res, {
      'allowed download is 200': (r) => r.status === 200,
      'body is correct size': (r) => r.body && r.body.length > 1000,
    });
  }
}
