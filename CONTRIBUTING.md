# Contributing to SilicaProxy

Thank you for contributing to SilicaProxy! This guide covers the development practices, code conventions, and quality standards for external developers.

## Table of Contents

1. [Setup](#setup)
2. [Code Quality](#code-quality)
3. [Code Conventions](#code-conventions)
4. [Architecture Overview](#architecture-overview)
5. [Testing](#testing)
6. [Commit and Pull Request Guidelines](#commit-and-pull-request-guidelines)
7. [Documentation](#documentation)

---

## Setup

### Prerequisites

- **Java 25+** — check your version with `java -version`
- **Gradle 9+** — bundled in the project via Gradle Wrapper
- **Docker and Docker Compose** — for PostgreSQL 18+ and test dependencies
- **PostgreSQL 18+** — managed via Docker Compose, or a local instance if preferred

### Local Development Environment

```bash
# Clone the repository
git clone https://github.com/your-org/silicaproxy.git
cd silicaproxy

# Start PostgreSQL 18+ and test infrastructure
docker compose up -d

# Run the proxy with all checks enabled (see Code Quality section)
./gradlew bootRun
```

The proxy listens on **port 8080**. To test a request through the proxy:

```bash
curl -x http://localhost:8080 https://registry.npmjs.org/lodash
```

To stop the infrastructure:

```bash
docker compose down
```

---

## Code Quality

### Static Analysis (Mandatory)

After **every code change**, run the complete static analysis:

```bash
./gradlew checkstyleMain pmdMain spotbugsMain
```

All three checks **must pass with zero violations** before committing:

- **Checkstyle** (`checkstyleMain`) — code formatting and naming conventions
- **PMD** (`pmdMain`) — code smell detection (unused variables, suspicious patterns)
- **SpotBugs** (`spotbugsMain`) — potential bugs (null pointers, incorrect comparison)

**Do NOT suppress or disable any rule to make checks pass.** Instead, fix the underlying issue. Suppressions are only allowed with explicit justification in code comments, and only as a last resort.

#### Configuring the Checkers

The checker configurations are in `config/`:

- `checkstyle.xml` — defines naming, formatting, and structure rules
- `pmd-ruleset.xml` — defines code smell detection rules
- `spotbugs-exclude.xml` — lists known false positives (read-only; do not add entries lightly)

#### Understanding Failures

When a check fails, the error message includes:

- **File and line number** — exact location of the violation
- **Rule name** — which rule was triggered
- **Expected behavior** — what the rule expects

Example:

```
[CHECKSTYLE] Missing a Javadoc comment on constructor.
File: src/main/java/fr/silicaproxy/service/SecurityService.java, line 42
```

**Action:** Add a one-line Javadoc comment or refactor the code. Do not suppress.

### Build and Test Checks

Run the full build with tests and code analysis:

```bash
./gradlew build
```

This runs (in order):
1. Compilation
2. Unit tests
3. Integration tests
4. Checkstyle
5. PMD
6. SpotBugs

The build fails if any step fails. Fix the issue, then re-run the build.

### Pre-commit Hook (Optional but Recommended)

Install a Git pre-commit hook to run static checks before each commit:

```bash
# Create .git/hooks/pre-commit
cat > .git/hooks/pre-commit << 'EOF'
#!/bin/bash
./gradlew checkstyleMain pmdMain spotbugsMain || exit 1
EOF

chmod +x .git/hooks/pre-commit
```

Now static analysis runs automatically before each commit. If it fails, the commit is aborted.

---

## Code Conventions

### Dependency Injection — Constructor Injection Only

**Rule:** Use constructor injection exclusively. `@Autowired` fields are forbidden.

**Why:** Constructor injection enforces that all dependencies are declared at class construction time, making the class immutable and easier to test.

**Correct:**

```java
@Service
public class SecurityService {
    private final PolicyDao policyDao;
    private final VulnerabilityService vulnerabilityService;

    // Constructor injection — required fields make testing explicit
    public SecurityService(PolicyDao policyDao, VulnerabilityService vulnerabilityService) {
        this.policyDao = policyDao;
        this.vulnerabilityService = vulnerabilityService;
    }
}
```

**Incorrect (will fail static analysis):**

```java
@Service
public class SecurityService {
    @Autowired  // ❌ Forbidden
    private PolicyDao policyDao;
}
```

**Exception:** `@MockitoBean` and `@MockitoSpyBean` in **test classes only** may use field injection.

### Terminology — No Vendor Names

**Rule:** Use "artifact repository" instead of vendor-specific names. Exception: technical URLs in tests that cannot be changed.

**Why:** The proxy is agnostic to the repository platform; code should reflect that.

### Naming Conventions

- **Classes:** PascalCase (e.g., `SecurityService`, `PolicyDao`)
- **Methods/Variables:** camelCase (e.g., `evaluatePolicy()`, `packageName`)
- **Constants:** UPPER_SNAKE_CASE (e.g., `BLOCK_VERDICT_TTL_MINUTES`)
- **Test classes:** `NameTest` or `NameTests` suffix (e.g., `SecurityServiceTest`)

### Comments

- **Write comments only for non-obvious "why"**, not what the code does. If removing a comment would confuse a reader, keep it; otherwise, delete it.
- **No multi-line comment blocks.** One short line per comment, max.
- **Javadoc:** Required for public classes and public methods. One-line format preferred.

**Correct:**

```java
// Discard when buffer overflows to avoid blocking package downloads
buffer.setDiscardPolicy(DiscardPolicy.DISCARD);
```

**Incorrect:**

```java
// This sets the discard policy  // ❌ Obvious from code
/**
 * This method validates the package.
 * It checks the package against the policy.
 * If the policy is violated, it returns false.
 */
boolean validate(...) { ... }  // ❌ Multi-line, restates code
```

### Avoid Premature Abstractions

- **Don't refactor on speculation.** Fix the immediate problem.
- **Three similar lines is better than a premature abstraction.** Add the abstraction when the fourth line appears and the pattern is clear.
- **One-shot utilities don't need helper methods.** Inline them.

**Correct:**

```java
// Two similar queries → inline (no abstraction yet)
List<Vulnerability> npmVulns = dao.findVulnerabilities("npm", packageName);
List<Vulnerability> pypiVulns = dao.findVulnerabilities("pypi", packageName);
```

**Incorrect (premature):**

```java
// Extracted after only two uses
private List<Vulnerability> getAllVulnerabilities() {
    return dao.findVulnerabilities("npm", packageName) 
        .addAll(dao.findVulnerabilities("pypi", packageName));
}
```

### Error Handling

- **Only validate at system boundaries** (user input, external APIs, file I/O).
- **Trust internal code.** If a method guarantees non-null return, don't null-check it.
- **Don't add fallbacks for impossible scenarios.** Keep the code focused.

**Correct:**

```java
// Validate at boundary (external API)
String response = httpClient.get(apiUrl);
if (response == null || response.isEmpty()) {
    throw new SecurityException("API response empty");
}
```

**Incorrect:**

```java
// Over-defensive: internal method guarantees non-null
String result = securityService.evaluate(package);
if (result != null) {  // ❌ Unnecessary
    return result;
}
```

---

## Architecture Overview

### Package Structure

The codebase mirrors the security decision pipeline:

```
fr.silicaproxy
├── controller/           REST endpoints (proxy, policies, monitoring)
├── service/
│   ├── interception/     TCP entry point, SSL MITM, URL parsing
│   ├── policy/           Company policy evaluation, GitOps sync
│   ├── vulnerability/    OSV sync, CVE ingestion, scheduler
│   ├── decision/         SecurityService orchestrator
│   ├── audit/            Async audit logging
│   ├── monitoring/       Health, inventory reporting
│   └── search/           Package search
├── dao/
│   ├── policy/           SQL (company_policies, decision cache)
│   ├── vulnerability/    SQL (public_vulnerabilities)
│   ├── sync/             SQL (sync metadata, locks)
│   ├── audit/            SQL (audit logs)
│   └── client/           HTTP (OSV, deps.dev, registries, Git)
├── config/               Spring configuration
├── model/
│   ├── dto/              Data transfer objects
│   └── entity/           JPA entities
└── properties/           SilicaProxyProperties (typed config)
```

### Key Design Principles

1. **Virtual threads (Project Loom)** — thousands of concurrent requests with minimal overhead.
2. **Single SQL query** — one `UNION ALL` covers all local sources; priority ordering enforces policy precedence.
3. **Streaming downloads** — 16 KB buffers keep memory footprint stable regardless of artifact size.
4. **Async audit logging** — audit writes never block package downloads.

### Request Flow

```
Client Request (HTTP/HTTPS)
    ↓
LoomProxyServer (TCP entry point, port 8080)
    ↓ (SSL MITM if HTTPS)
ProxyController (Spring Boot, port 8089 internal)
    ↓
UrlParserService (extract package name, version, ecosystem)
    ↓
SecurityService (orchestrate decision pipeline)
    ↓
Decision Pipeline (SQL UNION: company_policies, public_vulnerabilities, api_cache)
    ↓
Registry Metadata (if needed: publication date, deprecation status)
    ↓
Verdict: ALLOW (stream) or BLOCK (403 JSON)
```

---

## Testing

### Test Structure

- **Unit tests** in `src/test/java` — test individual classes in isolation
- **Integration tests** in `src/test/java` — test Spring components with a real database
- **Test data** in `src/test/resources`

### Running Tests

```bash
# Run all tests
./gradlew test

# Run a specific test class
./gradlew test --tests SecurityServiceTest

# Run with coverage report
./gradlew test jacocoTestReport
```

### Test Conventions

1. **Use constructor injection for dependencies** (same as production code).
2. **@MockitoBean for Spring beans**, `@MockitoSpyBean` for partial mocks.
3. **Test names are descriptive:** `testEvaluatePolicyShouldBlockWhenPackageMatches()`.
4. **One assertion per test method** (or a few related assertions grouped logically).

**Example:**

```java
@SpringBootTest
class SecurityServiceTest {
    @MockitoBean
    private PolicyDao policyDao;

    private SecurityService securityService;

    @Autowired
    SecurityServiceTest(SecurityService service) {
        this.securityService = service;
    }

    @Test
    void testEvaluatePolicyShouldBlockWhenPackageMatches() {
        // Arrange
        given(policyDao.findPolicy("lodash", "3.10.1"))
            .willReturn(Optional.of(new Policy("lodash", "block", "...")));

        // Act
        Decision decision = securityService.evaluate("lodash", "3.10.1");

        // Assert
        assertThat(decision.verdict()).isEqualTo(BLOCK);
    }
}
```

### Database Tests

If your test needs a real database, use `@SpringBootTest`:

```java
@SpringBootTest
@Testcontainers  // Start PostgreSQL container automatically
class PolicyDaoTest {
    @Container
    static PostgreSQLContainer<?> database = new PostgreSQLContainer<>("postgres:18");

    // Test code...
}
```

---

## Commit and Pull Request Guidelines

### Commit Messages

- **Concise subject line (50 chars max):** "Fix NPE in SecurityService.evaluate()"
- **Blank line, then detailed explanation (if needed):** Why was the change made? What problem does it solve?
- **Reference issues or PRs:** "Fixes #123" or "Related to #456"

**Example:**

```
Fix concurrent modification in SecurityService

When multiple requests evaluated the same package simultaneously,
the decision cache could be updated twice, causing duplicate audit
entries. Use ConcurrentHashMap with putIfAbsent() to ensure only
one entry per package.

Fixes #789
```

### Pull Request Guidelines

1. **One feature or fix per PR.** Avoid mixing unrelated changes.
2. **Run static analysis** before pushing:
   ```bash
   ./gradlew checkstyleMain pmdMain spotbugsMain
   ```
3. **Run full build** to ensure tests pass:
   ```bash
   ./gradlew build
   ```
4. **Update documentation** if adding new config properties or endpoints.
5. **Add tests** for new features or bug fixes.

### PR Title and Description

**Title format:** `[type] Brief description (50 chars max)`

Where `[type]` is one of:
- `[feat]` — new feature
- `[fix]` — bug fix
- `[refactor]` — code reorganization (no behavior change)
- `[test]` — test additions or fixes
- `[docs]` — documentation
- `[chore]` — build, dependencies, config

**Description template:**

```markdown
## Summary
Brief explanation of the change and why it was needed.

## Changes
- Point 1
- Point 2

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] Manual testing completed

## Checklist
- [ ] Static analysis passes (checkstyle, PMD, SpotBugs)
- [ ] All tests pass
- [ ] Documentation updated
```

---

## Documentation

### Code Comments

- **Javadoc:** Required for public classes, methods, and fields.
- **Inline comments:** Only for non-obvious logic (e.g., workarounds, tricky algorithms).
- **Format:** One-line comments preferred; use `//`, not `/* */`.

**Example:**

```java
/**
 * Evaluates a package against the decision pipeline.
 * Returns ALLOW if all checks pass, BLOCK otherwise.
 */
public Decision evaluate(String packageName, String version) {
    // Single SQL query covers all sources (company_policies, public_vulnerabilities, api_cache)
    // Priority ordering ensures company policies always win
    List<Decision> results = dao.findDecision(packageName, version);
    
    return results.isEmpty() ? ALLOW : results.get(0);
}
```

### README and Configuration

- **README.md** — user-facing, deployment, and API documentation
- **HELP.md** — getting started guide (reference only)
- **CLAUDE.md** — project-level development rules
- **CONTRIBUTING.md** — this file

If you add a new configuration property, update the [Configuration Reference](README.md#configuration-reference) table.

### Changelog

For releases, document significant changes (breaking changes, new features, bug fixes) in a `CHANGELOG.md` file at the project root.

---

## Common Tasks

### Adding a New REST Endpoint

1. Create a method in a `@RestController` or `@Controller` class.
2. Annotate with `@GetMapping`, `@PostMapping`, etc.
3. Use constructor injection for dependencies.
4. Add Javadoc and tests.
5. Update `README.md#api-endpoints` if it's a public endpoint.

### Adding a New Configuration Property

1. Add the property to `SilicaProxyProperties` (typed configuration class).
2. Add the environment variable mapping (Spring will do this automatically via `@ConfigurationProperties`).
3. Update the configuration reference table in `README.md#configuration-reference`.
4. Add tests for the new property.

### Adding a Database Migration

1. Create a new SQL script in `src/main/resources/db/migration/V<version>__<description>.sql`.
2. Spring Boot runs migrations automatically via Flyway.
3. Test locally: restart the application with `docker compose up -d` to ensure the migration runs.

---

## Resources

- **Spring Boot Docs:** https://spring.io/projects/spring-boot
- **Java 25 Virtual Threads:** https://openjdk.org/projects/loom/
- **PostgreSQL Docs:** https://www.postgresql.org/docs/
- **Checkstyle Rules:** https://checkstyle.sourceforge.io/checks.html
- **PMD Ruleset:** https://pmd.github.io/latest/pmd_rules_java.html
- **SpotBugs Guide:** https://spotbugs.readthedocs.io/

---

## Getting Help

- **Questions?** Open an issue or discussion in the repository.
- **Found a bug?** File a GitHub issue with reproduction steps.
- **Want to contribute?** Start with issues marked `good first issue`.

Thank you for making SilicaProxy more secure!
