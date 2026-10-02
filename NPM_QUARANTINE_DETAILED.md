# NPM Quarantine – Implémentation Précise

## Vue d'ensemble

Pour npm, la quarantaine fonctionne en **3 couches** :

1. **Parsing d'URL** – Identifier le package et la version depuis la requête
2. **Indexation de Packument** – Apprendre la date de publication depuis les packuments relayés
3. **Résolution de Date** – Chercher la date auprès du registre public, puis fallback sur les registres d'origine

---

## Couche 1 : Parsing des URLs npm

### Patterns de Détection

Le service utilise des **regex très spécifiques** pour identifier les packages npm :

#### Tarball (requête du client npm)

```java
// Scoped packages: /@scope/name
static final Pattern NPM_SCOPED_TARBALL_PATTERN = 
    Pattern.compile("^/(@[^/]+)/([^/]+)/-/\\2-([\\d\\.]+.*)\\.tgz$");

// Unscoped packages: /name
static final Pattern NPM_UNSCOPED_TARBALL_PATTERN = 
    Pattern.compile("^/([^/]+)/-/\\1-([\\d\\.]+.*)\\.tgz$");
```

**Exemple de parsing** :

```
URL: /registry.npmjs.org/@angular/core/-/core-17.0.0.tgz
     ↓ (path = /@angular/core/-/core-17.0.0.tgz)
     ↓ SCOPED_TARBALL_PATTERN
   Group 1: @angular    (scope)
   Group 2: core        (artifact ID)
   Group 3: 17.0.0      (version)
   → packageName = "@angular/core"
   → version = "17.0.0"

URL: /registry.npmjs.org/lodash/-/lodash-4.17.21.tgz
     ↓ (path = /lodash/-/lodash-4.17.21.tgz)
     ↓ UNSCOPED_TARBALL_PATTERN
   Group 1: lodash      (name)
   Group 2: 4.17.21     (version)
   → packageName = "lodash"
   → version = "4.17.21"
```

**Détails critiques des regex** :

- `[^/]+` : une partie du chemin (pas de slashes)
- `\\1` / `\\2` : backreference au groupe 1/2 (vérifier le nom du fichier == nom du package)
  - Prévient les faux positifs sur des répertoires génériques
  - Garantit `/foo/-/foo-*.tgz` (pas `/foo/-/bar-*.tgz`)
- `[\\d\\.]+.*` : version (commence par un chiffre ou point, suivi de n'importe quoi)
  - Capture les versions avec pre-release : `17.0.0-rc.1`, `1.0.0-beta+build`
  - Capture les tariffs locales : `1.0.0.local`

#### Packument (métadonnées du registre)

```java
// Scoped packument: /@scope/name ou /@scope/name/version ou /@scope/name/dist-tags
static final Pattern NPM_SCOPED_PACKUMENT_PATTERN =
    Pattern.compile("^/(@[^/@]+/[^/@]+)(?:/[^/]+)?$");

// Unscoped packument: /name ou /name/version ou /name/dist-tags
static final Pattern NPM_UNSCOPED_PACKUMENT_PATTERN = 
    Pattern.compile("^/([^/@-][^/]*)(?:/[^/]+)?$");
```

**Exemple** :

```
GET /@angular/core (packument complet)
GET /@angular/core/17.0.0 (metadata d'une version)
GET /lodash (packument complet)
GET /lodash/latest (dist-tag)
```

#### Registre npm API (détection par chemin)

```java
static final Pattern NPM_REGISTRY_API_PATTERN =
    Pattern.compile("^/-/(?:v1/|npm/|package/|user/|ping|whoami).*$");

static final Pattern NPM_DASH_SEGMENT_PATTERN = 
    Pattern.compile("^/(?:@[^/]+/)?[^/@-][^/]*/-/.*$");
```

**Exemples** :
- `/-/v1/search` – recherche npm
- `/-/npm/v1/...` – authentification npm
- `/@scope/name/-/...` – n'importe quoi après `/-/`

---

## Couche 2 : Détection npm par Headers (fallback pour registres privés)

Quand l'URL seule ne suffit pas (registres Verdaccio, Artifactory, JSR privé), on cherche des **indicateurs npm** dans les requêtes :

### Détection par User-Agent

```java
static final List<String> NPM_USER_AGENT_PREFIXES = 
    List.of("npm/", "pnpm/", "yarn/", "bun/");
```

**Exemple** :
```
User-Agent: npm/9.6.4 node/v18.16.0 linux x64
            ↓
            Starts with "npm/" → npm detected
```

### Détection par Accept Header

```java
static final String NPM_INSTALL_MEDIA_TYPE = 
    "application/vnd.npm.install-v1+json";

// Contain check (case-insensitive)
if (accept.toLowerCase().contains("application/vnd.npm.install-v1+json")) {
    return true;
}
```

**Exemple** :
```
Accept: application/vnd.npm.install-v1+json, application/json;q=0.9, */*;q=0.8
        ↓
        Contains npm media type → npm detected
```

### Détection par Headers npm-spécifiques

```java
static final List<String> NPM_HEADER_PREFIXES = 
    List.of("npm-", "pacote-");
```

**Headers cherchés** :
- `npm-command` (ex. "install")
- `npm-scope` (ex. "@angular")
- `npm-in-ci` (booléen)
- `npm-session` (UUID)
- `npm-auth-type` (ex. "legacy")
- `pacote-version` (client interne npm)
- `pacote-req-type` (type de requête)

**Détection (code)** :
```java
for (String name : headers.headerNames()) {
    String lower = name.toLowerCase(Locale.ROOT);
    for (String prefix : NPM_HEADER_PREFIXES) {
        if (lower.startsWith(prefix)) {
            return true;  // npm detected
        }
    }
}
```

---

## Couche 3 : Indexation de Packument

### Indexation en Temps Réel

Quand la proxy **relaye une réponse packument**, elle l'**indexe immédiatement** pour extraire :

1. **URL des tarballs** (`versions[v].dist.tarball`)
2. **Date de publication** (`time[version]`)
3. **État de dépreciation** (`versions[v].deprecated`)
4. **URL du packument source** (quelle registre l'a fourni)

### Structure Indexée

```java
private record IndexedTarball(
    String packageName,         // "lodash" ou "@angular/core"
    String version,             // "4.17.21"
    @Nullable Instant publishedAt,    // 2024-01-15T10:30:00Z
    boolean deprecated,         // true si marqué comme deprecated
    @Nullable String deprecationReason, // "Raison du deprecated"
    String packumentUrl,        // "https://npm.jsr.io/@scope/name" (pour JSR)
    Instant indexedAt           // Quand c'est entré en cache
)
```

### Parsing du JSON du Packument

Le parsing est **streaming** (token-by-token), pas par désérialisation complète :

```java
private Optional<PackageMetadataResult> parseNpmPackument(InputStream body, String version) 
        throws IOException {
    String publishedAtStr = null;
    boolean isDeprecated = false;
    
    try (JsonParser parser = objectMapper.createParser(body)) {
        if (parser.nextToken() != JsonToken.START_OBJECT) {
            return Optional.empty();  // Invalid packument
        }
        
        // Parcourir les fields au top niveau
        while (parser.nextToken() != JsonToken.END_OBJECT) {
            String fieldName = parser.currentName();
            JsonToken valueToken = parser.nextToken();
            
            // Chercher "time" objet
            if ("time".equals(fieldName) && valueToken == JsonToken.START_OBJECT) {
                publishedAtStr = scanObjectForStringValue(parser, version);
                // Cherche: time.17.0.0 = "2024-01-15T10:30:00Z"
            } 
            // Chercher "versions" objet
            else if ("versions".equals(fieldName) && valueToken == JsonToken.START_OBJECT) {
                DeprecationInfo depInfo = scanVersionsForDeprecation(parser, version);
                isDeprecated = depInfo.deprecated();
            } 
            // Skip tout le reste
            else if (valueToken == JsonToken.START_OBJECT || 
                     valueToken == JsonToken.START_ARRAY) {
                parser.skipChildren();
            }
        }
    }
    
    if (publishedAtStr == null) {
        return Optional.empty();
    }
    
    return Optional.of(new PackageMetadataResult(
        Instant.parse(publishedAtStr),  // ISO 8601: "2024-01-15T10:30:00Z"
        isDeprecated,
        deprecationReason
    ));
}
```

### Parsing Spécifique du Champ "time"

```java
private String scanObjectForStringValue(JsonParser parser, String key) 
        throws IOException {
    String result = null;
    
    // On est déjà dans l'objet "time"
    while (parser.nextToken() != JsonToken.END_OBJECT) {
        String currentKey = parser.currentName();
        JsonToken valueToken = parser.nextToken();
        
        // Chercher la clé exacte (version)
        if (currentKey.equals(key) && valueToken == JsonToken.VALUE_STRING) {
            result = parser.getString();  // "2024-01-15T10:30:00Z"
        } 
        // Skip les objets/arrays inutiles
        else if (valueToken == JsonToken.START_OBJECT || 
                 valueToken == JsonToken.START_ARRAY) {
            parser.skipChildren();
        }
    }
    return result;
}
```

**Exemple de packument npm** :

```json
{
  "name": "lodash",
  "versions": {
    "4.17.21": {
      "version": "4.17.21",
      "deprecated": false,
      "dist": {
        "tarball": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
      }
    }
  },
  "time": {
    "4.17.21": "2021-01-26T19:36:42.206Z"
  }
}
```

**Parsing pour version "4.17.21"** :

```
1. Chercher "time" objet → FOUND
2. Chercher clé "4.17.21" dans "time" → FOUND
3. Valeur = "2021-01-26T19:36:42.206Z"
4. Instant.parse() → Instant(2021-01-26T19:36:42.206Z)
```

### Formats de Date Supportés

```java
private static Instant parseInstant(String value) {
    if (value.isEmpty()) {
        return null;
    }
    try {
        return Instant.parse(value);  // ISO 8601 parse
    } catch (DateTimeParseException e) {
        return null;
    }
}
```

**Formats acceptés** (ISO 8601) :
- `2024-01-15T10:30:00Z`
- `2024-01-15T10:30:00.123Z`
- `2024-01-15T10:30:00+00:00`

### Gestion de Packuments Abrégés vs Complets

| Format | Champ "time" | Utilisé Pour |
|--------|-------------|------------|
| **Abrégé** (npm.js.org défaut) | ✅ Présent | Public registry lookup |
| **Complet** (`Accept: application/json`) | ✅ Présent | Origin registry fallback |
| **Verdaccio abbreviated** | ❌ Absent | Index only, no date |
| **JSR packument** | ✅ Présent | JSR metadata |

### Normalisation d'URL pour Indexation

```java
private static String normalize(String url) {
    try {
        URI uri = URI.create(url.trim());
        String host = uri.getHost();
        String path = uri.getRawPath();
        
        if (host == null || path == null) {
            return null;
        }
        
        // Format: "https://" + host.lowercase + [:port if non-default] + path + ?query
        StringBuilder key = new StringBuilder("https://")
            .append(host.toLowerCase(Locale.ROOT));
        
        int port = uri.getPort();
        if (port != -1 && port != 443 && port != 80) {
            key.append(':').append(port);
        }
        
        key.append(path);
        if (uri.getRawQuery() != null) {
            key.append('?').append(uri.getRawQuery());
        }
        return key.toString();
    } catch (IllegalArgumentException e) {
        return null;
    }
}
```

**Exemples** :

```
Input:  "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
Output: "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"

Input:  "HTTP://REGISTRY.NPMJS.ORG/lodash/-/lodash-4.17.21.tgz"
Output: "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
        (normalized to https, lowercase host)

Input:  "https://npm.jsr.io:8080/~/{rev}/@jsr/scope__name/1.0.0.tgz"
Output: "https://npm.jsr.io:8080/~/{rev}/@jsr/scope__name/1.0.0.tgz"
        (port included because non-default)
```

### Stockage Multi-Instance

```
┌─────────────────────────────────────────┐
│  Instance 1 (in-memory cache)           │
│  - Map<String, IndexedTarball> index    │
│  - TTL: 10 minutes                      │
│  - Max entries: 50000                   │
└─────────────────────────────────────────┘
            ↓ (si publishedAt != null)
┌─────────────────────────────────────────┐
│  npm_tarball_index (DB shared)          │
│  - Persiste date + packumentUrl         │
│  - TTL configurable (ex. 24h)           │
│  - Répliqué sur toutes les instances    │
└─────────────────────────────────────────┘
            ↓
┌─────────────────────────────────────────┐
│  Instance 2 (own in-memory cache)       │
│  - Cache miss → cherche DB               │
│  - Charge PackageMetadataResult         │
└─────────────────────────────────────────┘
```

### Éviction de Cache

```java
private void evictIfOversized() {
    int excess = index.size() - properties.maxEntries();
    if (excess > 0) {
        // Supprimer les {excess} premières entrées (FIFO)
        index.keySet().stream().limit(excess).toList().forEach(key -> {
            IndexedTarball removed = index.remove(key);
            if (removed != null) {
                byPackage.remove(packageKey(removed.packageName(), 
                                           removed.version()), 
                                removed);
            }
        });
    }
}
```

**Config** :

```yaml
silicaproxy:
  npm-packument-index:
    enabled: true
    max-entries: 50000          # Hard cap en mémoire
    ttl-minutes: 10             # Expire après 10 min
    max-body-bytes: 52428800    # 50MB max par packument
```

---

## Couche 4 : Résolution de Date – Flux Complet

### Diagramme Décisionnel

```
SecurityService.getDecision(packageName, version, "npm")
        │
        ├─ 1. Chercher en cache local (api_cache)
        │       │
        │       └─ ✅ FOUND → Retourner verdict
        │
        ├─ 2. Appeler registryClient.lookupNpmPublic(packageName, version)
        │       │
        │       ├─ GET https://registry.npmjs.org/{packageName}
        │       │
        │       ├─ Status 200 → parseNpmPackument()
        │       │       │
        │       │       ├─ time.{version} FOUND → return PackageMetadataResult
        │       │       └─ time.{version} NOT FOUND → return RegistryLookup.NOT_FOUND
        │       │
        │       ├─ Status 404 → return RegistryLookup.NOT_FOUND
        │       │       │
        │       │       └─ Fallback to Origin Registry
        │       │
        │       └─ Error → return RegistryLookup.UNAVAILABLE
        │
        ├─ 3. Si NOT_FOUND, appeler resolveNpmMetadataFromOrigin()
        │       │
        │       ├─ 3a. npmPackumentIndex.metadata(packageName, version)
        │       │       │ Cherche date dans index relayé
        │       │       │
        │       │       ├─ IN-MEMORY CACHE HIT → return PackageMetadataResult
        │       │       └─ CACHE MISS → cherche DB → return ou empty
        │       │
        │       └─ 3b. Si empty, npmPackumentIndex.originPackumentUrl()
        │               Récupère URL du registre d'origine
        │               │
        │               ├─ JSR: https://npm.jsr.io/@scope/name
        │               ├─ Private Verdaccio: https://verdaccio.internal/@scope/name
        │               └─ Artifactory: https://artifactory.internal/npm-local/@scope/name
        │               │
        │               ├─ registryClient.fetchNpmMetadataFrom(url, version)
        │               │ Full packument re-fetch (pas abbreviated)
        │               │ Accept: application/json
        │               │
        │               ├─ Status 200 → parseNpmPackument() → return date
        │               └─ Error → return empty
        │
        ├─ 4. Si date résolue → caches.metadataCacheDao().savePackagePublishedAt()
        │       Persiste en package_metadata pour future
        │
        └─ 5. checkDeprecationAndQuarantine()
                │
                ├─ Si deprecated → BLOCK (TTL ∞)
                │
                └─ Si âge < minAgeDays → BLOCK "REGISTRY_QUARANTINE"
```

### Exemple Concret : @angular/core@17.0.0

**Scénario** : Client demande `@angular/core@17.0.0`, publié il y a 2 jours

```
GET https://registry.npmjs.org/@angular/core
Accept: application/vnd.npm.install-v1+json
npm-session: abc123...

                    ↓
        Response: 200 OK (packument abrégé)
        Body:
        {
          "name": "@angular/core",
          "versions": {
            "17.0.0": {
              "version": "17.0.0",
              "deprecated": false,
              "dist": {
                "tarball": "https://registry.npmjs.org/@angular/core/-/core-17.0.0.tgz"
              }
            },
            ...
          },
          "time": {
            "17.0.0": "2024-12-23T15:30:00.000Z",
            ...
          }
        }
                    ↓
        1. Index tarball URL
           "@angular/core/-/core-17.0.0.tgz"
           Normalize → "https://registry.npmjs.org/@angular/core/-/core-17.0.0.tgz"
           Store: {
             packageName: "@angular/core",
             version: "17.0.0",
             publishedAt: 2024-12-23T15:30:00Z,
             deprecated: false
           }
                    ↓
        2. Client GET tarballs
           GET https://registry.npmjs.org/@angular/core/-/core-17.0.0.tgz
                    ↓
        3. ProxyController appelle SecurityService.getDecision()
                    ↓
        4. Resolve date:
           a) Package public → registryClient.lookupNpmPublic()
           b) Parse packument → time.17.0.0 = 2024-12-23T15:30:00Z
           c) Persist → package_metadata
                    ↓
        5. checkDeprecationAndQuarantine()
           publishedAt = 2024-12-23T15:30:00Z
           now = 2024-12-25T17:45:00Z
           ageInDays = ChronoUnit.DAYS.between(published, now)
                     = 2 days
           
           minAgeDays = 7
           2 < 7 → QUARANTINE
                    ↓
        ❌ BLOCK "REGISTRY_QUARANTINE"
        Raison: "Package @angular/core version 17.0.0 was published 2 days ago
                 (required threshold: 7 days). Temporarily blocked by 
                 anti-typosquatting quarantine."
```

### Exemple : Package JSR Privé

**Scénario** : Client demande `@jsr/mylib@1.0.0` (n'existe pas sur npm.js.org)

```
1. registryClient.lookupNpmPublic("@jsr/mylib", "1.0.0")
   GET https://registry.npmjs.org/@jsr/mylib
   Response: 404 NOT_FOUND
                    ↓
2. SecurityService.resolveNpmMetadataFromOrigin()
   a) npmPackumentIndex.metadata("@jsr/mylib", "1.0.0")
      Cherche index in-memory
      FOUND → {
        packageName: "@jsr/mylib",
        version: "1.0.0",
        publishedAt: 2024-12-20T10:00:00Z (from relayed packument earlier)
      }
                    ↓
   Retourner date → continue quarantaine
```

### Cas d'Erreur Registre

```
1. registryClient.lookupNpmPublic("@angular/core", "17.0.0")
   GET https://registry.npmjs.org/@angular/core
   → Network timeout
   → RegistryLookup.UNAVAILABLE
                    ↓
2. Chercher cache local (package_metadata)
   SELECT published_at FROM package_metadata 
   WHERE package_name = '@angular/core' 
   AND version = '17.0.0'
                    ↓
   ✅ FOUND (date précédente) → Continuer quarantaine avec date cached
   
   ou
   
   ❌ NOT FOUND → fail-open/fail-closed
                    ↓
   failOpen = true  → ALLOW "REGISTRY_ERROR"
   failOpen = false → BLOCK "REGISTRY_ERROR"
```

---

## Format des Dates dans Packuments

### npm.js.org (Registre Public)

**Format** : ISO 8601, toujours UTC avec `Z`

```json
{
  "time": {
    "17.0.0": "2024-01-15T10:30:00.206Z",
    "17.0.1": "2024-01-16T14:22:33.456Z"
  }
}
```

**Parsing** :
```java
Instant.parse("2024-01-15T10:30:00.206Z")  // Always succeeds
```

### Registres d'Origine (Verdaccio, JSR, Artifactory)

**Format** : Généralement ISO 8601, mais peut varier

```json
{
  "time": {
    "1.0.0": "2024-12-20T10:00:00Z",
    "1.0.1": "2024-12-20T10:15:22.123Z",
    "1.0.2": "2024-12-20 10:30"  // Non-standard, reject
  }
}
```

**Fallback** : Si parse échoue, `publishedAt = null` → date ignorée

---

## Métadonnées Persistées

### Table : package_metadata

```sql
CREATE TABLE package_metadata (
  id BIGSERIAL PRIMARY KEY,
  package_name VARCHAR(500) NOT NULL,
  ecosystem VARCHAR(50) NOT NULL,       -- "npm", "pypi", "maven"
  version VARCHAR(500) NOT NULL,        -- "17.0.0", "17.0.0-rc.1"
  published_at TIMESTAMP NOT NULL,      -- 2024-01-15 10:30:00.206Z
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(package_name, ecosystem, version)
);
```

**Exemple** :
```sql
INSERT INTO package_metadata (package_name, ecosystem, version, published_at)
VALUES ('@angular/core', 'npm', '17.0.0', '2024-01-15 10:30:00.206Z');
```

### Table : npm_tarball_index (Multi-instance Cache)

```sql
CREATE TABLE npm_tarball_index (
  id BIGSERIAL PRIMARY KEY,
  tarball_url_hash VARCHAR(64) UNIQUE NOT NULL,  -- SHA256 of URL
  package_name VARCHAR(500) NOT NULL,
  package_version VARCHAR(500) NOT NULL,
  published_at TIMESTAMP,                        -- Peut être null (abbreviated format)
  is_deprecated BOOLEAN DEFAULT false,
  deprecation_reason VARCHAR(500),
  packument_url VARCHAR(2000),                   -- Registre d'où c'est venu
  indexed_at TIMESTAMP NOT NULL,
  expires_at TIMESTAMP NOT NULL,                 -- TTL
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX (package_name, package_version),
  INDEX (expires_at)
);
```

---

## Configuration npm Spécifique

### Propriétés

```yaml
silicaproxy:
  # Quarantine npm
  quarantine:
    enabled: true
    default-min-age-days: 7
    fail-open: true
    ecosystems:
      npm:
        enabled: true
        min-age-days: 7         # ← SPÉCIFIQUE NPM
  
  # Indexation de packuments npm
  npm-packument-index:
    enabled: true
    max-entries: 50000          # Hard cap pour in-memory cache
    ttl-minutes: 10             # Expire après 10 min
    max-body-bytes: 52428800    # 50MB par packument
```

### Registres Configurés

```yaml
silicaproxy:
  registries:
    npm-url: "${NPM_REGISTRY_URL:https://registry.npmjs.org}"
    # Utilisé pour lookupNpmPublic()
    # Peut être remplacé par Artifactory/Nexus internal mirror
```

---

## Calcul de Quarantaine

### Algorithme Exact

```java
public Optional<DecisionResult> checkDeprecationAndQuarantine(
        String packageName, String version, String ecosystem, 
        PackageMetadataResult metadata) {
    
    if (isDeprecationFilteringEnabled(ecosystem) && metadata.isDeprecated()) {
        return Optional.of(new DecisionResult(
            "REGISTRY_DEPRECATION", "BLOCK", 
            metadata.deprecationReason()
        ));
    }
    
    if (isQuarantineEnabled(ecosystem)) {
        int minAgeDays = getQuarantineMinAgeDays(ecosystem);
        
        // Calcul exact de l'âge
        long ageInDays = ChronoUnit.DAYS.between(
            metadata.publishedAt(),  // Instant (ISO 8601 parsed)
            Instant.now()            // Now in UTC
        );
        
        if (ageInDays < minAgeDays) {
            String reason = String.format(
                "Package %s version %s was published %d days ago"
                + " (required threshold: %d days). Temporarily blocked by "
                + "anti-typosquatting quarantine.",
                packageName, version, ageInDays, minAgeDays
            );
            return Optional.of(new DecisionResult(
                "REGISTRY_QUARANTINE", "BLOCK", reason
            ));
        }
    }
    
    return Optional.empty();  // Pas de quarantine, continuer
}
```

### Exemple Numérique

```
publishedAt = 2024-12-23T15:30:00.000Z (Instant)
now         = 2024-12-25T17:45:30.000Z (Instant.now())

ChronoUnit.DAYS.between(published, now)
= Nombre de jours complets entre les deux
= 2 jours (l'heure exacte est ignorée)

minAgeDays = 7
ageInDays (2) < minAgeDays (7) → QUARANTINE
```

### Edge Cases

**Package publié aujourd'hui**
```
publishedAt = 2024-12-25T23:00:00Z
now         = 2024-12-25T23:59:59Z
ageInDays = 0
0 < 7 → QUARANTINE
```

**Package publié exactement 7 jours ago**
```
publishedAt = 2024-12-18T10:00:00Z
now         = 2024-12-25T10:00:00Z
ageInDays = 7
7 < 7 → FALSE → PASS (autorisé)
```

**Package publié 6 jours + 23h ago**
```
publishedAt = 2024-12-18T01:00:00Z
now         = 2024-12-25T00:00:00Z
ageInDays = 6 (on compte que jours complets)
6 < 7 → QUARANTINE
```

---

## Résumé Flux npm

```
Client request → UrlParserService.parseUrl()
   │
   ├─ Known npm host? → parseNpmUrl() + extract version
   ├─ Unknown host → isNpmClient(headers)?
   │   ├─ Accept: application/vnd.npm.install-v1+json?
   │   ├─ User-Agent: npm/ / pnpm/ / yarn/ / bun/?
   │   └─ npm-* / pacote-* headers?
   └─ Unknown → detectFromPath() + tarball regex
        │
        ├─ NPM_UNSCOPED_TARBALL_PATTERN: ^/([^/]+)/-/\1-([\\d\\.]+.*)\\.tgz$
        └─ NPM_SCOPED_TARBALL_PATTERN: ^/(@[^/]+)/([^/]+)/-/\\2-([\\d\\.]+.*)\\.tgz$
                │
                ├─ packageName + version extracted
                │
                └─ SecurityService.getDecision()
                        │
                        ├─ registryClient.lookupNpmPublic()
                        │   ├─ GET registry.npmjs.org/{packageName}
                        │   └─ Parse: time.{version}
                        │       │
                        │       └─ No 404 → success
                        │           404 → try origin registry
                        │
                        ├─ resolveNpmMetadataFromOrigin() (if 404)
                        │   ├─ npmPackumentIndex.metadata() [in-memory]
                        │   └─ npmPackumentIndex.originPackumentUrl()
                        │       └─ registryClient.fetchNpmMetadataFrom()
                        │           └─ GET {origin} (full format)
                        │
                        └─ checkDeprecationAndQuarantine()
                            ├─ deprecated? → BLOCK (infinite TTL)
                            └─ age < minDays? → BLOCK "REGISTRY_QUARANTINE"
```
