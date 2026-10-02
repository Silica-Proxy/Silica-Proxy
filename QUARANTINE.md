# Mécanisme de Quarantaine – Anti-Typosquatting

## Principes Généraux

La **quarantaine temporelle** bloque l'accès aux packages recemment publiés (moins de N jours) pour prévenir les attaques de **typosquatting**. C'est un mécanisme de protection par l'âge : les nouveaux packages suspects reçoivent un délai de vérification avant d'être utilisables, limitant le temps disponible pour une attaque.

### Flux de Décision

```
1. Requête → Chercher metadata (publish date) du registre
2. Si date trouvée → Vérifier âge du package
3. Si âge < minAgeDays → BLOCK (quarantaine)
4. Si âge >= minAgeDays → Continuer (OSV/deps.dev)
```

### Gestion des Dates de Publication

Le proxy utilise une **hiérarchie de sources** pour obtenir la date de publication :

1. **Registre Public** (autoritaire) – toujours prioritaire si présent
   - npm.js.org pour npm
   - pypi.org pour PyPI
   - Maven Central pour Maven

2. **Cache Local** (fallback)
   - Si le registre public est temporairement indisponible, la proxy utilise `package_metadata` (base de données)
   - Permet la continuité même lors d'une panne réseau

3. **Registres d'Origine** (npm uniquement, pour packages JSR ou privés)
   - Consulté SEULEMENT si le registre public retourne NOT_FOUND
   - Récupère la date du packument relayé par le client ou re-fetch la version complète

---

## Configuration

```yaml
silicaproxy:
  quarantine:
    enabled: true                    # Activation globale
    default-min-age-days: 7          # Seuil par défaut si non spécifié
    fail-open: true                  # true: ALLOW si registre indisponible | false: BLOCK
    ecosystems:
      npm:
        enabled: true
        min-age-days: 7
      maven:
        enabled: false               # Désactivé pour Maven
        min-age-days: 5
      pypi:
        enabled: true
        min-age-days: 10
```

---

## Écosystème : npm

### Résolution de la Date de Publication

**1. Registre Public npm.js.org (Autoritaire)**
- **Format** : packument abrégé ou complet
- **Champ utilisé** : `time[version]` ou `time.modified`
- **Fiabilité** : ✅ Toujours présent

**2. Registres Privés / JSR**
- Accédés SEULEMENT si npm.js.org retourne 404 (package absent)
- Source : packument relayé par le client OU full packument refetch
- Raison : isoler les packages scoped privés ou JSR du registre public

**3. Cache Local**
- Si registre public indisponible ET date connue localement → utilise cache
- Sinon → fail-open/fail-closed selon configuration

### Exemple

**Package : `@angular/core@17.0.0` publié il y a 2 jours**

```
Âge = 2 jours
minAgeDays = 7
2 < 7 → ❌ BLOCK "REGISTRY_QUARANTINE"

Raison : "Package @angular/core version 17.0.0 was published 2 days ago
          (required threshold: 7 days). Temporarily blocked by 
          anti-typosquatting quarantine."
```

---

## Écosystème : PyPI

### Résolution de la Date de Publication

**1. Registre Public PyPI**
- **Endpoint** : `/pypi/{package}/json`
- **Champ utilisé** : `releases[version][0].upload_time` (ISO 8601)
- **Fiabilité** : ✅ Toujours présent
- **Particularité** : supporte les packages yanked (voir **Filtrage de Dépreciation**)

**2. Cache Local**
- Utilisé si PyPI indisponible et date déjà connue

### Configuration

```yaml
pypi:
  enabled: true
  min-age-days: 10  # Seuil plus strict que npm (7 jours)
```

### Exemple

**Package : `requests@2.30.0` publié il y a 5 jours**

```
Âge = 5 jours
minAgeDays = 10
5 < 10 → ❌ BLOCK "REGISTRY_QUARANTINE"

Raison : "Package requests version 2.30.0 was published 5 days ago
          (required threshold: 10 days). Temporarily blocked by 
          anti-typosquatting quarantine."
```

### Distinction avec Yanked

**Yanked** (obsolescence durable) ≠ **Quarantine** (temporaire)

- **Yanked** : le package existe mais est marqué comme supprimé par le mainteneur → ❌ BLOCK "REGISTRY_DEPRECATION" (TTL infinie)
- **Quarantine** : package récent valide, blocage temporaire → ❌ BLOCK "REGISTRY_QUARANTINE" (pas de cache)

---

## Écosystème : Maven

### Résolution de la Date de Publication

**1. Registre Public Maven Central**
- **Endpoint** : `HEAD /maven2/{groupId}/{artifactId}/{version}/{artifactId}-{version}.jar`
- **En-tête utilisé** : `Last-Modified` (HTTP date format)
- **Fiabilité** : ✅ Toujours présent (HTTP 2xx)

**2. Cache Local**
- Utilisé si Maven Central indisponible et date déjà cachée

### Configuration

```yaml
maven:
  enabled: false          # 🔴 Désactivé par défaut
  min-age-days: 5
```

**⚠️ Statut** : Quarantaine Maven est **désactivée par défaut** car :
- Maven Central n'est pas l'écosystème cible principal de SilicaProxy v1
- Les artefacts Maven transiteraient moins par des vecteurs de typosquatting public
- Peut être réactivée pour des déploiements spécialisés

### Exemple (si activée)

**Artefact : `com.example:new-library:1.0.0` publié il y a 3 jours**

```
Âge = 3 jours
minAgeDays = 5
3 < 5 → ❌ BLOCK "REGISTRY_QUARANTINE"

Raison : "Package com.example:new-library version 1.0.0 was published 3 days ago
          (required threshold: 5 days). Temporarily blocked by 
          anti-typosquatting quarantine."
```

---

## Gestion des Erreurs Registre

### Fail-Open (Défaut : `true`)

Si la requête au registre échoue ET aucune date cachée disponible :

```
failOpen = true → ✅ ALLOW
Raison : "Fail open due to public registry unavailability."
```

**Usage** : Environnements où une courte indisponibilité du registre ne doit pas casser les builds.

### Fail-Closed (`false`)

```
failOpen = false → ❌ BLOCK
Raison : "Public registry is unreachable and proxy is configured in fail-closed."
```

**Usage** : Environnements où sécurité > disponibilité (ex. production, contextes réglementés).

---

## Caching et Persistance

### Table : `package_metadata`

```sql
CREATE TABLE package_metadata (
  id SERIAL PRIMARY KEY,
  package_name VARCHAR NOT NULL,
  ecosystem VARCHAR NOT NULL,
  version VARCHAR NOT NULL,
  published_at TIMESTAMP NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(package_name, ecosystem, version)
);
```

**Comportement** : 
- Chaque résolution de date est enregistrée (idempotent)
- Permet la quarantaine même lors de panne registre transitoire
- Pas de TTL : l'âge n'a qu'un sens croissant (date de publication = immuable)

### Absence de Cache pour Quarantine

La date elle-même EST cachée, mais le **verdict QUARANTINE n'est jamais écrit en cache** (`api_cache`) car :
- L'âge change continuellement (diminue avec le temps)
- Après minAgeDays jours, le même package devient autorisé
- Cacher le verdict bloquerait le package après son déblocage naturel

---

## Interactions avec Autres Mécanismes

### 1. Dépreciation/Yanked

Évalué **avant** quarantaine dans le flux :

```
1. Registre inaccessible? → fail-open/fail-closed
2. Package deprecated/yanked? → ❌ BLOCK "REGISTRY_DEPRECATION" (TTL ∞)
3. Package trop jeune? → ❌ BLOCK "REGISTRY_QUARANTINE" (pas de cache)
4. Vulnérabilités externes? → OSV/deps.dev
```

### 2. Seuils de Sévérité

Complètement indépendants :

- **Quarantine** : basée sur AGE
- **Sévérité** : basée sur CVSS/CVE

Un package peut :
- Être **en quarantaine** (par l'âge)
- Avoir des **vulnérabilités LOW** (passe sévérité)
- → Verdict : ❌ BLOCK (quarantaine prioritaire)

### 3. Validation Externe

Sautée si quarantaine/dépreciation détectée (short-circuit).

---

## Calcul de l'Âge

```java
long ageInDays = ChronoUnit.DAYS.between(metadata.publishedAt(), Instant.now());
if (ageInDays < minAgeDays) {
    // BLOCK
}
```

**Précision** : jours calendaires complets (00:00 UTC)

**Exemples** :
- Publié hier à 23:59 UTC → Âge = 0 jours
- Publié hier à 00:00 UTC → Âge = 1 jour
- Publié 7 jours ago → Âge = 7 jours

---

## Insights Operationnels

### Mettriques Exposées

```
metrics.recordPublishDateLookup(ecosystem, dateSource)
  → "npm", "public_registry" | "origin_registry" | "local_cache" | "unresolved"
```

### Logging

```
WARN "Unable to retrieve registry metadata for npm/package (version). failOpen=true"
REGISTRY_QUARANTINE verdict → package {name} version {ver} was published {age} days ago...
```

### Tuning par Écosystème

| Écosystème | minAgeDays | Enabled | Raison |
|-----------|-----------|---------|---------|
| npm | 7 | ✅ | Typosquatting courant, délai court |
| pypi | 10 | ✅ | Écosystème Python, délai plus prudent |
| maven | 5 | ❌ | Hors-scope v1, non activé |

---

## Résumé

La **quarantaine temporelle** est un mécanisme **rapide, sans faux positifs** qui ralentit les attaques de typosquatting sans nécessiter de renseignement externe. Elle s'appuie sur des **dates de publication immuables** et **cachées persistamment**, offrant une protection même lors de pannes réseau brèves.
