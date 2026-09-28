# Cahier des charges — `fortimig`
Outil de conversion de configuration FortiGate 300E (FortiOS 7.4.9) → FortiGate 120G

## 1. Contexte

Migration d'un cluster HA de production FortiGate 300E (FortiOS 7.4.9) vers un cluster FortiGate 120G.
FortiConverter n'est pas disponible : la conversion doit être outillée en interne.

Stratégie de migration retenue :

1. Le 120G est installé dans la même version que la source (7.4.9, ou la plus proche supportée par le modèle).
2. La configuration du 300E est convertie par `fortimig` pour le matériel du 120G.
3. La configuration convertie est restaurée sur un 120G de lab, isolé du réseau.
4. Les erreurs remontées par le boîtier (`diagnose debug config-error-log read`) sont analysées et corrigées de manière itérative.
5. Le boîtier est ensuite upgradé vers FortiOS 7.6 en suivant l'upgrade path officiel. **La conversion 7.4 → 7.6 est faite par le firmware, pas par l'outil.**

## 2. Principes non négociables

- **Ne jamais inventer de syntaxe FortiOS.** Si une option, un bloc ou un comportement n'est pas certain, l'outil ne le modifie pas silencieusement : il le signale dans le rapport en catégorie `A_REVOIR`. En cas de doute, signaler plutôt que transformer.
- **Le FortiGate est la source de vérité.** La validation finale de la syntaxe se fait par restauration sur un boîtier réel et lecture du `config-error-log`, pas par l'outil lui-même.
- **Aucune perte silencieuse.** Tout ce qui est supprimé, renommé ou modifié apparaît dans le rapport.
- **Confidentialité.** L'outil ne doit jamais afficher, journaliser ou écrire dans le rapport les secrets de la configuration (voir §7).
- **Aucune action réseau.** L'outil travaille uniquement sur des fichiers locaux. Pas d'API FortiGate, pas de SSH, pas d'appel externe.
- **Déterminisme.** Mêmes entrées → même sortie, octet pour octet.

## 3. Contraintes techniques

- Python ≥ 3.11, **bibliothèque standard uniquement** (poste d'administration potentiellement sans accès internet). `tomllib` pour lire les fichiers de règles.
- Tests avec `pytest` (seule dépendance de développement autorisée).
- Code typé (annotations), lisible, commenté aux endroits spécifiques à FortiOS.
- Utilisable en ligne de commande, sans interface graphique.

## 4. Entrées

| Entrée | Description |
|---|---|
| `source.conf` | Backup complet du 300E (primaire du cluster) |
| `target-default.conf` | Backup de la configuration par défaut d'un 120G vierge, dans la version cible de restauration |
| `mapping.toml` | Table de correspondance des interfaces et paramètres de migration (voir §6) |
| `rules.toml` | Règles de suppression / signalement de blocs et d'options (voir §5.4) |

## 5. Fonctionnalités

### 5.1 Parser / sérialiseur

- Parser le format de configuration FortiOS en arbre ordonné : `config`, `edit`, `set`, `unset`, `append`, `select`, `next`, `end`, lignes d'en-tête `#`.
- Gérer correctement :
  - les valeurs entre guillemets, contenant des espaces et des guillemets échappés ;
  - les valeurs **multi-lignes** entre guillemets (certificats, clés privées, scripts, messages de remplacement) ;
  - les listes de valeurs (`set member "port1" "port2"`) ;
  - les blocs imbriqués sur plusieurs niveaux ;
  - les configurations multi-VDOM (`config global` / `config vdom`) si elles sont présentes ;
  - l'ordre d'origine de tous les éléments (l'ordre des policies est significatif).
- **Exigence de round-trip** : parser puis resérialiser une configuration sans transformation doit produire un fichier identique à l'original. C'est le premier test à faire passer.

### 5.2 Remplacement de l'en-tête

- Remplacer la ligne `#config-version=...` de la source par celle extraite de `target-default.conf`.
- Conserver les autres lignes d'en-tête de la source, sauf indication contraire dans `mapping.toml`.
- Signaler dans le rapport les deux valeurs (avant / après).

### 5.3 Renommage des interfaces

- Renommer les interfaces physiques selon `mapping.toml`.
- Le renommage est **simultané** (une seule passe avec la table complète), jamais séquentiel : un mapping `port1 → port3` et `port3 → port5` ne doit pas produire `port1 → port5`.
- Renommer :
  - les clés `edit "<interface>"` sous `config system interface` ;
  - les références dans les attributs connus pour contenir des noms d'interface. Liste initiale non exhaustive, à maintenir dans le code sous forme de table : `interface`, `srcintf`, `dstintf`, `device`, `member`, `associated-interface`, `hbdev`, `ha-mgmt-interfaces` (sous-bloc), `monitor`, `pingserver-monitor-interface`, `session-sync-dev`, `gateway-address`… Chaque ajout à cette liste doit être justifié en commentaire.
- **Références non couvertes** : après renommage, rechercher dans toute la configuration toute valeur égale à un ancien nom d'interface dans un attribut *non* listé. Ne pas la modifier : la signaler en `A_REVOIR` avec son chemin complet.
- Interface physique source absente du mapping → `ERREUR` bloquante, sauf si elle est explicitement déclarée `drop` dans le mapping. Dans ce cas, lister toutes ses références en `A_REVOIR`.
- Interface cible inexistante dans `target-default.conf` → `ERREUR` bloquante.
- Les interfaces logiques (VLAN, agrégats, zones, tunnels, loopbacks, software switches) conservent leur nom ; seules leurs références vers les interfaces physiques sont mises à jour.
- Les options matérielles d'une interface physique (ex. `speed`, `mediatype`) sont signalées en `A_REVOIR` car elles dépendent du type de port cible (RJ45, SFP, SFP+).

### 5.4 Suppressions et signalements par règles

Piloté par `rules.toml`, sans règles codées en dur :

```toml
[[rule]]
path = "config system npu"      # chemin du bloc
action = "remove"               # remove | flag
reason = "Bloc spécifique NP6 (300E), sans équivalent sur 120G"

[[rule]]
path = "config system global"
option = "exemple-option"
action = "flag"
reason = "Option à vérifier sur le modèle cible"
```

- `remove` : suppression du bloc ou de l'option, tracée en `SUPPRIME`.
- `flag` : aucune modification, tracée en `A_REVOIR`.
- Le fichier de règles initial ne contient **que des règles dont on est certain**. Les autres sont ajoutées au fil des itérations à partir du `config-error-log`.

### 5.5 Interfaces physiques du modèle cible

- Pour chaque port physique présent dans `target-default.conf` mais non utilisé par le mapping, conserver son bloc issu de la configuration par défaut du 120G (à valider sur le lab).
- Signaler en `A_REVOIR` les objets de la configuration par défaut du 120G qui disparaîtront avec la restauration (ex. hardware/virtual switch par défaut, adressage par défaut, serveur DHCP par défaut).

### 5.6 Haute disponibilité

- Appliquer le mapping aux paramètres HA (`hbdev`, `session-sync-dev`, `monitor`, interfaces de management réservées).
- Appliquer la priorité et le hostname du primaire définis dans `mapping.toml`.
- Générer un fichier `secondary-ha.txt` contenant uniquement le bloc CLI `config system ha` (et le hostname) à appliquer sur le second 120G vierge, cohérent avec le primaire : même `group-id`, même `group-name`, `hbdev` identiques, priorité différente. Le mot de passe HA n'est **pas** écrit dans ce fichier : remplacer par un marqueur explicite `<A_RENSEIGNER>`.

### 5.7 Contrôle d'intégrité des références

Commande dédiée, exécutable sur n'importe quelle configuration (source ou convertie) :

- références vers des interfaces, zones, adresses, groupes, services, profils ou certificats inexistants ;
- zones et agrégats vides ;
- interfaces référencées mais absentes de `config system interface`.

Chaque anomalie est reportée avec son chemin complet dans l'arbre.

### 5.8 Diff

- Produire un diff lisible entre la source et la configuration convertie, en **ignorant les secrets** (masqués des deux côtés).
- Regrouper les différences par bloc `config`.

### 5.9 Anonymisation (`sanitize`)

Produire une version de la configuration partageable (notamment avec un assistant IA) :

- masquer tous les secrets (§7) ;
- en option (`--ips`), remplacer les adresses IP par des adresses cohérentes et déterministes (même IP source → même IP de remplacement, masques et appartenance aux sous-réseaux préservés) ;
- en option (`--names`), remplacer les noms d'objets, de policies, de comptes et les commentaires par des identifiants génériques déterministes ;
- ne jamais modifier les noms d'interfaces physiques ni les mots-clés FortiOS.
- La table de correspondance d'anonymisation est écrite dans un fichier séparé, clairement signalé comme sensible.

### 5.10 Analyse du `config-error-log`

- Parser la sortie de `diagnose debug config-error-log read` collée dans un fichier texte.
- Pour chaque erreur, retrouver si possible la ligne et le bloc correspondants dans la configuration convertie.
- Produire un rapport regroupé par bloc, pour faciliter l'ajout de règles dans `rules.toml`.

## 6. Fichier de mapping

```toml
[device]
hostname = "FW-PROD-01"
ha_priority_primary = 200
ha_priority_secondary = 100

[interfaces]
# source (300E) = cible (120G) — valeurs à définir selon le plan de câblage
"port1"  = "port1"
"port2"  = "port2"
"port17" = "x1"
"mgmt1"  = "mgmt"
"ha1"    = "ha"
"port30" = "drop"   # port non utilisé, explicitement abandonné
```

Les noms ci-dessus sont des exemples : les noms réels du 120G sont ceux présents dans `target-default.conf`.

## 7. Gestion des secrets

Sont considérés comme secrets, au minimum : toute valeur `ENC ...`, `password`, `passwd`, `psksecret`, `secret`, `key` / `private-key`, `passphrase`, les blocs de certificats et clés PEM, les secrets RADIUS / LDAP / TACACS+, les clés SNMP, les tokens et clés d'API.

- Ils sont conservés tels quels dans la configuration convertie (le boîtier doit pouvoir les déchiffrer).
- Ils ne doivent **jamais** apparaître dans : la sortie console, les logs, les rapports, les diffs, les messages d'erreur, les fixtures de test.
- Si `private-data-encryption` est activé dans la source, émettre un avertissement en tête du rapport (la clé devra être positionnée sur le 120G avant restauration).

## 8. Interface en ligne de commande

```
fortimig convert  --source S --target-default T --mapping M --rules R --out DIR
fortimig check    --config C [--target-default T]
fortimig diff     --before A --after B
fortimig sanitize --config C --out F [--ips] [--names]
fortimig errlog   --log L --config C
```

`convert` produit dans `DIR` : la configuration convertie, `secondary-ha.txt`, `report.md`, `report.json`.

Codes de sortie : `0` succès sans point à revoir, `1` succès avec des `A_REVOIR`, `2` erreur bloquante (aucune configuration écrite).

## 9. Rapport de conversion

Deux formats : `report.md` (lecture humaine) et `report.json` (exploitable par script).

Catégories :

- `MODIFIE` : élément transformé (avant / après, secrets masqués) ;
- `SUPPRIME` : élément retiré, avec la règle ou la raison ;
- `A_REVOIR` : élément non modifié mais nécessitant une décision humaine ;
- `ERREUR` : anomalie bloquante.

Chaque entrée indique le chemin complet dans l'arbre (ex. `config firewall policy > edit 42 > set srcintf`).
En tête du rapport : résumé chiffré par catégorie et liste des avertissements globaux.

## 10. Tests

- Round-trip sur des configurations d'exemple (§5.1).
- Valeurs multi-lignes, guillemets échappés, listes, imbrication profonde.
- Renommage simultané avec mappings croisés et circulaires.
- Détection des références non couvertes.
- Interface non mappée / cible inexistante → erreur bloquante.
- Absence de tout secret dans les rapports, diffs et sorties console (test dédié qui injecte des secrets reconnaissables et vérifie qu'ils ne fuient nulle part).
- Déterminisme de `sanitize`.
- Toutes les fixtures sont **synthétiques**. Aucune configuration réelle dans le dépôt.

## 11. Hors périmètre

- La conversion syntaxique 7.4 → 7.6 (assurée par l'upgrade de firmware).
- La migration du SSL VPN mode tunnel vers IPsec, si elle est nécessaire (décision d'architecture, traitée à part).
- Toute interaction avec un équipement ou un service réseau.
- Le support d'autres couples de modèles (le code doit toutefois rester générique : aucun nom de port en dur hors du mapping et des fixtures).

## 12. Procédure d'utilisation visée

1. Anonymiser un extrait de la configuration réelle avec `sanitize` pour les échanges éventuels avec un assistant.
2. Exécuter `convert` localement sur la vraie configuration.
3. Traiter toutes les `ERREUR`, puis revoir les `A_REVOIR`.
4. Restaurer sur le 120G de lab isolé.
5. Récupérer le `config-error-log`, l'analyser avec `errlog`, compléter `rules.toml`.
6. Répéter 2 à 5 jusqu'à un log d'erreurs vide et un diff validé.
7. Upgrader le lab en 7.6 selon l'upgrade path, relire le `config-error-log`.
8. Recette fonctionnelle, puis bascule.
