# Décisions validées

Complément à `SPEC.md` (qui fait foi) : choix de conception validés avec
l'ingénieur de production, et incertitudes FortiOS en suspens.

## Décisions

| # | Sujet | Décision |
|---|---|---|
| D1 | Multi-VDOM | La source **est** multi-VDOM. Si le champ `vdom=` de `#config-version` diffère entre la source et `target-default.conf`, c'est une `ERREUR` (pas de transformation silencieuse). Le backup de la configuration par défaut du 120G doit donc être pris **après** activation du mode multi-VDOM sur le boîtier de lab. |
| D2 | En-tête | Seule la ligne `#config-version` est remplacée par défaut. Une section optionnelle `[header]` de `mapping.toml` (ex. `from_target = ["buildno"]`) permet de reprendre d'autres lignes de la cible. |
| D3 | Interface `drop` | Son bloc `edit` sous `config system interface` est supprimé (`SUPPRIME`) ; ses références restent intactes et sont signalées en `A_REVOIR`. |
| D4 | Port mappé | Le bloc de la source est repris et renommé, sans fusion avec le bloc par défaut du 120G. Les options matérielles sont signalées. |
| D5 | Ports cibles inutilisés | Leurs blocs issus de `target-default.conf` sont insérés juste après le dernier port physique, sans réordonner le reste. |
| D6 | Hostname du secondaire | Nouvelle clé `hostname_secondary` dans `[device]` de `mapping.toml`. |
| D7 | `secondary-ha.txt` | Copie intégrale du bloc `config system ha` du primaire converti, priorité remplacée, `set password <A_RENSEIGNER>`, précédée de `config system global` / `set hostname`. Pas de commentaires `#` dans le fichier ; les remarques vont dans le rapport. L'IP de management réservée du secondaire est seulement signalée. |
| D8 | `check` | Références introuvables en `A_REVOIR`. Les objets intégrés absents des backups sont déclarés dans une liste modifiable. |
| D9 | `sanitize --ips` | Anonymisation préservant les préfixes, graine optionnelle. Masques et adresses spéciales inchangés. La distinction privé / public est **conservée** (une adresse privée reste dans sa plage privée). IPv6 non traité (non utilisé). |
| D10 | Sortie de `convert` | `DIR/converted.conf`, `DIR/secondary-ha.txt`, `DIR/report.md`, `DIR/report.json`. |

## Choix d'implémentation (à valider au fil de l'eau)

| # | Sujet | Choix |
|---|---|---|
| I1 | Round-trip | Chaque nœud garde son texte brut ; seuls les nœuds dont le contenu a changé sont régénérés. Lecture en UTF-8 avec `surrogateescape` : tout octet est restitué à l'identique. |
| I2 | Messages d'erreur de parsing | Numéros de ligne uniquement, jamais le contenu (qui peut être un secret). |
| I3 | Marqueur de secret | `<SECRET-MASQUE>` ; pour une valeur chiffrée, le mot-clé est conservé : `set password ENC <SECRET-MASQUE>`. Pas d'empreinte (hash) des secrets : elle permettrait une attaque hors ligne sur les secrets faibles. |
| I4 | Garde anti-fuite | Toutes les valeurs secrètes de la source (et chaque ligne des PEM) sont recherchées dans chaque sortie ; toute occurrence est remplacée par le marqueur et comptée. |
| I5 | `sanitize` : options ajoutées | `--seed` (graine des IP ; avertissement si absente) et `--keep-names-from CONF` (noms d'une configuration de référence, typiquement `target-default.conf`, conservés car objets d'usine). |
| I6 | `sanitize --ips` : adresses de réseau | Une adresse suivie d'un masque (`set subnet A M`) ou en notation `A/len`, à bits d'hôte nuls, est remplacée par `f(A) & masque` : l'image reste une adresse de réseau et contient l'image de ses hôtes. Les masques ne sont jamais modifiés. |
| I7 | `sanitize --names` : périmètre | Clés d'`edit` entre guillemets (hors interfaces physiques), noms de VDOM (sauf `root`), options `name`, `hostname`, `alias`, `group-name`, `username`, et commentaires (`comment`, `comments`, `description`). Remplacement par jeton exact, uniquement sur les valeurs entre guillemets : les mots-clés ne sont jamais touchés. **Non couverts** (signalés en nombre) : `fqdn`, `dn`, `server`, `domain`, `email`… à relire avant partage. |
| I8 | `sanitize` : lignes non reconnues | Masquées entièrement (`# <LIGNE MASQUEE PAR SANITIZE>`), leur contenu n'ayant pas pu être analysé. L'en-tête `#config-version` est conservé. |

## Incertitudes FortiOS en suspens

À lever avec des extraits anonymisés et le `config-error-log` du lab.

| # | Point | Traitement actuel |
|---|---|---|
| U1 | Échappements entre guillemets : seuls `\"` et `\\` sont supposés. Guillemets simples supposés non délimiteurs. | Texte brut conservé : sans impact sur le round-trip, seulement sur la valeur décodée. |
| U2 | Présence systématique de `set type physical` pour les ports physiques (y compris mgmt, ha, `npu0_vlink*`) dans un backup ; absence possible de `set type vlan` pour les VLAN (`vlan` étant le type par défaut). | Physique = `type physical`, ou `type` absent **et** pas de `vlanid` (prudent). À confirmer avant l'étape 3. |
| U3 | Existence de `config system npu` sur un 120G (SoC SP5). | Règle initiale en `flag`, pas en `remove`. |
| U4 | Attribut `gateway-address` cité dans la SPEC : contexte inconnu. | À préciser. |
| U5 | Format exact de `diagnose debug config-error-log read`. | Étape 8 sur extraits réels. |
| U6 | `snmp-index` des ports repris du 300E : conflit possible sur le 120G. | `A_REVOIR`, non transformé. |
| U8 | Liste des noms d'options secrètes (voir `fortimig/secrets.py`). | Masquage par dernier segment du nom (`password`, `secret`, `key`, `pwd`...), par valeur (`ENC`, PEM) et par contexte (communauté SNMP). Tout secret non détecté signalé par vos extraits sera ajouté. |
| U7 | Indentation des blocs sous `config global` / `config vdom` dans un backup multi-VDOM (colonne 0 supposée). | Sans impact : texte brut conservé, les nœuds régénérés prennent l'indentation de leurs voisins. |
