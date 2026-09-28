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

## Incertitudes FortiOS en suspens

À lever avec des extraits anonymisés et le `config-error-log` du lab.

| # | Point | Traitement actuel |
|---|---|---|
| U1 | Échappements entre guillemets : seuls `\"` et `\\` sont supposés. Guillemets simples supposés non délimiteurs. | Texte brut conservé : sans impact sur le round-trip, seulement sur la valeur décodée. |
| U2 | Présence systématique de `set type physical` pour les ports physiques (y compris mgmt, ha, `npu0_vlink*`) dans un backup. | À confirmer avant l'étape 3. |
| U3 | Existence de `config system npu` sur un 120G (SoC SP5). | Règle initiale en `flag`, pas en `remove`. |
| U4 | Attribut `gateway-address` cité dans la SPEC : contexte inconnu. | À préciser. |
| U5 | Format exact de `diagnose debug config-error-log read`. | Étape 8 sur extraits réels. |
| U6 | `snmp-index` des ports repris du 300E : conflit possible sur le 120G. | `A_REVOIR`, non transformé. |
| U7 | Indentation des blocs sous `config global` / `config vdom` dans un backup multi-VDOM (colonne 0 supposée). | Sans impact : texte brut conservé, les nœuds régénérés prennent l'indentation de leurs voisins. |
