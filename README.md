# fortimig

Outil interne de conversion de configuration FortiGate 300E (FortiOS 7.4.9)
vers FortiGate 120G. Cahier des charges : [`SPEC.md`](SPEC.md).
Décisions et incertitudes FortiOS : [`DECISIONS.md`](DECISIONS.md).

Python ≥ 3.11, bibliothèque standard uniquement, aucune action réseau.

## Utilisation

Sans installation :

```
python -m fortimig <commande> ...
```

ou après `pip install -e .` : `fortimig <commande> ...`

### État d'avancement

| Commande | État |
|---|---|
| `convert`, `mapping-template`, `errlog`, `sanitize`, `diagnose` | disponibles |
| `check`, `diff` | à venir |

### Convertir

1. Générer un squelette de mapping (aucune correspondance n'est proposée) :

   ```
   python -m fortimig mapping-template --source 300E.conf --target-default 120G-default.conf --out mapping.toml
   ```

   Remplacer chaque `A_DEFINIR` par un port du 120G ou par `"drop"`, et
   compléter `[device]`.

2. Convertir :

   ```
   python -m fortimig convert --source 300E.conf --target-default 120G-default.conf \
       --mapping mapping.toml --rules rules.toml --out sortie/
   ```

   `sortie/` contient `converted.conf`, `secondary-ha.txt`, `report.md` et
   `report.json`. Codes de sortie : `0` sans point à revoir, `1` avec des
   `A_REVOIR`, `2` erreur bloquante (aucune configuration écrite, et une
   configuration d'une exécution précédente est supprimée).

   `target-default.conf` : backup du 120G **en usine, dans la version de la
   source, en multi-VDOM** si la source l'est.

### Analyser le journal d'erreurs du 120G de lab

Après restauration de `converted.conf`, coller la sortie de
`diagnose debug config-error-log read` dans un fichier texte, puis :

```
python -m fortimig errlog --log errlog.txt --config sortie/converted.conf
```

Chaque erreur est retrouvée dans `converted.conf` (ligne, chemin), regroupée
par bloc, avec une règle `rules.toml` proposée — jamais appliquée
automatiquement.

### Anonymiser un extrait avant de le partager

```
python -m fortimig sanitize --config extrait.conf --out extrait-anonyme.conf \
    --ips --names --seed "<graine connue de vous seul>" \
    --keep-names-from target-default.conf
```

- Les secrets sont toujours masqués (`<SECRET-MASQUE>`).
- `--ips` : adresses IPv4 remplacées de façon déterministe (sous-réseaux et
  classes privé / public préservés, masques inchangés).
- `--names` : noms d'objets, de policies, de comptes et commentaires remplacés
  par des identifiants génériques. Les interfaces physiques et mots-clés ne
  sont jamais modifiés. Les FQDN, DN, serveurs et e-mails ne sont **pas**
  traités : leur nombre est signalé, relisez-les avant partage.
- La table de correspondance est écrite dans `extrait-anonyme.conf.SENSIBLE.json` :
  **ne jamais la partager ni la committer** (exclue par `.gitignore`).

### Si la lecture d'une configuration échoue

Le message d'erreur donne la ligne, les blocs ouverts et la dernière valeur
multi-lignes lue, sans jamais afficher de contenu. Pour voir la structure
autour de la ligne en cause, **toujours sans aucune valeur** (sortie partageable) :

```
python -m fortimig diagnose --config backup.conf --line 14242
```

## Tests

```
pip install pytest
python -m pytest
```

Toutes les fixtures (`tests/fixtures/`) sont synthétiques.
