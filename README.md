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
| `sanitize`, `diagnose` | disponibles |
| `convert`, `check`, `diff`, `errlog` | à venir |

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
