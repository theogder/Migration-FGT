# Fixtures de test

Toutes les configurations de ce répertoire sont **synthétiques**. Elles imitent
la structure d'un backup FortiOS 7.4 mais ne proviennent d'aucun équipement :

- numéros de build, numéros de série et modèles sont fictifs ;
- les adresses IP appartiennent aux plages de documentation (RFC 5737) ou à
  des plages privées arbitraires ;
- les valeurs chiffrées (`ENC ...`), certificats et clés sont des chaînes
  manifestement factices (`FAKE...`, `CANARY-SECRET-...`).

Aucune configuration réelle, même anonymisée, ne doit être ajoutée au dépôt.

- `flat.conf` reproduit le **format** observé sur un extrait anonymisé du
  300E (aucune indentation, en-têtes `#version=` / `#platform=`, ports `ha` et
  `mgmt`, `hbdev` nom / priorité) avec des valeurs entièrement inventées.
- `target-default.conf` reproduit la **structure** observée sur la
  configuration par défaut d'un 120G (ports `x` SFP+ avec `mediatype` /
  `speed`, port `modem`, hard-switch `lan` et son `virtual-switch`,
  agrégat `fortilink`, serveur DHCP par défaut, `config system npu`), en
  multi-VDOM et avec une liste de ports réduite.

Les fichiers `.conf` ne contiennent pas de commentaire explicatif : le
round-trip exige qu'ils soient reproduits octet pour octet.
