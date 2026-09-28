# Fixtures de test

Toutes les configurations de ce répertoire sont **synthétiques**. Elles imitent
la structure d'un backup FortiOS 7.4 mais ne proviennent d'aucun équipement :

- numéros de build, numéros de série et modèles sont fictifs ;
- les adresses IP appartiennent aux plages de documentation (RFC 5737) ou à
  des plages privées arbitraires ;
- les valeurs chiffrées (`ENC ...`), certificats et clés sont des chaînes
  manifestement factices (`FAKE...`, `CANARY-SECRET-...`).

Aucune configuration réelle, même anonymisée, ne doit être ajoutée au dépôt.

Les fichiers `.conf` ne contiennent pas de commentaire explicatif : le
round-trip exige qu'ils soient reproduits octet pour octet.
