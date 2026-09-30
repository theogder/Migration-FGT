# fortimig — migration FortiGate 300E → 120G

`fortimig` est un outil interne qui **convertit la configuration d'un cluster
FortiGate 300E (FortiOS 7.4.9) pour qu'elle soit restaurable sur un
FortiGate 120G**, sans FortiConverter.

Ce document est une **procédure pas à pas**. Il est écrit pour quelqu'un qui
n'a jamais utilisé l'outil : suivez les étapes dans l'ordre et recopiez les
commandes.

> **Ce que fait l'outil** : il lit des fichiers de configuration sur votre
> poste et produit des fichiers. **Il ne se connecte à aucun équipement**
> (pas de SSH, pas d'API, pas d'Internet).
>
> **Ce qu'il ne fait pas** : il ne restaure rien sur un FortiGate, il ne fait
> pas la montée de version 7.4 → 7.6 (c'est le firmware qui s'en charge), et
> il ne remplace pas la validation sur un boîtier de lab.

---

## Sommaire

0. [Vue d'ensemble](#0-vue-densemble)
1. [Règles de sécurité à lire avant de commencer](#1-règles-de-sécurité-à-lire-avant-de-commencer)
2. [Installer l'outil sur son poste](#2-installer-loutil-sur-son-poste)
3. [Étape A — Récupérer les deux fichiers de configuration](#3-étape-a--récupérer-les-deux-fichiers-de-configuration)
4. [Étape B — Écrire le fichier `mapping.toml`](#4-étape-b--écrire-le-fichier-mappingtoml)
5. [Étape C — Lancer la conversion](#5-étape-c--lancer-la-conversion)
6. [Étape D — Lire et traiter le rapport](#6-étape-d--lire-et-traiter-le-rapport)
7. [Étape E — Restaurer sur le 120G de lab et lire le journal d'erreurs](#7-étape-e--restaurer-sur-le-120g-de-lab-et-lire-le-journal-derreurs)
8. [Étape F — Vérifier le fonctionnement sur le lab](#8-étape-f--vérifier-le-fonctionnement-sur-le-lab)
9. [Étape G — Monter le cluster HA avec le second 120G](#9-étape-g--monter-le-cluster-ha-avec-le-second-120g)
10. [Étape H — Monter en version 7.6](#10-étape-h--monter-en-version-76)
11. [Étape I — Bascule en production](#11-étape-i--bascule-en-production)
12. [Partager un extrait anonymisé (`sanitize`)](#12-partager-un-extrait-anonymisé-sanitize)
13. [Le fichier `rules.toml`](#13-le-fichier-rulestoml)
14. [Dépannage](#14-dépannage)
15. [Référence de toutes les commandes](#15-référence-de-toutes-les-commandes)
16. [Contenu du projet et informations pour les développeurs](#16-contenu-du-projet-et-informations-pour-les-développeurs)

---

## 0. Vue d'ensemble

```
   300E (production)                          120G de lab (isolé)
   ─────────────────                          ───────────────────
   A. backup direct  ──┐               ┌──  A. remise en usine + backup
                       ▼               ▼
                 B. mapping.toml (quel port 300E → quel port 120G)
                                 │
                                 ▼
                 C. fortimig convert  ──►  converted.conf
                                           secondary-ha.txt
                                           report.md / report.json
                                 │
                                 ▼
                 D. traiter les ERREUR et A_REVOIR du rapport
                                 │
                                 ▼
                 E. restaurer converted.conf sur le lab
                    lire le config-error-log  ──►  fortimig errlog
                    compléter rules.toml, reconvertir   (boucle
                    jusqu'à un journal vide)             E ↺ C)
                                 │
                                 ▼
          F. tests fonctionnels   G. cluster HA   H. montée en 7.6
                                 │
                                 ▼
                         I. bascule en production
```

Temps indicatif pour une première conversion, une fois les fichiers en main :
30 minutes à 1 heure (surtout pour écrire `mapping.toml`).

---

## 1. Règles de sécurité à lire avant de commencer

1. **Aucune configuration réelle dans le dépôt Git.** Ni backup, ni
   `mapping.toml` réel, ni rapport, ni fichier `*.SENSIBLE.json`. Travaillez
   dans le dossier **`work/`** du projet : il est ignoré par Git (voir
   `.gitignore`).
2. **Les secrets restent dans `converted.conf`** (le boîtier doit pouvoir les
   déchiffrer). Ce fichier est donc **aussi sensible que le backup du 300E** :
   ne l'envoyez à personne, ne le déposez nulle part hors de votre poste et du
   lab.
3. **Les rapports, la console et `secondary-ha.txt` ne contiennent jamais de
   secret** : ils sont masqués (`<SECRET-MASQUE>`). Ils contiennent en revanche
   des noms d'objets et des adresses IP réels : relisez avant de partager.
4. **Pour demander de l'aide avec un extrait de configuration**, passez-le
   d'abord par `sanitize` (section 12). Ne partagez **jamais** le fichier
   `*.SENSIBLE.json` produit à côté.
5. **Le 120G de lab doit être totalement isolé** du réseau de production
   (explications en section 7).

---

## 2. Installer l'outil sur son poste

### 2.1 Prérequis

- **Python 3.11 ou plus récent.** Aucune autre bibliothèque n'est nécessaire,
  aucun accès Internet n'est nécessaire.
- **Git** (ou simplement l'archive ZIP du projet).

Vérifier la version de Python :

```
python --version
```

Sous Windows, si `python` n'est pas reconnu ou donne une version plus
ancienne, utilisez le lanceur `py` :

```
py -3.11 --version
```

> **Sous Windows**, dans toutes les commandes de ce document, remplacez
> `python` par `py -3.11` si nécessaire.

### 2.2 Récupérer le projet

```
git clone https://github.com/theogder/Migration-FGT.git
cd Migration-FGT
```

Pour mettre à jour plus tard :

```
git pull
```

### 2.3 Vérifier que l'outil fonctionne

Depuis le dossier `Migration-FGT` :

```
python -m fortimig --help
```

Vous devez voir la liste des commandes (`convert`, `mapping-template`,
`errlog`, …). Aucune installation supplémentaire n'est requise : l'outil se
lance toujours avec `python -m fortimig <commande>` **depuis le dossier du
projet**.

### 2.4 Préparer le dossier de travail

```
mkdir work
```

Tous vos fichiers réels (backups, `mapping.toml`, sorties) iront dans
`work/`. Dans la suite, les chemins sont écrits `work/...`.

---

## 3. Étape A — Récupérer les deux fichiers de configuration

Il faut **deux** fichiers :

| Fichier | Contenu | Nom conseillé |
|---|---|---|
| Source | backup complet du 300E primaire | `work/300E.conf` |
| Cible par défaut | backup du 120G **remis en usine** | `work/120G-usine.conf` |

### A.1 Backup du 300E (source)

1. **Faire le backup directement sur le FortiGate**, pas depuis FortiManager.
   Un export FortiManager a un en-tête et un format différents (constaté :
   `7.00`, sans indentation) et ne convient pas.
2. Interface web du 300E : menu de l'administrateur (en haut à droite) →
   **Configuration** → **Backup**. En multi-VDOM, choisir la portée
   **Global**. Ne pas chiffrer le fichier.
3. Enregistrer le fichier sous `work/300E.conf`.
4. **Vérifier la première ligne** du fichier (ouvrez-le avec un éditeur de
   texte) :

   ```
   #config-version=FG3H0E-7.4.9-FW-build2829-...:opmode=0:vdom=1:user=...
   ```

   - `7.4.9` et `build2829` : version du 300E ;
   - `vdom=1` : le 300E est en multi-VDOM.

### A.2 Préparation du 120G de lab et backup d'usine (cible)

Le 120G de lab doit être **dans la même version que le 300E** et **dans le
même mode VDOM**.

1. **Installer la même version** que le 300E (ici 7.4.9 build 2829) : menu
   **System** → **Firmware & Registration** (ou via une clé USB). Vérifier en
   CLI :

   ```
   get system status
   ```

   La ligne `Version:` doit indiquer `v7.4.9,build2829`.

2. **Remettre en configuration d'usine** (efface tout) :

   ```
   execute factoryreset
   ```

   Confirmer par `y`. Le boîtier redémarre avec l'IP d'usine sur `mgmt`
   (`192.168.1.99`) : connectez-vous en console ou sur ce port.

3. **Passer en multi-VDOM** (si le 300E l'est, `vdom=1`) :

   ```
   config system global
       set vdom-mode multi-vdom
   end
   ```

   La session se ferme : reconnectez-vous. `get system status` doit
   maintenant indiquer que les VDOM sont activés.

4. **Faire le backup** (portée **Global**) et l'enregistrer sous
   `work/120G-usine.conf`.

5. **Vérifier la première ligne** :

   ```
   #config-version=FG120G-7.4.9-FW-build2829-...:opmode=0:vdom=1:user=admin
   ```

   Même version, même build et même `vdom=` que le 300E. Si `vdom=0`, le
   passage en multi-VDOM n'a pas été pris en compte : recommencer le point 3.

> **Pourquoi c'est important** : si le mode VDOM diffère, `convert` s'arrête
> en erreur bloquante. Si la version diffère, c'est signalé en `A_REVOIR`.

### A.3 (Facultatif) Vérifier que l'outil lit bien les fichiers

Cette commande affiche seulement `round-trip OK` ou `round-trip DIFFERENT`
(jamais de contenu). `OK` signifie que l'outil relit et réécrit le fichier à
l'identique, octet pour octet :

```
python -c "import sys; from pathlib import Path; from fortimig.parser import load; from fortimig.serializer import serialize; p=Path(sys.argv[1]); print('round-trip OK' if serialize(load(p)).encode('utf-8','surrogateescape')==p.read_bytes() else 'round-trip DIFFERENT')" work/300E.conf
```

Si une erreur de lecture apparaît à la place, voir [Dépannage](#14-dépannage).

---

## 4. Étape B — Écrire le fichier `mapping.toml`

`mapping.toml` dit **sur quel port du 120G va chaque port physique du 300E**,
selon votre plan de câblage. C'est la seule partie qui demande une réflexion.

### B.1 Générer le squelette

```
python -m fortimig mapping-template --source work/300E.conf --target-default work/120G-usine.conf --out work/mapping.toml
```

La commande n'écrase jamais un fichier existant : si `work/mapping.toml`
existe déjà, supprimez-le ou choisissez un autre nom.

### B.2 Comprendre le squelette

Exemple de contenu généré :

```toml
[device]
# hostname = "..."
# hostname_secondary = "..."
# ha_priority_primary = 200
# ha_priority_secondary = 100

[interfaces]
"ha"          = "A_DEFINIR"  # lien HA (hbdev), 1 référence(s), port de même nom disponible sur la cible
"mgmt"        = "A_DEFINIR"  # 0 référence(s), adresse IP, port de même nom disponible sur la cible
"port1"       = "A_DEFINIR"  # porte 1 VLAN, 5 référence(s), port de même nom disponible sur la cible
"port3"       = "A_DEFINIR"  # membre de l'agrégat « LACP_1 », 1 référence(s)
"port30"      = "A_DEFINIR"  # 0 référence(s)
"npu0_vlink0" = "A_DEFINIR"  # porte 1 VLAN, 1 référence(s), port de même nom disponible sur la cible

# Ports physiques disponibles sur la cible :
# mgmt, ha, port1, ..., port24, x1, x2, x3, x4, modem, npu0_vlink0, npu0_vlink1
```

- **À gauche** : les ports physiques du 300E. **N'y touchez pas.**
- **À droite** : `A_DEFINIR`, à remplacer.
- **En commentaire** : le rôle du port dans la configuration du 300E, pour
  vous aider à décider.
- **En bas** : la liste des ports du 120G, écrits exactement comme il faut
  les recopier.

### B.3 Remplir la section `[interfaces]`

Pour **chaque** ligne, remplacez `A_DEFINIR` par :

- **le nom d'un port du 120G**, entre guillemets, exactement comme dans la
  liste du bas (`"port1"`, `"x1"`, `"mgmt"`…) ;
- **ou `"drop"`** si le port du 300E n'est pas repris.

Règles :

1. **Un port du 120G ne sert qu'une seule fois.**
2. **Aucun `A_DEFINIR` ne doit rester** (sinon erreur bloquante).
3. **Ne pas ajouter les interfaces logiques** (VLAN, agrégats LACP, zones,
   tunnels) : elles gardent leur nom et suivent automatiquement leurs ports.
   Pour un agrégat, on mappe seulement ses ports membres.
4. **Attention aux ports sans adresse IP** : ils peuvent être indispensables.
   Lisez le commentaire :

   | Commentaire | Signification | Décision |
   |---|---|---|
   | `membre de l'agrégat « X »` | port d'un LACP | à mapper, jamais `drop` |
   | `porte N VLAN` | parent de VLAN | à mapper |
   | `lien HA (hbdev)` | câble de heartbeat HA | à mapper |
   | `surveillé par le HA (monitor)` | surveillé pour la bascule | à mapper |
   | `membre de la zone « X »` | appartient à une zone | à mapper |
   | `0 référence(s)` sans rôle ni IP | inutilisé dans la configuration | `drop` possible |

5. **Cuivre / fibre** : un port fibre du 300E doit aller sur un port du 120G
   qui accepte le même type de module. Sur la configuration d'usine du 120G,
   `x1` à `x4` sont des ports SFP+ 10G. Vérifiez la fiche technique pour les
   autres ports et pour la compatibilité 1G des ports SFP+.
6. **Les ports `npu0_vlink0` / `npu0_vlink1`** existent sur le 120G en
   multi-VDOM : ils peuvent être mappés à l'identique.

### B.4 Remplir la section `[device]`

Retirez le `#` au début des quatre lignes et complétez :

```toml
[device]
hostname = "FW-PROD-01"          # hostname du 120G primaire
hostname_secondary = "FW-PROD-02" # hostname du 120G secondaire
ha_priority_primary = 200
ha_priority_secondary = 100
```

- Les deux priorités doivent être **différentes**.
- Avec `set override enable` dans le HA, la priorité du primaire doit être
  **plus haute** que celle du secondaire.

### B.5 Exemple complet

```toml
[device]
hostname = "FW-PROD-01"
hostname_secondary = "FW-PROD-02"
ha_priority_primary = 200
ha_priority_secondary = 100

[interfaces]
"ha"          = "ha"
"port15"      = "port16"       # 2e lien HA : le hbdev suivra automatiquement
"mgmt"        = "mgmt"
"port1"       = "port1"
"port27"      = "x1"           # membres d'un LACP fibre -> ports SFP+
"port28"      = "x2"
"port30"      = "drop"         # inutilisé
"npu0_vlink0" = "npu0_vlink0"
"npu0_vlink1" = "npu0_vlink1"
```

### B.6 (Facultatif) Section `[header]`

Par défaut, seule la ligne `#config-version` de l'en-tête est reprise du 120G.
Pour reprendre d'autres lignes de l'en-tête du 120G (par exemple si le lab
les réclame) :

```toml
[header]
from_target = ["conf_file_ver"]
```

---

## 5. Étape C — Lancer la conversion

```
python -m fortimig convert --source work/300E.conf --target-default work/120G-usine.conf --mapping work/mapping.toml --rules rules.toml --out work/sortie
```

- `--rules rules.toml` : le fichier de règles **du projet** (à la racine),
  partagé par tous (voir section 13).
- `--out work/sortie` : dossier créé s'il n'existe pas.

### C.1 Ce qui s'affiche

```
convert : ERREUR 0, A_REVOIR 18, SUPPRIME 6, MODIFIE 6
avertissement : ...
configuration convertie : work/sortie/converted.conf
configuration du second 120G : work/sortie/secondary-ha.txt
rapport : work/sortie/report.md et work/sortie/report.json
```

### C.2 Les fichiers produits

| Fichier | Rôle |
|---|---|
| `converted.conf` | configuration à restaurer sur le 120G **primaire** (contient les secrets) |
| `secondary-ha.txt` | commandes à coller sur le 120G **secondaire** (section 9) |
| `report.md` | rapport lisible (à ouvrir dans un éditeur ou un visualiseur Markdown) |
| `report.json` | même rapport, pour les scripts |

### C.3 Code de retour

| Code | Signification |
|---|---|
| `0` | conversion faite, rien à revoir |
| `1` | conversion faite, des points `A_REVOIR` à lire |
| `2` | **erreur bloquante** : aucune configuration n'est écrite (et un `converted.conf` d'une exécution précédente dans le même dossier est supprimé, pour éviter de restaurer un fichier périmé) |

---

## 6. Étape D — Lire et traiter le rapport

Ouvrez `work/sortie/report.md`. Il contient : le statut, un résumé chiffré, les
avertissements globaux, puis les entrées **du plus urgent au moins urgent**,
regroupées par bloc de configuration (`[global]`, `[root]`…).

### D.1 Les quatre catégories

| Catégorie | Signification | Quoi faire |
|---|---|---|
| `ERREUR` | bloquant, aucune configuration écrite | corriger (souvent `mapping.toml`) et relancer |
| `A_REVOIR` | rien n'a été modifié, une décision humaine est nécessaire | lire chaque ligne |
| `SUPPRIME` | élément retiré, avec la raison | vérifier que c'est voulu |
| `MODIFIE` | élément transformé (avant / après) | pour information |

Chaque entrée donne son **chemin complet**, par exemple
`config global > config system interface > edit "port1" > set speed`.

### D.2 Afficher la liste en une commande (sans les valeurs détaillées)

```
python -c "import json;d=json.load(open('work/sortie/report.json',encoding='utf-8'));[print(e['categorie'],'|',e['chemin'],'|',e['message']) for e in d['entrees'] if e['categorie']!='MODIFIE']"
```

### D.3 Messages fréquents et conduite à tenir

**Erreurs (`ERREUR`)**

| Message | Cause | Correction |
|---|---|---|
| `interface physique « X » absente du mapping` | ligne manquante | ajouter `"X" = "..."` ou `"drop"` |
| `interface cible « X » absente des ports physiques de target-default.conf` | faute de frappe, ou `A_DEFINIR` oublié | corriger le nom à droite |
| `interface cible « X » attribuée plusieurs fois` | un port du 120G utilisé deux fois | choisir un autre port |
| `« X » est une interface logique` | VLAN / agrégat mis dans le mapping | retirer la ligne |
| `mode VDOM différent : source vdom=1, cible vdom=0` | le 120G n'était pas en multi-VDOM au backup | refaire l'étape A.2 |
| `hostname_secondary, ha_priority_secondary requis` | section `[device]` incomplète | compléter `[device]` |

**Points à revoir (`A_REVOIR`)**

| Message | Signification | Conduite |
|---|---|---|
| `référence vers « X » (interface abandonnée : drop)` | un objet (souvent un LACP, un VLAN) utilise un port déclaré `drop` | **à corriger avant restauration** : mapper le port, ou retirer l'objet |
| `référence non couverte : ... égale à « X »` | une valeur égale à un ancien nom de port, à un endroit que l'outil ne sait pas renommer | vérifier à la main dans `converted.conf` |
| `options du bloc par défaut du 120G non reprises` | ex. `mediatype sr`, `speed 10000full` sur `x1`, ou `mode dhcp` sur `port1` | normal (c'est la configuration du 300E qui s'applique) ; vérifier la vitesse des ports sur le lab |
| `vitesse / duplex dépendant du type de port cible` (`speed`, `mediatype`, FEC) | réglage matériel du 300E conservé | vérifier qu'il convient au port du 120G |
| `interface par défaut du 120G « lan » / « fortilink » … disparaîtra` | objets d'usine du 120G non repris | normal, ils libèrent les ports |
| `entrée par défaut du 120G remplacée par l'entrée de même nom de la source` | ex. serveurs DHCP | normal |
| `port non utilisé avec accès administratif et/ou adressage DHCP par défaut` | un port du 120G non mappé garde son accès d'usine | à fermer après restauration |
| `index SNMP N porté par plusieurs interfaces` | doublon d'index SNMP | à renuméroter si la supervision l'exige ; le lab dira si FortiOS l'accepte |
| `bloc présent dans la configuration par défaut du 120G, absent de la configuration convertie` | bloc propre au matériel du 120G (ex. `config system npu`) | **important pour le HA** : s'il est propre au matériel, ajouter une règle `keep_target` (section 13) |
| `#conf_file_ver` : valeur conservée de la source | ligne d'en-tête différente | sans conséquence constatée ; sinon `[header] from_target` |
| `mot de passe HA à renseigner` / `passer le second 120G en multi-VDOM` | rappels pour `secondary-ha.txt` | à faire à l'étape G |

**Avertissements globaux** : en tête du rapport. Le plus important :
`private-data-encryption est activé` → la même clé doit être positionnée sur
le 120G **avant** la restauration.

Corrigez ce qui doit l'être (en général dans `mapping.toml`), puis
**relancez `convert`** jusqu'à n'avoir plus aucune `ERREUR` ni référence vers
un port abandonné.

---

## 7. Étape E — Restaurer sur le 120G de lab et lire le journal d'erreurs

### E.1 Précautions

1. **Isoler complètement le 120G de lab** : aucun câble vers la production.
   `converted.conf` contient les adresses IP de production et **le même
   `group-id` HA** que le cluster actuel.
2. **Se brancher en console** : après restauration, les comptes
   administrateurs, les mots de passe et l'IP de `mgmt` sont **ceux du 300E**.
3. Si l'avertissement `private-data-encryption` est présent : positionner la
   clé sur le 120G avant la restauration.

### E.2 Restaurer

Interface web du 120G : menu de l'administrateur → **Configuration** →
**Restore** → portée **Global** → fichier `work/sortie/converted.conf`. Le
boîtier redémarre.

### E.3 Lire le journal d'erreurs de configuration

Après le redémarrage, en console :

```
diagnose debug config-error-log read
```

- **Sortie vide** : toute la configuration a été acceptée. Passer à l'étape F.
- **Des lignes s'affichent**, par exemple :

  ```
  "config" "system" "np6" @ 60:global:command parse error (error -61)
  ```

  Copiez **toute** la sortie dans un fichier texte `work/errlog.txt`.

### E.4 Analyser le journal avec l'outil

```
python -m fortimig errlog --log work/errlog.txt --config work/sortie/converted.conf
```

Pour chaque erreur, l'outil indique :

- la ligne et le chemin correspondants dans `converted.conf`
  (« position du log confirmée ») ;
- le bloc concerné ;
- **une règle proposée** pour `rules.toml`, au format TOML, par exemple :

  ```toml
  [[rule]]
  path = "config system np6"
  action = "remove"
  reason = "Refusé par le 120G (config-error-log) : command parse error"
  ```

La règle n'est **jamais appliquée automatiquement** : relisez-la, ajoutez-la
à `rules.toml` si elle est justifiée (section 13), puis **relancez `convert`
et recommencez l'étape E**, jusqu'à obtenir un journal vide.

> **Relecture avant partage** : le journal recopie des lignes de
> configuration. `errlog` masque les secrets, mais pas les noms ni les IP.

---

## 8. Étape F — Vérifier le fonctionnement sur le lab

Commandes utiles en console sur le 120G de lab (à comparer avec le 300E) :

| Vérification | Commande |
|---|---|
| Version et mode VDOM | `get system status` |
| État des ports physiques | `get system interface physical` |
| Détail d'une interface | `show system interface <nom>` |
| État d'un agrégat LACP | `diagnose netlink aggregate name <nom>` |
| Vitesses acceptées par un port | `config system interface` → `edit <port>` → `set speed ?` (puis `abort`) |
| Table de routage (par VDOM) | `config vdom` → `edit <vdom>` → `get router info routing-table all` |

### F.1 Mots de passe et `ENC`

Les valeurs `ENC ...` (mots de passe chiffrés) **changent à chaque
sauvegarde**, même sur le même boîtier et pour un même mot de passe (un aléa
est ajouté à chaque chiffrement). Deux configurations ne se comparent donc
**jamais** sur leurs lignes `ENC`. Pour vérifier qu'un mot de passe est
correct, faites un **test fonctionnel** :

- comptes administrateurs : se connecter ;
- SNMP v3 : interroger le lab depuis un poste de test (`snmpwalk`) avec les
  identifiants habituels ;
- LDAP / RADIUS (si un serveur est joignable depuis le lab) :

  ```
  diagnose test authserver ldap <serveur> <utilisateur> <mot de passe>
  ```

### F.2 Certificats

- **Certificats importés** (les vôtres) : comparer le **numéro de série et
  l'empreinte** sur les deux boîtiers, pas le texte :

  ```
  get vpn certificate local details <nom>
  ```

- **Certificats d'usine** (`Fortinet_Factory`, `Fortinet_CA_SSL`, …) :
  propres à chaque boîtier, ils diffèrent entre le 300E et le 120G. Points
  d'attention :
  - **inspection SSL profonde** avec `Fortinet_CA_SSL` : les postes font
    confiance à la CA du 300E ; prévoir d'importer cette CA (certificat + clé)
    sur le 120G ou de déployer la CA du 120G sur les postes ;
  - **accès admin HTTPS / portail VPN** : l'empreinte présentée change.

---

## 9. Étape G — Monter le cluster HA avec le second 120G

Le second 120G ne reçoit **pas** `converted.conf` : il reçoit seulement ses
paramètres HA (`secondary-ha.txt`), puis le primaire lui synchronise toute la
configuration.

### G.1 Préparer le second 120G

1. Même version que le primaire (`get system status`).
2. Remise en usine :

   ```
   execute factoryreset
   ```

3. Passage en multi-VDOM (comme le primaire) :

   ```
   config system global
       set vdom-mode multi-vdom
   end
   ```

   Se reconnecter.

### G.2 Compléter `secondary-ha.txt`

Ouvrir `work/sortie/secondary-ha.txt` et remplacer `<A_RENSEIGNER>` par le
**mot de passe HA en clair** (FortiOS le chiffrera).

Si le mot de passe HA actuel n'est pas connu (seule sa forme `ENC` existe),
en définir un nouveau **sur le primaire** et mettre le même dans le fichier :

```
config global
config system ha
    set password <nouveau mot de passe>
end
end
```

### G.3 Appliquer et former le cluster

1. **Coller le contenu de `secondary-ha.txt` en console** sur le second 120G
   (pas en SSH : son adresse de gestion va changer).
2. **Brancher les câbles de heartbeat** entre les deux 120G, sur les ports
   `hbdev` (câbles directs ou switch dédié).
3. Le cluster se forme ; le primaire (priorité la plus haute) pousse sa
   configuration.

### G.4 Vérifier

```
get system ha status
diagnose sys ha checksum cluster
```

- `get system ha status` : les deux membres apparaissent, le bon est primaire.
- `diagnose sys ha checksum cluster` : **les checksums doivent être
  identiques** sur les deux membres.

Si les checksums diffèrent, afficher le détail par table pour trouver le bloc
en cause :

```
diagnose sys ha checksum show
```

(Cas déjà rencontré et corrigé dans l'outil : bloc `config system npu`
absent du primaire → règle `keep_target`, section 13.)

Accéder au secondaire depuis le primaire :

```
execute ha manage <index> <compte admin>
```

(`<index>` : visible dans `get system ha status`.)

### G.5 Tester la bascule

- Redémarrer le primaire (`execute reboot`) **ou** débrancher une interface
  surveillée (`monitor`) : le secondaire doit prendre la main.
- Avec `override enable`, le primaire reprend la main à son retour.

---

## 10. Étape H — Monter en version 7.6

La conversion 7.4 → 7.6 est faite **par le firmware**, pas par l'outil.

1. Suivre le **chemin de mise à jour officiel** de Fortinet (outil *Upgrade
   Path* sur docs.fortinet.com) : certaines versions intermédiaires peuvent
   être obligatoires.
2. Après chaque montée de version, relire le journal :

   ```
   diagnose debug config-error-log read
   ```

3. Pour l'analyser avec l'outil, faire un **backup du lab après la montée de
   version** (`work/lab-7.6.conf`) et l'utiliser comme `--config` :

   ```
   python -m fortimig errlog --log work/errlog-7.6.txt --config work/lab-7.6.conf
   ```

---

## 11. Étape I — Bascule en production

> ⚠️ **Le nouveau cluster reprend le même `group-id` et le même `group-name`
> que le cluster 300E.** Les adresses MAC virtuelles du HA FortiGate
> dépendent du `group-id` : **les deux clusters ne doivent jamais être
> branchés en même temps sur les mêmes réseaux** (MAC en double).

1. Recette fonctionnelle validée sur le lab (étapes F à H).
2. Le jour de la bascule : **débrancher le cluster 300E, puis brancher le
   cluster 120G**, sans période de recouvrement.
3. Surveiller les tables ARP / MAC des équipements voisins (switches,
   routeurs) ; prévoir de les vider si nécessaire.
4. Fermer les accès d'usine éventuellement restés ouverts sur les ports non
   utilisés (voir le rapport).

---

## 12. Partager un extrait anonymisé (`sanitize`)

Pour demander de l'aide (collègue, support, assistant IA) sans divulguer la
configuration :

```
python -m fortimig sanitize --config work/300E.conf --out work/300E-anonyme.conf --ips --names --seed "une-graine-secrete" --keep-names-from work/120G-usine.conf
```

| Option | Effet |
|---|---|
| *(toujours)* | tous les secrets sont masqués (`<SECRET-MASQUE>`), y compris certificats et clés |
| `--ips` | adresses IPv4 remplacées de façon cohérente (même IP → même remplaçant ; sous-réseaux, masques et distinction privé / public conservés) |
| `--names` | noms d'objets, de policies, de comptes, de VDOM et commentaires remplacés par des identifiants génériques ; les ports physiques et les mots-clés FortiOS ne sont jamais modifiés |
| `--seed` | graine de l'anonymisation des IP : gardez toujours la même, **ne la partagez pas** |
| `--keep-names-from` | garde lisibles les noms d'objets d'usine (services, profils par défaut…) |

Ensuite :

1. **Relisez** l'extrait avant de l'envoyer : les FQDN, DN LDAP, noms de
   serveurs et e-mails **ne sont pas anonymisés** (la commande indique combien
   il en reste).
2. Ne partagez que les morceaux utiles (copier-coller depuis le fichier
   anonymisé).
3. **Ne partagez jamais** `work/300E-anonyme.conf.SENSIBLE.json` : c'est la
   table de correspondance vers les vraies valeurs.

---

## 13. Le fichier `rules.toml`

`rules.toml` (à la racine du projet) contient les règles appliquées à chaque
conversion. **Il est partagé** : toute règle ajoutée profite aux conversions
suivantes. Il ne contient aucune donnée sensible et **doit être commité** dans
Git après validation.

### 13.1 Format

```toml
[[rule]]
path = "config system np6"     # un ou plusieurs "config ..." séparés par " > "
option = "nom-option"          # facultatif : vise une option plutôt que le bloc
action = "remove"              # remove | flag | keep_target
reason = "Pourquoi (obligatoire)"
```

| Action | Effet | Catégorie dans le rapport |
|---|---|---|
| `remove` | supprime le bloc (ou l'option) | `SUPPRIME` |
| `flag` | ne modifie rien, signale | `A_REVOIR` |
| `keep_target` | bloc **absent du 300E** mais présent sur le 120G d'usine : il est repris de la configuration d'usine (bloc entier seulement) | `MODIFIE` |

Correspondance :

- les niveaux `edit` sont ignorés : `path = "config router ospf > config
  ospf-interface"` vise toutes les interfaces OSPF ;
- une règle s'applique dans `config global` et dans tous les VDOM ;
- avec `option`, la règle vise `set <option>` dans le bloc et dans ses
  entrées `edit`.

Une règle qui ne trouve rien est signalée en avertissement (sans effet sur
le code de retour).

### 13.2 Règles actuelles

| Règle | Pourquoi |
|---|---|
| `config system np6` → `remove` | réglages NP6 propres au 300E, refusés en bloc par le 120G (constaté dans le `config-error-log` du lab) |
| `config system npu` → `keep_target` | bloc propre au 120G, absent du 300E : sans lui, le primaire perd ses réglages NPU d'usine et le cluster HA ne se synchronise pas (constaté sur le lab) |

### 13.3 Ajouter une règle

1. Partir d'une règle proposée par `errlog` (section 7.4) ou d'un
   `A_REVOIR` du rapport.
2. **N'ajouter que des règles certaines** (constatées sur le lab), avec une
   raison explicite.
3. Relancer `convert` et vérifier l'effet dans le rapport.
4. Committer `rules.toml` :

   ```
   git add rules.toml
   git commit -m "rules.toml : <résumé de la règle>"
   git push
   ```

---

## 14. Dépannage

### « python n'est pas reconnu » / mauvaise version

Utiliser `py -3.11 -m fortimig ...` sous Windows, ou installer Python 3.11+.

### `fortimig: erreur : configuration (xxx.conf) : ligne N : ...`

L'outil n'arrive pas à lire la structure du fichier. Le message ne contient
jamais de valeur (seulement des numéros de ligne) : il peut être partagé tel
quel. Il indique les blocs ouverts et la dernière valeur multi-lignes lue.

Pour voir la structure autour de la ligne en cause (**sans aucune valeur**,
sortie partageable) :

```
python -m fortimig diagnose --config work/300E.conf --line 14242
```

Option `--context 50` pour afficher plus de lignes autour.

### `avertissement : ... délimitation incertaine`

Une valeur entre guillemets se termine peut-être par un antislash (`\"`) :
la lecture de la valeur est peut-être faussée. Vérifier avec `diagnose` à la
ligne indiquée.

### `convert` s'arrête avec le code 2

Lire la section `ERREUR` de `report.md` (voir tableau en section 6).

### `mapping-template` : « existe déjà »

La commande n'écrase jamais un fichier : supprimer ou renommer le fichier
existant.

### Le cluster ne se synchronise pas

`diagnose sys ha checksum cluster` puis `diagnose sys ha checksum show` pour
trouver le bloc en cause ; vérifier dans le rapport les messages « bloc
présent dans la configuration par défaut du 120G, absent de la configuration
convertie ».

---

## 15. Référence de toutes les commandes

Toutes les commandes se lancent depuis le dossier du projet :
`python -m fortimig <commande> [options]`. `--help` après une commande
affiche ses options.

| Commande | Rôle | Options |
|---|---|---|
| `mapping-template` | génère le squelette de `mapping.toml` | `--source` `--target-default` `--out` |
| `convert` | conversion complète | `--source` `--target-default` `--mapping` `--rules` `--out` |
| `errlog` | analyse du `config-error-log` du lab | `--log` `--config` |
| `sanitize` | extrait anonymisé partageable | `--config` `--out` `[--ips]` `[--names]` `[--seed]` `[--keep-names-from]` |
| `diagnose` | structure autour d'une ligne illisible, sans valeur | `--config` `--line` `[--context]` |
| `check` | contrôle des références | *à venir* |
| `diff` | comparaison lisible de deux configurations | *à venir* |

Codes de retour : `0` succès ; `1` succès avec des `A_REVOIR` (`convert`) ;
`2` erreur bloquante.

### Récapitulatif des commandes FortiGate utilisées

| Étape | Commande |
|---|---|
| Version, mode VDOM | `get system status` |
| Remise en usine | `execute factoryreset` |
| Passage en multi-VDOM | `config system global` / `set vdom-mode multi-vdom` / `end` |
| Journal d'erreurs après restauration | `diagnose debug config-error-log read` |
| Interfaces | `get system interface physical`, `show system interface <nom>` |
| LACP | `diagnose netlink aggregate name <nom>` |
| Certificats | `get vpn certificate local details <nom>` |
| Test d'authentification | `diagnose test authserver ldap <serveur> <utilisateur> <mdp>` |
| État HA | `get system ha status` |
| Synchronisation HA | `diagnose sys ha checksum cluster`, `diagnose sys ha checksum show` |
| Accès au secondaire | `execute ha manage <index> <admin>` |

> Ces commandes FortiOS sont données pour la 7.4 ; leur syntaxe peut varier
> légèrement selon la version. En cas de doute : `?` en CLI.

---

## 16. Contenu du projet et informations pour les développeurs

```
Migration-FGT/
├── README.md            ce document
├── SPEC.md              cahier des charges (fait foi)
├── DECISIONS.md         décisions prises et constats faits sur les vrais boîtiers
├── rules.toml           règles de conversion partagées
├── fortimig/            code de l'outil (Python, bibliothèque standard uniquement)
├── tests/               tests automatiques (fixtures 100 % synthétiques)
└── work/                VOTRE dossier de travail (ignoré par Git, à créer)
```

- **`DECISIONS.md`** explique chaque choix de l'outil et tout ce qui a été
  constaté sur le 300E et le 120G réels (formats, blocs propres au matériel,
  erreurs du lab). À lire avant de modifier le code.
- **Tests** (pour qui modifie le code) :

  ```
  pip install pytest
  python -m pytest
  ```

  Tous les tests doivent passer avant tout commit. Les fixtures de
  `tests/fixtures/` sont **synthétiques** : n'y ajoutez jamais de
  configuration réelle, même anonymisée.
- **Principes non négociables** (voir `SPEC.md`) : ne jamais inventer de
  syntaxe FortiOS (en cas de doute, signaler plutôt que transformer), aucune
  perte silencieuse, aucun secret dans les sorties, aucune action réseau,
  résultat déterministe.
