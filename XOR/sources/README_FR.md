# XOR — Agent endpoint (EDR amélioré) pour XORCISM

Agent **multi-OS** (Windows / macOS / Linux) en **Python pur (stdlib uniquement)** :
copiez `xor_agent.py` sur l'endpoint, enrôlez-le, c'est tout.

## Capacités
| Fonction | Détail |
|---|---|
| **Enrôlement → ASSET** | l'endpoint s'enregistre auprès de XORCISM et devient un ASSET (hostname). |
| **Inventaire logiciel → CPE** | Windows (registre), Linux (`dpkg`/`rpm`), macOS (`system_profiler`) → CPE liés à l'asset (`CPEFORASSET`). |
| **Vulnérabilités → ASSETVULNERABILITY** | corrélation CPE→CVE côté serveur (base NVD) → liens asset↔CVE. |
| **Configuration / conformité** | OpenSCAP (`oscap`) si présent, sinon contrôles intégrés (pare-feu, chiffrement disque, SSH…). Extensible **OVAL**. |
| **Antivirus** | ClamAV (`clamscan`/`clamdscan`) si installé → détections remontées. |
| **Threat hunting** | récupère les **IOC** (threat intel) du serveur et les chasse localement (process, connexions réseau, fichiers, hashes). |
| **Scan à la demande** | exécute les scans **« Launch a scan »** déclenchés depuis la fenêtre ASSET de XORCISM (au prochain check-in). |

## Threat intelligence (IOC)
Les IOC servis aux agents proviennent de la CTI XORCISM et sont chargés dans
`XAGENT.XIOC` par [`connectors/import_iocs.py`](../connectors/import_iocs.py) :
- **STIX 2.1** (fichiers importés / reçus sur le serveur **TAXII**, dossier `stix/`),
- **AlienVault OTX** et autres **connecteurs/feeds CTI** (`--otx-key` / `OTX_API_KEY`),
- (extensible) objets de la base **XTHREAT**.

```bash
python connectors/import_iocs.py --stix-dir stix            # depuis STIX/TAXII
python connectors/import_iocs.py --otx-key $OTX_API_KEY     # depuis AlienVault OTX
```

## Démarrage rapide (endpoint)
```bash
# 1) Enrôlement (le serveur peut exiger une clé : XOR_ENROLL_KEY)
python xor_agent.py --server https://xorcism.example:9292 --enroll [--enroll-key KEY] [--insecure]

# 2) Scans
python xor_agent.py --scan full          # inventaire + vuln + conformité + AV + hunt
python xor_agent.py --inventory          # inventaire seul
python xor_agent.py --once               # un check-in (exécute les scans demandés depuis l'ASSET)

# 3) Démon (check-in périodique)
python xor_agent.py --run --interval 300
```
Le token est stocké dans `xor_agent.conf` (à côté du script).

## Côté serveur XORCISM
- API agent (jeton) : `/api/agent/{enroll,checkin,inventory,vulnerabilities,events,match,intel}`.
- Les remontées d'inventaire/vuln passent par le **pipeline d'import** existant
  (`runner.py` → `import_findings`) : lancez le runner local pour ingérer
  (`python connectors/runner.py`).
- UI : fenêtre **ASSET → « XOR agent — launch a scan »** ; agents/événements via
  `/api/agents`, `/api/agent-events`.

## Déploiement en service
- **Linux** : voir `install/xor-agent.service` (systemd).
- **macOS** : voir `install/com.xorcism.xor.plist` (launchd).
- **Windows** : Planificateur de tâches (au démarrage) ou NSSM pour un service.
- **Binaire autonome** : `pyinstaller --onefile xor_agent.py` produit un exécutable
  par OS (aucune dépendance Python requise sur la cible).

## Périmètre & feuille de route
Cet agent fournit une **détection basée hôte** (télémétrie + IOC) et l'intégration
complète à XORCISM. Pour un EDR « temps réel » de niveau noyau (hooks ETW/eBPF,
blocage de process, isolation réseau), prévoir un cœur natif (Go/Rust) — l'API
serveur et le modèle d'événements ci-dessus sont conçus pour l'accueillir.
