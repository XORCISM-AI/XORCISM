"""
seed_iso42001_policies.py — seed a baseline set of ISO/IEC 42001:2023 (AI Management
System, AIMS) policies into XORCISM.POLICY, in English and French.
Jerome Athias - XORCISM

ISO/IEC 42001:2023 is the management-system standard for Artificial Intelligence. It
requires an AI Policy (Clause 5.2), AI objectives, and a set of operational policies
mapped to its Annex A controls (AI risk, impact assessment, data governance, system
lifecycle, transparency, human oversight, third parties, incidents). This seeder writes
a ready-to-tailor template of each, in both languages, so the Policy & Document
management view (/policy-management) and the GRC module have real content to govern.

Idempotent: keyed on (PolicyReference, Language) — re-running updates the body in place
rather than duplicating. POLICY.PolicyID is a legacy non-autoincrement PK, so new rows
take MAX(PolicyID)+1.

    python seed_iso42001_policies.py                 # tenant 3 (default), both languages
    python seed_iso42001_policies.py --tenant 3
    python seed_iso42001_policies.py --lang en       # one language only
    python seed_iso42001_policies.py --list          # show what would be written
"""
from __future__ import annotations

import argparse
import datetime as _dt
import os
import sqlite3
import sys
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
try:
    from xorcism_python import config
    _DB_DIR = config.DB_DIR
except Exception:
    _DB_DIR = os.environ.get("XORCISM_DB_DIR", r"C:\Users\jerom\XORCISM_databases")

MODULE = "SeedISO42001"
FRAMEWORK = "ISO/IEC 42001:2023"
CATEGORY = "AI Management System"

# A realistic AIMS rollout: most policies published & owned, a couple still working
# through the lifecycle. (Anything not listed here defaults to "Published".)
STATUS_OVERRIDE = {"AIMS-POL-09": "In review", "AIMS-POL-10": "Draft"}

# Columns added by the server's ensureGrcColumns(); the seeder also ensures them so it
# can run standalone before the server has ever booted.
_EXTRA_COLS = {
    "Status": "TEXT", "WorkflowStatus": "TEXT", "Version": "TEXT", "PolicyReference": "TEXT",
    "OwnerPersonID": "INTEGER", "ApprovedByPersonID": "INTEGER", "EffectiveDate": "DATE", "ReviewDate": "DATE",
    "Category": "TEXT", "Framework": "TEXT", "Clause": "TEXT", "Classification": "TEXT",
    "Language": "TEXT", "Scope": "TEXT", "PolicyContent": "TEXT", "ApprovedDate": "DATE", "TenantID": "INTEGER",
}


def _html(sections):
    """sections = list of (heading, body) where body is str (→ <p>) or list (→ <ul>).
    Emits HTML for XORCISM's WYSIWYG rich-text editor (POLICY.PolicyContent)."""
    out = []
    for heading, body in sections:
        out.append(f"<p><strong>{heading}</strong></p>")
        if isinstance(body, (list, tuple)):
            out.append("<ul>" + "".join(f"<li>{x}</li>" for x in body) + "</ul>")
        else:
            out.append(f"<p>{body}</p>")
    return "".join(out)


def _en(purpose, scope, statements, roles, review):
    return _html([
        ("Purpose", purpose),
        ("Scope", scope),
        ("Policy statements", statements),
        ("Roles &amp; responsibilities", roles),
        ("Compliance, monitoring &amp; review", review),
    ])


def _fr(purpose, scope, statements, roles, review):
    return _html([
        ("Objet", purpose),
        ("Périmètre", scope),
        ("Énoncés de la politique", statements),
        ("Rôles &amp; responsabilités", roles),
        ("Conformité, surveillance &amp; revue", review),
    ])


# ── Policy templates (10), ISO/IEC 42001:2023 ──────────────────────────────────
POLICIES = [
    {
        "ref": "AIMS-POL-01", "clause": "Clause 5.2",
        "en": {
            "name": "AI Management System Policy",
            "desc": "Top-level policy establishing the organisation's commitment to a responsible AI Management System per ISO/IEC 42001:2023.",
            "content": _en(
                "Establish top-management commitment to managing artificial intelligence responsibly, and provide the framework for setting AI objectives across the AI Management System (AIMS).",
                "All AI systems developed, deployed, operated or procured by the organisation, and everyone involved in their lifecycle.",
                [
                    "AI is governed throughout its lifecycle in line with our values, applicable law and obligations to interested parties.",
                    "AI objectives are established, measured and reviewed, and resources are allocated to meet them.",
                    "We commit to satisfying applicable requirements and to the continual improvement of the AIMS.",
                    "AI risks and impacts on individuals, groups and society are systematically identified and treated.",
                ],
                [
                    "Top management — owns the AIMS, approves this policy and the AI objectives.",
                    "AIMS Manager — operates the management system and reports performance.",
                    "All staff — comply with this policy and the supporting policies referenced below.",
                ],
                "Compliance is monitored through internal audit and management review. This policy is reviewed at least annually and after significant change to AI use, technology, law or risk.",
            ),
        },
        "fr": {
            "name": "Politique du Système de Management de l'IA",
            "desc": "Politique de plus haut niveau formalisant l'engagement de l'organisation envers un Système de Management de l'IA responsable selon l'ISO/IEC 42001:2023.",
            "content": _fr(
                "Formaliser l'engagement de la direction à gérer l'intelligence artificielle de manière responsable et fournir le cadre de définition des objectifs IA du Système de Management de l'IA (SMIA).",
                "Tous les systèmes d'IA conçus, déployés, exploités ou acquis par l'organisation, ainsi que toute personne impliquée dans leur cycle de vie.",
                [
                    "L'IA est gouvernée tout au long de son cycle de vie conformément à nos valeurs, au droit applicable et à nos obligations envers les parties intéressées.",
                    "Des objectifs IA sont établis, mesurés et revus, et les ressources nécessaires sont allouées.",
                    "Nous nous engageons à satisfaire les exigences applicables et à améliorer en continu le SMIA.",
                    "Les risques et impacts de l'IA sur les individus, les groupes et la société sont identifiés et traités de manière systématique.",
                ],
                [
                    "Direction — propriétaire du SMIA, approuve la présente politique et les objectifs IA.",
                    "Responsable du SMIA — exploite le système de management et rend compte de la performance.",
                    "Ensemble du personnel — applique la présente politique et les politiques de soutien référencées ci-dessous.",
                ],
                "La conformité est surveillée par l'audit interne et la revue de direction. La présente politique est revue au moins une fois par an et après tout changement significatif d'usage de l'IA, de technologie, de droit ou de risque.",
            ),
        },
    },
    {
        "ref": "AIMS-POL-02", "clause": "Annex A.2 / A.3",
        "en": {
            "name": "Responsible & Acceptable AI Use Policy",
            "desc": "Defines acceptable, prohibited and high-risk uses of AI and the principles every AI system must respect.",
            "content": _en(
                "Set the principles and boundaries for acceptable use of AI so that systems are lawful, ethical, fair and aligned with the organisation's values.",
                "All employees, contractors and systems that build, integrate or use AI, including third-party and generative AI services.",
                [
                    "AI must respect fairness, non-discrimination, safety, privacy, security and human dignity.",
                    "Prohibited uses include unlawful surveillance, social scoring, manipulation, and any use breaching applicable law (e.g. the EU AI Act prohibited practices).",
                    "High-risk uses require a documented impact assessment and management approval before deployment.",
                    "Confidential or personal data must not be entered into unapproved external AI services.",
                ],
                [
                    "AIMS Manager — maintains the catalogue of approved AI uses and tools.",
                    "Business owners — classify the risk of each intended use.",
                    "Users — use AI only within the boundaries of this policy.",
                ],
                "Violations are handled under the disciplinary process. Reviewed annually and when new AI capabilities or regulations emerge.",
            ),
        },
        "fr": {
            "name": "Politique d'Usage Responsable et Acceptable de l'IA",
            "desc": "Définit les usages acceptables, interdits et à haut risque de l'IA, ainsi que les principes que tout système d'IA doit respecter.",
            "content": _fr(
                "Fixer les principes et les limites d'un usage acceptable de l'IA afin que les systèmes soient licites, éthiques, équitables et alignés sur les valeurs de l'organisation.",
                "Tous les salariés, prestataires et systèmes qui conçoivent, intègrent ou utilisent de l'IA, y compris les services d'IA tiers et génératifs.",
                [
                    "L'IA doit respecter l'équité, la non-discrimination, la sûreté, la vie privée, la sécurité et la dignité humaine.",
                    "Les usages interdits comprennent la surveillance illicite, la notation sociale, la manipulation et tout usage contraire au droit applicable (p. ex. les pratiques interdites par le Règlement IA de l'UE).",
                    "Les usages à haut risque nécessitent une évaluation d'impact documentée et l'approbation de la direction avant tout déploiement.",
                    "Aucune donnée confidentielle ou personnelle ne doit être saisie dans un service d'IA externe non approuvé.",
                ],
                [
                    "Responsable du SMIA — tient à jour le catalogue des usages et outils d'IA approuvés.",
                    "Responsables métiers — classent le risque de chaque usage envisagé.",
                    "Utilisateurs — n'utilisent l'IA que dans les limites de la présente politique.",
                ],
                "Les manquements relèvent du processus disciplinaire. Revue annuelle et à l'apparition de nouvelles capacités d'IA ou réglementations.",
            ),
        },
    },
    {
        "ref": "AIMS-POL-03", "clause": "Clause 6.1 / Annex A.5",
        "en": {
            "name": "AI Risk Management Policy",
            "desc": "Establishes how AI risks are identified, analysed, evaluated and treated across the AI lifecycle.",
            "content": _en(
                "Ensure AI risks — to the organisation and to individuals and society — are identified, assessed and treated to acceptable levels.",
                "All AI systems within the AIMS scope, at every lifecycle stage from conception to retirement.",
                [
                    "An AI risk assessment is performed and maintained for each AI system, integrated with enterprise risk management.",
                    "Risks are evaluated against defined criteria and treated by avoiding, reducing, transferring or accepting them.",
                    "Residual risk is formally accepted by an accountable owner before deployment.",
                    "Risk assessments are revisited on significant change and at planned intervals.",
                ],
                [
                    "Risk owners — accountable for treating and accepting AI risks.",
                    "AIMS Manager — maintains the AI risk methodology and register.",
                    "Development & operations teams — implement risk treatments.",
                ],
                "Effectiveness is verified through audit and metrics. Reviewed at least annually.",
            ),
        },
        "fr": {
            "name": "Politique de Gestion des Risques liés à l'IA",
            "desc": "Établit la manière dont les risques liés à l'IA sont identifiés, analysés, évalués et traités sur l'ensemble du cycle de vie.",
            "content": _fr(
                "Garantir que les risques liés à l'IA — pour l'organisation comme pour les personnes et la société — sont identifiés, évalués et traités à des niveaux acceptables.",
                "Tous les systèmes d'IA du périmètre du SMIA, à chaque étape du cycle de vie, de la conception au retrait.",
                [
                    "Une analyse de risque IA est réalisée et maintenue pour chaque système d'IA, intégrée à la gestion des risques de l'entreprise.",
                    "Les risques sont évalués selon des critères définis et traités par évitement, réduction, transfert ou acceptation.",
                    "Le risque résiduel est formellement accepté par un propriétaire responsable avant tout déploiement.",
                    "Les analyses de risque sont réexaminées lors de changements significatifs et à intervalles planifiés.",
                ],
                [
                    "Propriétaires de risque — responsables du traitement et de l'acceptation des risques IA.",
                    "Responsable du SMIA — maintient la méthodologie et le registre des risques IA.",
                    "Équipes de développement et d'exploitation — mettent en œuvre les traitements de risque.",
                ],
                "L'efficacité est vérifiée par l'audit et des indicateurs. Revue au moins annuelle.",
            ),
        },
    },
    {
        "ref": "AIMS-POL-04", "clause": "Clause 6.1.4 / Annex A.5.2",
        "en": {
            "name": "AI System Impact Assessment Policy",
            "desc": "Requires assessment of the potential consequences of AI systems for individuals, groups and society.",
            "content": _en(
                "Ensure the potential impacts of AI systems on individuals, groups and society are assessed and considered before and during deployment.",
                "All AI systems that may affect people — directly or indirectly — within the AIMS scope.",
                [
                    "An AI system impact assessment is completed before deployment of any consequential AI system.",
                    "The assessment covers affected stakeholders, potential harms, fairness, safety, privacy and societal effects.",
                    "Findings drive design choices, mitigations, human oversight and the decision to deploy.",
                    "Assessments are retained as records and updated on significant change.",
                ],
                [
                    "Product/AI owners — commission and act on impact assessments.",
                    "AIMS Manager — maintains the assessment method and templates.",
                    "Legal/DPO — advise on rights, privacy and regulatory impacts.",
                ],
                "Completion is verified at deployment gates and in audit. Reviewed annually.",
            ),
        },
        "fr": {
            "name": "Politique d'Évaluation d'Impact des Systèmes d'IA",
            "desc": "Exige l'évaluation des conséquences potentielles des systèmes d'IA pour les individus, les groupes et la société.",
            "content": _fr(
                "Garantir que les impacts potentiels des systèmes d'IA sur les individus, les groupes et la société sont évalués et pris en compte avant et pendant le déploiement.",
                "Tous les systèmes d'IA susceptibles d'affecter des personnes — directement ou indirectement — dans le périmètre du SMIA.",
                [
                    "Une évaluation d'impact du système d'IA est réalisée avant le déploiement de tout système d'IA à conséquences.",
                    "L'évaluation couvre les parties prenantes affectées, les préjudices potentiels, l'équité, la sûreté, la vie privée et les effets sociétaux.",
                    "Les conclusions orientent les choix de conception, les mesures d'atténuation, la supervision humaine et la décision de déployer.",
                    "Les évaluations sont conservées comme enregistrements et mises à jour en cas de changement significatif.",
                ],
                [
                    "Propriétaires de produit/IA — commandent les évaluations d'impact et y donnent suite.",
                    "Responsable du SMIA — maintient la méthode et les modèles d'évaluation.",
                    "Juridique/DPO — conseillent sur les droits, la vie privée et les impacts réglementaires.",
                ],
                "La réalisation est vérifiée aux jalons de déploiement et en audit. Revue annuelle.",
            ),
        },
    },
    {
        "ref": "AIMS-POL-05", "clause": "Annex A.7",
        "en": {
            "name": "Data Governance & Management Policy for AI",
            "desc": "Governs the data used to develop and operate AI systems — quality, provenance, privacy and bias.",
            "content": _en(
                "Ensure data used for AI is appropriate, of sufficient quality, lawfully obtained and managed throughout its lifecycle.",
                "All datasets used to train, test, validate or operate AI systems within the AIMS scope.",
                [
                    "Data provenance, rights to use and applicable consents are documented for AI datasets.",
                    "Data quality, representativeness and known biases are assessed and recorded.",
                    "Personal data is processed lawfully, minimised, protected and retained only as needed.",
                    "Data preparation, labelling and versioning are controlled and traceable.",
                ],
                [
                    "Data owners — accountable for the datasets they provide.",
                    "AIMS / Data Governance — define standards and verify compliance.",
                    "DPO — oversees personal-data lawfulness.",
                ],
                "Verified through data reviews and audit. Reviewed at least annually.",
            ),
        },
        "fr": {
            "name": "Politique de Gouvernance et de Gestion des Données pour l'IA",
            "desc": "Régit les données utilisées pour développer et exploiter les systèmes d'IA — qualité, provenance, vie privée et biais.",
            "content": _fr(
                "Garantir que les données utilisées pour l'IA sont appropriées, de qualité suffisante, obtenues licitement et gérées tout au long de leur cycle de vie.",
                "Tous les jeux de données servant à entraîner, tester, valider ou exploiter les systèmes d'IA du périmètre du SMIA.",
                [
                    "La provenance des données, les droits d'usage et les consentements applicables sont documentés pour les jeux de données d'IA.",
                    "La qualité, la représentativité et les biais connus des données sont évalués et consignés.",
                    "Les données personnelles sont traitées licitement, minimisées, protégées et conservées uniquement le temps nécessaire.",
                    "La préparation, l'étiquetage et le versionnement des données sont maîtrisés et traçables.",
                ],
                [
                    "Propriétaires de données — responsables des jeux de données qu'ils fournissent.",
                    "SMIA / Gouvernance des données — définissent les standards et vérifient la conformité.",
                    "DPO — supervise la licéité des données personnelles.",
                ],
                "Vérifiée par des revues de données et l'audit. Revue au moins annuelle.",
            ),
        },
    },
    {
        "ref": "AIMS-POL-06", "clause": "Annex A.6",
        "en": {
            "name": "AI System Lifecycle & Development Policy",
            "desc": "Defines responsible development, testing, verification and release controls across the AI system lifecycle.",
            "content": _en(
                "Ensure AI systems are developed, tested, verified, released and maintained under defined, responsible engineering controls.",
                "All AI systems built or substantially modified within the AIMS scope.",
                [
                    "Each AI system has documented objectives, requirements and acceptance criteria.",
                    "Models are tested for performance, robustness, safety and bias before release.",
                    "Changes follow change management; versions of data, models and code are recorded.",
                    "Deployed systems are monitored for drift and degradation, with defined retraining and rollback paths.",
                ],
                [
                    "Engineering leads — apply the lifecycle controls.",
                    "AIMS Manager — maintains the lifecycle standard.",
                    "Operations — monitor production AI systems.",
                ],
                "Verified through release gates and audit. Reviewed annually.",
            ),
        },
        "fr": {
            "name": "Politique de Cycle de Vie et de Développement des Systèmes d'IA",
            "desc": "Définit les contrôles de développement, de test, de vérification et de mise en production responsables sur le cycle de vie des systèmes d'IA.",
            "content": _fr(
                "Garantir que les systèmes d'IA sont développés, testés, vérifiés, mis en production et maintenus selon des contrôles d'ingénierie définis et responsables.",
                "Tous les systèmes d'IA construits ou substantiellement modifiés dans le périmètre du SMIA.",
                [
                    "Chaque système d'IA dispose d'objectifs, d'exigences et de critères d'acceptation documentés.",
                    "Les modèles sont testés en performance, robustesse, sûreté et biais avant mise en production.",
                    "Les changements suivent la gestion des changements ; les versions de données, modèles et code sont enregistrées.",
                    "Les systèmes déployés sont surveillés (dérive, dégradation) avec des chemins définis de réentraînement et de retour arrière.",
                ],
                [
                    "Responsables d'ingénierie — appliquent les contrôles de cycle de vie.",
                    "Responsable du SMIA — maintient le standard de cycle de vie.",
                    "Exploitation — surveille les systèmes d'IA en production.",
                ],
                "Vérifiée par des jalons de mise en production et l'audit. Revue annuelle.",
            ),
        },
    },
    {
        "ref": "AIMS-POL-07", "clause": "Annex A.8",
        "en": {
            "name": "AI Transparency & Explainability Policy",
            "desc": "Requires appropriate information to users and affected parties about AI systems and their decisions.",
            "content": _en(
                "Ensure people are appropriately informed when they interact with or are affected by AI, and that decisions can be explained to the extent required.",
                "All AI systems that interact with or make/inform decisions about people within the AIMS scope.",
                [
                    "Users are informed when they are interacting with an AI system.",
                    "The purpose, capabilities and limitations of AI systems are communicated to relevant parties.",
                    "Explanations of AI-influenced decisions are available proportionate to their impact.",
                    "AI-generated content is labelled where required by law or policy.",
                ],
                [
                    "Product owners — provide the required disclosures and explanations.",
                    "AIMS Manager — defines transparency requirements.",
                    "Legal — confirms disclosure obligations.",
                ],
                "Verified through reviews and audit. Reviewed annually.",
            ),
        },
        "fr": {
            "name": "Politique de Transparence et d'Explicabilité de l'IA",
            "desc": "Exige une information appropriée des utilisateurs et des parties affectées sur les systèmes d'IA et leurs décisions.",
            "content": _fr(
                "Garantir que les personnes sont correctement informées lorsqu'elles interagissent avec l'IA ou en subissent les effets, et que les décisions peuvent être expliquées dans la mesure requise.",
                "Tous les systèmes d'IA qui interagissent avec des personnes ou prennent/éclairent des décisions les concernant, dans le périmètre du SMIA.",
                [
                    "Les utilisateurs sont informés lorsqu'ils interagissent avec un système d'IA.",
                    "La finalité, les capacités et les limites des systèmes d'IA sont communiquées aux parties concernées.",
                    "Des explications des décisions influencées par l'IA sont disponibles à la mesure de leur impact.",
                    "Les contenus générés par l'IA sont signalés lorsque la loi ou la politique l'exige.",
                ],
                [
                    "Propriétaires de produit — fournissent les informations et explications requises.",
                    "Responsable du SMIA — définit les exigences de transparence.",
                    "Juridique — confirme les obligations d'information.",
                ],
                "Vérifiée par des revues et l'audit. Revue annuelle.",
            ),
        },
    },
    {
        "ref": "AIMS-POL-08", "clause": "Annex A.9 / A.3",
        "en": {
            "name": "Human Oversight & Accountability Policy",
            "desc": "Ensures meaningful human oversight of AI and clear accountability for AI outcomes.",
            "content": _en(
                "Ensure AI systems remain under meaningful human oversight and that accountability for AI outcomes is clearly assigned.",
                "All AI systems within the AIMS scope, especially those informing decisions about people.",
                [
                    "Each AI system has a defined level of human oversight proportionate to its risk.",
                    "Humans can intervene, override or stop an AI system where appropriate.",
                    "Roles and responsibilities for AI are defined and accountability is never delegated to the system.",
                    "Operators are trained and competent for their oversight role.",
                ],
                [
                    "Accountable owners — answerable for AI outcomes.",
                    "Operators — exercise oversight and intervention.",
                    "AIMS Manager — defines oversight requirements.",
                ],
                "Verified through audit and incident review. Reviewed annually.",
            ),
        },
        "fr": {
            "name": "Politique de Supervision Humaine et de Responsabilité",
            "desc": "Assure une supervision humaine effective de l'IA et une responsabilité claire quant à ses résultats.",
            "content": _fr(
                "Garantir que les systèmes d'IA restent sous supervision humaine effective et que la responsabilité de leurs résultats est clairement attribuée.",
                "Tous les systèmes d'IA du périmètre du SMIA, en particulier ceux éclairant des décisions concernant des personnes.",
                [
                    "Chaque système d'IA dispose d'un niveau de supervision humaine proportionné à son risque.",
                    "Des humains peuvent intervenir, passer outre ou arrêter un système d'IA lorsque cela est approprié.",
                    "Les rôles et responsabilités liés à l'IA sont définis et la responsabilité n'est jamais déléguée au système.",
                    "Les opérateurs sont formés et compétents pour leur rôle de supervision.",
                ],
                [
                    "Propriétaires responsables — répondent des résultats de l'IA.",
                    "Opérateurs — exercent la supervision et l'intervention.",
                    "Responsable du SMIA — définit les exigences de supervision.",
                ],
                "Vérifiée par l'audit et la revue des incidents. Revue annuelle.",
            ),
        },
    },
    {
        "ref": "AIMS-POL-09", "clause": "Annex A.10",
        "en": {
            "name": "Third-Party & Supplier AI Policy",
            "desc": "Governs AI components, services and suppliers acquired or integrated by the organisation.",
            "content": _en(
                "Ensure AI systems, components and services obtained from third parties meet the organisation's AI requirements and responsibilities.",
                "All externally sourced AI — models, APIs, datasets, tools and managed services — used within the AIMS scope.",
                [
                    "Suppliers of AI are assessed for capability, security, privacy and responsible-AI practices before use.",
                    "Contracts allocate responsibilities, data rights, transparency and incident obligations.",
                    "The organisation's AI requirements flow down to suppliers and are monitored.",
                    "Dependencies on third-party AI are inventoried and risk-assessed.",
                ],
                [
                    "Procurement — runs supplier due diligence with the AIMS.",
                    "Business owners — define requirements for sourced AI.",
                    "AIMS Manager — maintains the third-party AI inventory.",
                ],
                "Verified through supplier reviews and audit. Reviewed annually.",
            ),
        },
        "fr": {
            "name": "Politique relative à l'IA des Tiers et des Fournisseurs",
            "desc": "Régit les composants, services et fournisseurs d'IA acquis ou intégrés par l'organisation.",
            "content": _fr(
                "Garantir que les systèmes, composants et services d'IA obtenus auprès de tiers respectent les exigences et responsabilités IA de l'organisation.",
                "Toute IA d'origine externe — modèles, API, jeux de données, outils et services managés — utilisée dans le périmètre du SMIA.",
                [
                    "Les fournisseurs d'IA sont évalués (capacité, sécurité, vie privée, pratiques d'IA responsable) avant utilisation.",
                    "Les contrats répartissent les responsabilités, les droits sur les données, la transparence et les obligations en cas d'incident.",
                    "Les exigences IA de l'organisation sont répercutées aux fournisseurs et surveillées.",
                    "Les dépendances à l'IA de tiers sont inventoriées et soumises à analyse de risque.",
                ],
                [
                    "Achats — réalisent la due diligence fournisseurs avec le SMIA.",
                    "Responsables métiers — définissent les exigences pour l'IA acquise.",
                    "Responsable du SMIA — maintient l'inventaire de l'IA tierce.",
                ],
                "Vérifiée par des revues fournisseurs et l'audit. Revue annuelle.",
            ),
        },
    },
    {
        "ref": "AIMS-POL-10", "clause": "Clause 8 / Annex A",
        "en": {
            "name": "AI Incident Management & Reporting Policy",
            "desc": "Defines how AI-related incidents, malfunctions and harms are detected, reported, handled and learned from.",
            "content": _en(
                "Ensure AI-related incidents — malfunctions, harmful outputs, misuse, safety or security events — are promptly detected, reported, handled and used to improve the AIMS.",
                "All AI systems within the AIMS scope and everyone operating or affected by them.",
                [
                    "AI incidents and near-misses are reported through defined channels without fear of reprisal.",
                    "Incidents are triaged, contained, investigated and remediated under the incident process.",
                    "Regulators and affected parties are notified where legally required.",
                    "Lessons learned feed back into risk assessments, controls and training.",
                ],
                [
                    "All staff — report suspected AI incidents.",
                    "Incident response — handles AI incidents end to end.",
                    "AIMS Manager — tracks trends and drives improvement.",
                ],
                "Verified through incident metrics and audit. Reviewed annually.",
            ),
        },
        "fr": {
            "name": "Politique de Gestion et de Signalement des Incidents d'IA",
            "desc": "Définit la manière dont les incidents, dysfonctionnements et préjudices liés à l'IA sont détectés, signalés, traités et exploités pour s'améliorer.",
            "content": _fr(
                "Garantir que les incidents liés à l'IA — dysfonctionnements, sorties préjudiciables, mésusages, événements de sûreté ou de sécurité — sont détectés, signalés, traités rapidement et exploités pour améliorer le SMIA.",
                "Tous les systèmes d'IA du périmètre du SMIA et toute personne les exploitant ou en subissant les effets.",
                [
                    "Les incidents et quasi-incidents d'IA sont signalés via des canaux définis, sans crainte de représailles.",
                    "Les incidents sont triés, contenus, investigués et remédiés selon le processus de gestion des incidents.",
                    "Les régulateurs et les parties affectées sont notifiés lorsque la loi l'exige.",
                    "Les enseignements tirés alimentent les analyses de risque, les contrôles et la formation.",
                ],
                [
                    "Ensemble du personnel — signale les incidents d'IA suspectés.",
                    "Réponse aux incidents — traite les incidents d'IA de bout en bout.",
                    "Responsable du SMIA — suit les tendances et pilote l'amélioration.",
                ],
                "Vérifiée par des indicateurs d'incidents et l'audit. Revue annuelle.",
            ),
        },
    },
]


def _ensure_columns(conn: sqlite3.Connection) -> None:
    existing = {r[1] for r in conn.execute('PRAGMA table_info("POLICY")')}
    if not existing:
        # POLICY should already exist (legacy schema); create a minimal one if not.
        conn.execute('CREATE TABLE IF NOT EXISTS POLICY ("PolicyID" INTEGER NOT NULL, "PolicyName" TEXT, "PolicyDescription" TEXT, "CreatedDate" TEXT)')
        existing = {r[1] for r in conn.execute('PRAGMA table_info("POLICY")')}
    for col, typ in _EXTRA_COLS.items():
        if col not in existing:
            conn.execute(f'ALTER TABLE "POLICY" ADD COLUMN "{col}" {typ}')


def _resolve_owner(conn: sqlite3.Connection, owner: int) -> int | None:
    """owner > 0: use it. owner == 0: auto-pick the first PERSON. owner < 0: none."""
    if owner < 0:
        return None
    if owner > 0:
        return owner
    try:
        r = conn.execute("SELECT MIN(PersonID) FROM PERSON").fetchone()
        return int(r[0]) if r and r[0] is not None else None
    except Exception:
        return None


def seed(db_dir: str, tenant: int, langs, owner: int = 0, dry: bool = False) -> None:
    path = os.path.join(db_dir, "XORCISM.db")
    if not os.path.exists(path):
        print(f"[{MODULE}] XORCISM.db not found at {path}", file=sys.stderr)
        sys.exit(2)
    conn = sqlite3.connect(path)
    try:
        _ensure_columns(conn)
        owner_id = _resolve_owner(conn, owner)
        today = _dt.date.today()
        eff = today.isoformat()
        review = today.replace(year=today.year + 1).isoformat()
        nxt = (conn.execute('SELECT COALESCE(MAX("PolicyID"),0) FROM POLICY').fetchone()[0]) + 1
        ins = upd = 0
        for tpl in POLICIES:
            ref = tpl["ref"]
            status = STATUS_OVERRIDE.get(ref, "Published")
            published = status == "Published"
            draft = status == "Draft"
            for lang in langs:
                body = tpl[lang]
                name = body["name"]
                desc = body["desc"]
                content = body["content"]
                row = conn.execute(
                    'SELECT "PolicyID" FROM POLICY WHERE "PolicyReference"=? AND "Language"=?',
                    (ref, lang),
                ).fetchone()
                vals = {
                    "PolicyName": name, "PolicyDescription": desc, "PolicyContent": content,
                    "PolicyReference": ref, "Clause": tpl["clause"], "Framework": FRAMEWORK,
                    "Category": CATEGORY, "Classification": "Internal", "Language": lang,
                    "Status": status, "WorkflowStatus": status, "Version": ("1.0" if published else "0.9"),
                    "Scope": "Organisation-wide AI Management System (AIMS)",
                    "OwnerPersonID": owner_id,
                    "ApprovedByPersonID": (owner_id if published else None),
                    "EffectiveDate": (eff if published else None),
                    "ReviewDate": (review if published else None),
                    "ApprovedDate": (eff if published else None),
                    "TenantID": tenant,
                }
                if dry:
                    print(f"  [{ 'UPD' if row else 'NEW'}] {ref} [{lang}] — {name}")
                    continue
                if row:
                    sets = ", ".join(f'"{k}"=?' for k in vals)
                    conn.execute(f'UPDATE POLICY SET {sets} WHERE "PolicyID"=?', (*vals.values(), row[0]))
                    upd += 1
                else:
                    cols = ["PolicyID", "CreatedDate", *vals.keys()]
                    ph = ",".join("?" for _ in cols)
                    conn.execute(
                        f'INSERT INTO POLICY ({",".join(chr(34)+c+chr(34) for c in cols)}) VALUES ({ph})',
                        (nxt, eff, *vals.values()),
                    )
                    nxt += 1
                    ins += 1
        if not dry:
            conn.commit()
        print(f"[{MODULE}] tenant={tenant} langs={','.join(langs)} → {ins} inserted, {upd} updated "
              f"({len(POLICIES)} policies × {len(langs)} languages)")
    finally:
        conn.close()


def main() -> None:
    ap = argparse.ArgumentParser(description="Seed ISO/IEC 42001:2023 AIMS policies (EN/FR) into XORCISM.POLICY")
    ap.add_argument("--db-dir", default=_DB_DIR, help="directory containing XORCISM.db")
    ap.add_argument("--tenant", type=int, default=3, help="TenantID to assign (default 3)")
    ap.add_argument("--lang", choices=["en", "fr", "both"], default="both", help="language(s) to seed")
    ap.add_argument("--owner", type=int, default=0, help="OwnerPersonID (0=auto-pick first PERSON, -1=none)")
    ap.add_argument("--list", action="store_true", help="show what would be written, do not modify")
    args = ap.parse_args()
    langs = ["en", "fr"] if args.lang == "both" else [args.lang]
    seed(args.db_dir, args.tenant, langs, owner=args.owner, dry=args.list)


if __name__ == "__main__":
    main()
