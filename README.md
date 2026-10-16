# 🔭 OSINT Platform v2.0 — Local

Plateforme OSINT complète avec IA, 12 APIs et interface web moderne.

## ⚡ Démarrage rapide

```bash
# 1. Installer les dépendances
pip install -r requirements.txt

# 2. Configurer les clés API
cp .env.example .env
# Éditez .env et ajoutez au minimum : GROQ_API_KEY=gsk_...

# 3. Lancer le serveur
python main.py
# → http://localhost:8000
```

## 📋 Prérequis

- Python ≥ 3.10
- Clé API Groq (obligatoire, gratuite) : https://console.groq.com/keys

## 🔑 Clés API

| API | Gratuit | Lien |
|-----|---------|------|
| **Groq (Llama 3.3)** ⭐ obligatoire | Gratuit | https://console.groq.com/keys |
| Pappers | 1000 req/mois | https://www.pappers.fr/api |
| Have I Been Pwned | 3,50$/mois | https://haveibeenpwned.com/API/Key |
| Hunter.io | 25 req/mois | https://hunter.io |
| IPInfo | 50k req/mois | https://ipinfo.io/account/token |
| AbuseIPDB | 1000/jour | https://www.abuseipdb.com/account/api |
| VirusTotal | 4 req/min | https://www.virustotal.com/gui/my-apikey |
| Shodan | Compte gratuit | https://account.shodan.io |
| AlienVault OTX | Illimité | https://otx.alienvault.com/api |

**APIs gratuites sans clé (actives automatiquement) :**
- 🇫🇷 Annuaire Entreprises (gouv.fr)
- ⚖️ BODACC (procédures collectives)
- 🔍 URLScan.io
- 🔐 Certificats SSL (crt.sh)
- 🌐 WHOIS (RDAP)
- 📍 Géolocalisation IP (ip-api.com)

> ⚠️ OpenSanctions exige désormais une clé API côté leur service (changement récent de leur part) — la source reste appelée mais remonte une erreur tant qu'aucune clé n'est configurée.

## 🚀 Fonctionnalités

- **4 modes** : Investigation, Particulier, Entreprise, Recrutement
- **Rapport IA** généré par Llama 3.3 70B (Groq, gratuit)
- **12 APIs** interrogées en parallèle selon le type de cible
- **Export PDF** propre (via fpdf2)
- **Username checker** sur 50+ plateformes (GitHub/Reddit vérifiés en temps réel)
- **Analyse en lot** jusqu'à 10 cibles simultanées
- **Historique** persistent (SQLite)
- **Dossiers** avec timeline et notes
- **Rapport partageable** via lien encodé
- **Graphe D3** des connexions

## 📡 Endpoints API

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| POST | `/api/report` | Génération rapport IA |
| POST | `/api/batch` | Analyse multi-cibles |
| GET | `/api/analyze?q=` | Toutes les APIs en parallèle |
| POST | `/api/username` | Username checker 50+ plateformes |
| POST | `/api/export/pdf` | Export PDF |
| GET | `/api/config` | État des APIs configurées |
| GET | `/api/history` | Historique des recherches |
| DELETE | `/api/history` | Effacer l'historique |
| GET | `/api/cases` | Liste des dossiers |
| POST | `/api/cases` | Créer un dossier |
| PUT | `/api/cases/{id}` | Modifier un dossier |
| DELETE | `/api/cases/{id}` | Supprimer un dossier |
| GET | `/api/pappers/detail?siren=` | Détail Pappers par SIREN |
| POST | `/api/waitlist` | Inscription liste d'attente Premium |
| GET | `/api/docs` | Swagger UI |

## 🧪 Tests

```bash
pip install -r requirements-dev.txt
pytest tests/ -v
```

Les tests tournent aussi automatiquement sur chaque push via GitHub Actions.

## 📁 Structure

```
osint-platform/
├── main.py              ← Backend FastAPI complet
├── requirements.txt     ← Dépendances Python (production)
├── requirements-dev.txt ← + dépendances de test (pytest)
├── tests/                ← Suite de tests automatisés
├── .env.txt              ← Template variables d'environnement
├── .env                  ← Vos clés API (ne pas committer!)
├── osint.db              ← Base SQLite (créée automatiquement)
├── README.md
└── static/
    └── index.html       ← Frontend React
```

## ⚖️ Avertissement légal

Outil conçu pour un usage bienveillant et légal :
- Sources publiques uniquement
- Respectez le RGPD et la loi Informatique et Libertés
- Usage professionnel (enquête, recrutement, due diligence)
- Ne pas utiliser pour du harcèlement ou de la surveillance non autorisée
