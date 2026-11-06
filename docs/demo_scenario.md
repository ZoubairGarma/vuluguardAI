# Scénario de Démonstration Officiel & Guide Oral — VulnGuard AI

Ce document détaille le déroulement pas à pas de la démonstration en direct pour la soutenance, ainsi que les arguments techniques à présenter pour chaque brique du projet.

---

## 1. Vue d'Ensemble de l'Architecture Locale

```text
[Développeur / Auditeur]
       │
       ▼ (1. Soumission d'un requirements.txt)
[Streamlit Interface] ────► [Kafka Producer]
                                   │
                                   ▼ (Topic scan-requests)
                            [Kafka Broker]
                                   │
                                   ▼
                            [Kafka Consumer]
                                   │
        ┌──────────────────────────┼──────────────────────────┐
        ▼                          ▼                          ▼
[OSV / EPSS / KEV]        [Risk Scoring]             [LangGraph Agent 1]
(Bases de vulnérabilités) (Scoring déterministe      (Génération du plan
                          + Modèle ML .joblib)        et explication LLM)
                                                              │
                                                              ▼
                                                    [Human Approval Gate]
                                                    (Contrôle obligatoire)
                                                              │
                                        ┌─────────────────────┴─────────────────────┐
                                        ▼                                           ▼
                                   [REJETÉ]                                    [APPROUVÉ]
                             (Workflow interrompu)                                  │
                                                                                    ▼
                                                                        [LangGraph Agent 2]
                                                                        [Docker Sandbox]
                                                                        (--network=none,
                                                                         isolation multi-python)
                                                                                    │
                                                                                    ▼
                                                                        [Vérification & Rapport]
                                                                        (Téléchargeable en JSON)
```

---

## 2. Déroulé Pas à Pas de la Démonstration (En direct)

### Étape 1 : Lancement des services
Dans vos terminaux :
1. **Lancer Kafka** :
   ```powershell
   docker compose up -d kafka
   ```
2. **Lancer Ollama** (avec le modèle local) :
   ```powershell
   ollama run llama3.2:3b
   ```
   *Réglage recommandé : `temperature: 0.1` à `0.2` pour éliminer les hallucinations de chiffres.*
3. **Lancer le Consumer** :
   ```powershell
   .\.venv\Scripts\Activate.ps1
   python -m src.streaming.consumer
   ```
4. **Lancer l'Interface Streamlit** :
   ```powershell
   .\.venv\Scripts\Activate.ps1
   python -m streamlit run app.py
   ```

---

### Étape 2 : Soumission d'un scan de dépendances (Page "New Scan")
* **Action** : Naviguer vers la page **New Scan** dans Streamlit.
* **Fichier test** : Uploader un fichier `requirements.txt` contenant par exemple :
  ```text
  open-webui==0.1.124
  requests==2.31.0
  urllib3==2.2.1
  ```
* **Ce qu'il faut expliquer au jury** :
  > *« Le scan est sérialisé sous contrat JSON strict (Schéma 1.0) et publié dans un topic Apache Kafka. Le consumer prend en charge l'événement de manière asynchrone pour ne jamais bloquer l'interface utilisateur. »*

---

### Étape 3 : Analyse des risques et explications IA (Page "Scan Details")
* **Action** : Ouvrir le scan dans **Scan Details**.
* **Points forts à montrer** :
  1. **Scoring déterministe & ML** : Montrer le score de risque calculé à partir des bases officielles (CVSS v3, EPSS et CISA KEV). Mentionner le modèle Random Forest entraîné localement (`data/models/risk_model.joblib`) avec plus de 91 % de ROC-AUC.
  2. **Explication IA (« Explain with AI »)** : Cliquer sur le bouton. L'Agent 1 (Ollama) génère une synthèse accessible pour un analyste.
  3. **Garde-fou anti-hallucination** : Expliquer que chaque phrase générée par l'IA est vérifiée par rapport aux données réelles. Si l'IA invente un faux score ou une fausse version de patch, le système censure le texte pour protéger l'analyste.

---

### Étape 4 : Le point d'arrêt humain (Human-in-the-Loop)
* **Action** : Dérouler la section **« Optional security test plan »**.
* **Ce qu'il faut montrer** :
  1. Le statut est à **`PENDING_APPROVAL`**.
  2. Le bouton **« Approve plan »** est grisé et désactivé tant qu'aucun nom d'examinateur n'est renseigné.
  3. Entrer un nom (ex: `admin-sec`) : le bouton devient actif.
  4. Cliquer sur **Approve plan** : le statut passe immédiatement à **`APPROVED`**.
* **Ce qu'il faut expliquer au jury** :
  > *« Conformément aux bonnes pratiques de sécurité, aucun agent autonome n'a le droit d'exécuter des actions techniques sans validation explicite d'un humain. Le graphe LangGraph s'interrompt pour recueillir cette signature. »*

---

### Étape 5 : Exécution sécurisée en bac à sable Docker (Agent 2)
* **Action** : Cliquer sur le bouton vert **« Run approved package-version check »**.
* **Ce qu'il faut montrer** :
  1. L'Agent 2 démarre un conteneur Docker éphémère (`python:3.11-slim-bookworm` ou `3.12`).
  2. Le conteneur s'exécute avec les drapeaux de durcissement : `--network=none`, `--read-only`, `--cap-drop=ALL`.
  3. Il inspecte uniquement les métadonnées de distribution du paquet sans jamais exécuter de code source inconnu.
  4. Le statut passe à **`COMPLETED`** et les résultats de vérification s'affichent en vert.

---

### Étape 6 : Rapport final et export d'audit
* **Action** : Ouvrir **« Final workflow report »** et cliquer sur **« 📥 Download final report (JSON) »**.
* **Ce qu'il faut expliquer au jury** :
  > *« L'ensemble des preuves (preuves d'analyse, identité du validateur humain, logs d'inspection Docker et décision) est consolidé dans un rapport d'audit traçable et téléchargeable pour les équipes de sécurité. »*

