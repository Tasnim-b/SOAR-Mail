
## 🛡️ SOAR-Mail

#### Security Orchestration, Automation and Response for Email Threats
SOAR-Mail est une plateforme de sécurité des emails développée avec Django & Django REST Framework, permettant l’analyse automatique des emails, la détection des menaces (phishing, malware, spam…), l’exécution de playbooks SOAR, et la mise en quarantaine automatique des emails malveillants.


## 🚀 Fonctionnalités principales
- Récupération automatique des emails (Celery & Redis)
- Analyse automatique des emails
- Détection des menaces
- Mise en quarantaine des emails suspects
- Automatisation via playbooks SOAR
- Tableau de bord de supervision
- Statistiques et indicateurs clés (KPI)
- Identification des sources de menaces
- Gestion sécurisée des accès
- Interface utilisateur sécurisée avec contrôle d'accès par rôle
## 🧠 Technologies utilisées

- Backend : Django, Django REST Framework
- Traitement asynchrone : Celery, Redis
- Base de données : SQLite
- Frontend : HTML, CSS, JavaScript
- Charts : Chart.js
- Analyse sécurité : Moteur d’analyse des menaces
- Auth : JWT
- API : RESTful avec pagination et filtres
- Sécurité : CORS, CSRF, Validation JWT
- Infrastructure : IMAP, SMTP
- Architecture : SOAR (Security Orchestration, Automation & Response)


## 🔄 Flux de traitement des emails
```
┌──────────────────────────────────────────────────────────┐
│ 1. Planification automatique (Celery Beat)              │
└──────────────────────────┬───────────────────────────────┘
                           │
┌──────────────────────────▼───────────────────────────────┐
│ 2. Récupération des emails via IMAP                      │
│    (Tâche Celery asynchrone)                              │
└──────────────────────────┬───────────────────────────────┘
                           │
┌──────────────────────────▼───────────────────────────────┐
│ 3. Analyse de sécurité de l’email                        │
│    - threat_type                                         │
│    - threat_level                                        │
│    - risk_score                                          │
└──────────────────────────┬───────────────────────────────┘
                           │
┌──────────────────────────▼───────────────────────────────┐
│ 4. Enregistrement dans EmailMessage                     │
└──────────────────────────┬───────────────────────────────┘
                           │
┌──────────────────────────▼───────────────────────────────┐
│ 5. Vérification des règles automatiques                  │
│    - MALWARE                                             │
│    - HIGH / CRITICAL                                     │
└──────────────────────────┬───────────────────────────────┘
                           │
        ┌──────────────────┴──────────────────┐
        │ OUI                                 │ NON
        ▼                                     ▼
┌──────────────────────────────┐      ┌────────────────────┐
│ 6. Mise en quarantaine auto   │      │ Email normal       │
│    - is_quarantined = True   │      │                    │
│    - QuarantineEmail créé    │      └────────────────────┘
└──────────────────────────────┘
        │
        ▼
┌──────────────────────────────────────────┐
│ 7. Exécution des playbooks SOAR          │
│    - Quarantine                          │
│    - Alert                               │
│    - Log incident                       │
└──────────────────────────────────────────┘
        │
        ▼
┌──────────────────────────────────────────┐
│ 8. Exposition via API REST               │
│    - Dashboard                           │
│    - Quarantaine                         │
│    - Statistiques                        │
└──────────────────────────────────────────┘

```

## 📥 Installation
### 1️⃣ Cloner le dépôt
```
git clone https://github.com/Tasnim-b/SOAR-Mail.git
cd SOAR-Mail
```

### 2️⃣ Créez un environnement virtuel avec pipenv
```
pipenv install
```
### 3️⃣ Activez l'environnement 
```
pipenv shell
```
### 4️⃣ installer les dépendances
```
pip install -r requirements.txt
```
### 5️⃣ Appliquer les migrations
```
python manage.py makemigrations
python manage.py migrate
```
### 6️⃣ Créer un super utilisateur (admin)
```
python manage.py createsuperuser
```
### 7️⃣ installer Redis (sur windows 11)
Téléchargez et installez Redis depuis :

https://github.com/tporadowski/redis/releases

### 8️⃣ Lancer Celery avec Redis (récupération automatique des emails)

``` 
# Lancer Celery Beat (planification des tâches)
celery -A soar_mail_project beat --loglevel=info

# Lancer Celery Worker (traitement des emails)
celery -A soar_mail_project worker --loglevel=info --pool=solo
```
### 9️⃣ Lancer le serveur Django
```
python manage.py runserver
```
![Login Page](https://raw.githubusercontent.com/Tasnim-b/SOAR-Mail/master/img/loginPage.png)
