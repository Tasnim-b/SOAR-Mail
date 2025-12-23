# 🔧 Correction: Mise en quarantaine automatique des emails malveillants

## 📋 Résumé du problème
Les emails analysés avec le statut `threat_type = 'MALWARE'` ou `threat_level = 'HIGH'/'CRITICAL'` n'étaient **PAS mis automatiquement en quarantaine**. Ils restaient seulement dans la table `EmailMessage` avec le flag `is_quarantined = False`.

---

## ✅ Modifications apportées

### 1️⃣ **Fichier: `core/management/commands/fetch_emails.py`**

**Changement:** Ajout de l'import de `QuarantineEmail`
```python
from core.models import EmailAccount, EmailMessage, QuarantineEmail  # ← AJOUTÉ
```

**Changement:** Création automatique d'une entrée en quarantaine pour les emails malveillants
```python
# ============ AUTOMATIQUEMENT METTRE EN QUARANTAINE LES EMAILS MALVEILLANTS ============
# Si l'email est détecté comme MALWARE ou un threat_level élevé, le mettre automatiquement en quarantaine
if threat_type == 'MALWARE' or threat_level in ['HIGH', 'CRITICAL']:
    try:
        # Marquer l'email comme quarantiné
        email_obj.is_quarantined = True
        email_obj.save()
        
        # Créer une entrée dans QuarantineEmail
        QuarantineEmail.objects.create(
            original_email=email_obj,
            sender=email_data['sender'],
            sender_name=email_data.get('sender_name', ''),
            subject=email_data['subject'],
            received_date=email_data['received_date'],
            body_text=email_data['body_text'],
            body_html=email_data['body_html'],
            attachments=email_data['attachments'],
            threat_type=quarantine_threat_type,
            risk_score=risk_score,
            size=email_data['size'],
            has_attachments=email_data['has_attachments'],
            analysis_summary=f"Détecté comme {threat_type} avec un niveau de menace {threat_level}...",
            reason=f"Mis en quarantaine automatiquement - Menace détectée: {threat_type}"
        )
        self.stdout.write(f'    🚨 ✅ Email mis en quarantaine automatiquement: {threat_type} ({threat_level})')
    except Exception as e:
        logger.error(f"Erreur création quarantaine: {e}")
```

---

### 2️⃣ **Fichier: `core/services/playbook_executor.py`**

**Changement:** Ajout de l'import de `QuarantineEmail`
```python
from core.models import Playbook, PlaybookRule, PlaybookAction, EmailMessage, IncidentLog, QuarantineEmail  # ← AJOUTÉ
```

**Changement:** Amélioration de la méthode `_action_quarantine()` pour créer une vraie entrée en quarantaine
```python
def _action_quarantine(self, action: PlaybookAction) -> Dict:
    """Met l'email en quarantaine"""
    try:
        # Marquer l'email comme quarantiné
        self.email.is_quarantined = True
        self.email.save()
        
        # Vérifier si une quarantaine existe déjà pour cet email
        if not QuarantineEmail.objects.filter(original_email=self.email).exists():
            # Créer une entrée dans QuarantineEmail
            QuarantineEmail.objects.create(
                original_email=self.email,
                sender=self.email.sender,
                sender_name=self.email.sender_name,
                subject=self.email.subject,
                received_date=self.email.received_date,
                body_text=self.email.body_text,
                body_html=self.email.body_html,
                attachments=self.email.attachments,
                threat_type=self.email.threat_type if self.email.threat_type in ['PHISHING', 'SPAM', 'MALWARE', 'SUSPICIOUS', 'SPOOFING'] else 'SUSPICIOUS',
                risk_score=self.email.risk_score,
                size=self.email.size,
                has_attachments=self.email.has_attachments,
                analysis_summary=f"Détecté comme {self.email.threat_type} avec un niveau de menace {self.email.threat_level}...",
                reason=f"Mis en quarantaine par playbook - Menace détectée: {self.email.threat_type}"
            )
        
        return {
            'success': True,
            'message': f'Email mis en quarantaine avec succès',
            'email_id': self.email.id
        }
    except Exception as e:
        logger.error(f"Erreur lors de la quarantaine: {e}")
        return {
            'success': False,
            'error': str(e),
            'email_id': self.email.id
        }
```

---

## 🔄 Flux complet de la quarantaine automatique

```
┌─────────────────────────────────────────────────────────────────┐
│ 1. Email reçu depuis IMAP                                       │
└──────────────────────────┬──────────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────────┐
│ 2. EmailAnalyzer analyse l'email                                │
│    ↓                                                             │
│    - Détecte threat_type = 'MALWARE'                            │
│    - Assigne threat_level = 'HIGH' ou 'CRITICAL'               │
└──────────────────────────┬──────────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────────┐
│ 3. EmailMessage créé avec les données d'analyse                 │
└──────────────────────────┬──────────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────────┐
│ 4. ✨ NOUVEAU: Vérifier la condition                             │
│    if threat_type == 'MALWARE' OR                               │
│       threat_level in ['HIGH', 'CRITICAL']                      │
└──────────────────────────┬──────────────────────────────────────┘
                           │
        ┌──────────────────┴──────────────────┐
        │ OUI                                 │ NON
        ▼                                     ▼
    ┌─────────────────────┐           ┌──────────────┐
    │ Marquer:            │           │ Email reste  │
    │ is_quarantined=True │           │ Normal       │
    │                     │           └──────────────┘
    │ Créer entrée        │
    │ QuarantineEmail     │
    │ avec détails        │
    │ Affiche ✅          │
    └─────────────────────┘
        │
        ▼
    ┌──────────────────────────────────────┐
    │ 5. PlaybookExecutor exécute          │
    │    - Actions sur email               │
    │    - Peut ajouter quarantaine via    │
    │      action playbook                 │
    └──────────────────────────────────────┘
```

---

## 🧪 Comment tester

### Via CLI (commande de gestion)
```bash
python manage.py fetch_emails --limit 5
```

**Résultat attendu:**
```
📧 Traitement du compte: Mon Compte
  ✅ 5 emails récupérés
    🚨 Menace détectée: MALWARE (HIGH) - Sujet de l'email...
    🚨 ✅ Email mis en quarantaine automatiquement: MALWARE (HIGH)
    ⚡ Action exécutée: quarantine - Email mis en quarantaine...
```

### Via API Frontend
1. Ouvrir `quarantaine.html`
2. Vérifier que les emails malveillants y apparaissent automatiquement
3. Vérifier les détails: type de menace, score de risque, date

### Via API Django Shell
```bash
python manage.py shell

from core.models import EmailMessage, QuarantineEmail

# Vérifier les emails en quarantaine
quarantined = QuarantineEmail.objects.all()
print(f"Emails en quarantaine: {quarantined.count()}")

for q in quarantined:
    print(f"- {q.sender}: {q.subject} ({q.threat_type})")
```

---

## 📊 Schéma de la base de données

```
EmailMessage
├── id
├── threat_level (SAFE, LOW, MEDIUM, HIGH, CRITICAL)
├── threat_type (PHISHING, SPAM, MALWARE, SUSPICIOUS, SPOOFING, NONE)
├── is_quarantined ← ✨ Marqué TRUE si malveillant
└── ...

QuarantineEmail (OneToOneField vers EmailMessage)
├── id
├── original_email ← Référence l'EmailMessage
├── threat_type
├── risk_score
├── quarantined_at
├── reason (raison de la quarantaine)
└── ...
```

---

## 🎯 Conditions de quarantaine automatique

Un email est **automatiquement mis en quarantaine** si:

✅ `threat_type == 'MALWARE'` **OU**
✅ `threat_level == 'HIGH'` **OU**
✅ `threat_level == 'CRITICAL'`

---

## 📝 Notes importantes

### ✔️ Points positifs
- Quarantaine automatique et immédiate
- Pas besoin d'action manuelle de l'administrateur
- Enregistrement complet dans la DB
- Intégration avec les playbooks

### ⚠️ Points à surveiller
1. **Performance**: Si vous avez beaucoup d'emails, vérifiez les performances DB
2. **Faux positifs**: L'analyseur peut marquer à tort des emails comme malveillants
3. **Restoration**: Les utilisateurs doivent pouvoir restaurer depuis `quarantaine.html`

---

## 🔗 Fichiers modifiés

1. ✅ `core/management/commands/fetch_emails.py` - Quarantaine auto
2. ✅ `core/services/playbook_executor.py` - Amélioration action quarantine

## 🚀 Prochaines étapes (optionnel)

Si vous voulez aller plus loin:
- [ ] Ajouter une whitelist (emails à ne pas quarantainer)
- [ ] Ajouter des notifications par email à l'admin
- [ ] Créer un playbook pour automatiser la réponse
- [ ] Ajouter une expiration de la quarantaine (30 jours)
- [ ] Dashboard statistiques des emails en quarantaine

---

**Date:** 23 décembre 2025
**Statut:** ✅ Corrections appliquées
