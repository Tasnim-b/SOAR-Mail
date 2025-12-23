# from django.test import TestCase

# # Create your tests here.
# from core.models import Playbook, PlaybookRule, PlaybookAction

# # 1. Playbook pour les emails de phishing
# phishing_playbook = Playbook.objects.create(
#     name="Bloquer les emails de phishing",
#     description="Détecte et bloque les emails de phishing",
#     is_active=True,
#     priority=1
# )

# # Règle: email avec risque élevé
# PlaybookRule.objects.create(
#     playbook=phishing_playbook,
#     field='threat_level',
#     operator='in',
#     value='HIGH,CRITICAL',
#     negate=False
# )

# # Action: mettre en quarantaine
# PlaybookAction.objects.create(
#     playbook=phishing_playbook,
#     action_type='quarantine',
#     parameters={'folder': 'INBOX.Quarantine'},
#     order=1
# )

# # Action: notifier l'admin
# PlaybookAction.objects.create(
#     playbook=phishing_playbook,
#     action_type='notify',
#     parameters={
#         'notify_to': 'admin@soar.com',
#         'subject': 'Alerte phishing détectée'
#     },
#     order=2
# )

# # 2. Playbook pour les spams
# spam_playbook = Playbook.objects.create(
#     name="Gérer les spams",
#     description="Actions pour les emails spam",
#     is_active=True,
#     priority=2
# )

# PlaybookRule.objects.create(
#     playbook=spam_playbook,
#     field='threat_type',
#     operator='equals',
#     value='SPAM',
#     negate=False
# )

# PlaybookAction.objects.create(
#     playbook=spam_playbook,
#     action_type='move_to_folder',
#     parameters={'folder': 'INBOX.Spam'},
#     order=1
# )

# print("✅ Playbooks de test créés!")



# # test_playbook_integration.py

# import os
# import django
# import sys

# # Configuration Django
# sys.path.append('.')
# os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'soar_mail_project.settings')
# django.setup()

# from core.models import EmailMessage, EmailAccount, IncidentLog, QuarantineEmail
# from django.utils import timezone
# from core.services.playbook_executor import PlaybookExecutor

# print("🧪 TEST INTÉGRATION PLAYBOOKS")
# print("=" * 50)

# # 1. Vérifier les playbooks existants
# from core.models import Playbook
# playbooks = Playbook.objects.filter(is_active=True)
# print(f"📋 {playbooks.count()} playbook(s) actif(s)")

# for playbook in playbooks:
#     print(f"  - {playbook.name} (Priorité: {playbook.priority})")
#     for rule in playbook.rules.all():
#         print(f"    Règle: {rule.field} {rule.operator} '{rule.value}'")

# # 2. Créer un email de phishing (HIGH/CRITICAL)
# account = EmailAccount.objects.first()
# if not account:
#     print("❌ Aucun compte email trouvé. Créez-en un d'abord.")
#     exit()

# email = EmailMessage.objects.create(
#     account=account,
#     uid="test_phishing_001",
#     message_id="<phishing@evil.com>",
#     sender="phishing@evil-bank.com",
#     sender_name="Banque Frauduleuse",
#     recipients="victime@entreprise.com",
#     subject="URGENT: Votre compte bancaire a été compromis",
#     received_date=timezone.now(),
#     body_text="Cher client, votre compte a été compromis. Cliquez ici pour le sécuriser: http://evil-bank-fake.com/login",
#     body_html="<html><body><h1>URGENT</h1><p>Votre compte a été compromis. <a href='http://evil-bank-fake.com/login'>Cliquez ici pour le sécuriser</a></p></body></html>",
#     attachments=[],
#     has_attachments=False,
#     size=2048,
#     threat_level="HIGH",  # Ceci devrait déclencher le playbook phishing
#     threat_type="PHISHING",
#     risk_score=92,  # Score élevé
#     analyzed=True,
#     analysis_date=timezone.now()
# )

# print(f"\n📧 Email de test créé:")
# print(f"  Sujet: {email.subject}")
# print(f"  Expéditeur: {email.sender}")
# print(f"  Score de risque: {email.risk_score}%")
# print(f"  Niveau de menace: {email.threat_level}")
# print(f"  Type de menace: {email.threat_type}")

# # 3. Exécuter les playbooks
# print("\n⚡ Exécution des playbooks...")
# executor = PlaybookExecutor(email)
# results = executor.execute_playbooks()

# if results:
#     print(f"✅ {len(results)} action(s) exécutée(s)")
#     for result in results:
#         print(f"  - Playbook: {result['playbook']}")
#         print(f"    Action: {result['action']}")
#         print(f"    Résultat: {result['result'].get('message', 'N/A')}")
# else:
#     print("⚠️ Aucun playbook déclenché")

# # 4. Vérifier les incidents créés
# print("\n📊 Vérification des incidents...")
# incidents = IncidentLog.objects.filter(email=email)
# print(f"  {incidents.count()} incident(s) créé(s)")

# for incident in incidents:
#     print(f"  - Incident #{incident.id}")
#     print(f"    Playbook: {incident.playbook.name if incident.playbook else 'Automatique'}")
#     print(f"    Statut: {incident.get_status_display()}")
#     print(f"    Actions: {len(incident.actions_executed)}")

# # 5. Vérifier la quarantaine
# print("\n🛡️ Vérification de la quarantaine...")
# if hasattr(email, 'quarantine'):
#     quarantine = email.quarantine
#     print(f"✅ Email mis en quarantaine")
#     print(f"  ID quarantaine: {quarantine.id}")
#     print(f"  Raison: {quarantine.reason}")
# else:
#     print("❌ Email non mis en quarantaine")

# # 6. Vérifier les statistiques
# print("\n📈 Statistiques après test:")
# print(f"  Total emails: {EmailMessage.objects.count()}")
# print(f"  Total incidents: {IncidentLog.objects.count()}")
# print(f"  Total quarantaine: {QuarantineEmail.objects.count()}")

# print("\n" + "=" * 50)
# print("🎉 TEST TERMINÉ")





# test_scenarios.py
import os
import django
import sys

sys.path.append('.')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'soar_mail_project.settings')
django.setup()

from core.models import EmailMessage, EmailAccount
from django.utils import timezone
from core.services.playbook_executor import PlaybookExecutor
import uuid

account = EmailAccount.objects.first()

scenarios = [
    {
        'name': 'Phishing critique',
        'sender': 'hack@phishing.com',
        'subject': 'Votre compte PayPal a été piraté',
        'threat_level': 'CRITICAL',
        'threat_type': 'PHISHING',
        'risk_score': 98,
        'should_trigger': True  # Devrait déclencher le playbook phishing
    },
    {
        'name': 'Spam normal',
        'sender': 'spam@promo.com',
        'subject': 'Offre spéciale -90%',
        'threat_level': 'LOW',
        'threat_type': 'SPAM',
        'risk_score': 30,
        'should_trigger': True  # Devrait déclencher le playbook spam
    },
    {
        'name': 'Email sécurisé',
        'sender': 'boss@entreprise.com',
        'subject': 'Réunion hebdomadaire',
        'threat_level': 'SAFE',
        'threat_type': 'NONE',
        'risk_score': 5,
        'should_trigger': False  # Ne devrait pas déclencher
    }
]

print("🧪 TESTS MULTIPLES DE SCÉNARIOS")
print("=" * 50)

for scenario in scenarios:
    print(f"\n📨 Scénario: {scenario['name']}")
    print(f"  Sujet: {scenario['subject']}")
    print(f"  Score: {scenario['risk_score']}%")
    
    # Génère un UID unique pour éviter les collisions si on relance le script
    uid = f"test_scenario_{scenario['name'].replace(' ', '_').lower()}_{uuid.uuid4().hex[:8]}"
    email = EmailMessage.objects.create(
        account=account,
        uid=uid,
        sender=scenario['sender'],
        subject=scenario['subject'],
        received_date=timezone.now(),
        threat_level=scenario['threat_level'],
        threat_type=scenario['threat_type'],
        risk_score=scenario['risk_score'],
        analyzed=True,
        size=4096
    )
    
    executor = PlaybookExecutor(email)
    results = executor.execute_playbooks()
    
    if results:
        print(f"  ✅ Playbooks déclenchés: {len(results)}")
        for result in results[:2]:  # Afficher max 2 résultats
            print(f"    - {result['playbook']}: {result['action']}")
    else:
        print(f"  ⚠️ Aucun playbook déclenché")
    
    # Vérification
    if scenario['should_trigger'] and not results:
        print(f"  ❌ ATTENTION: Devrait déclencher mais n'a pas déclenché!")
    elif not scenario['should_trigger'] and results:
        print(f"  ❌ ATTENTION: Ne devrait pas déclencher mais a déclenché!")
    else:
        print(f"  ✓ Comportement attendu")

print("\n" + "=" * 50)
print("🎯 Tests de scénarios terminés")


#python manage.py shell
#exec(open('core/tests.py', encoding='utf-8').read())