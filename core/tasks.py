# core/tasks.py
#Celery (celery.py + tasks.py) : exécute les tâches de manière asynchrone ou planifiée.
from celery import shared_task
from django.core.management import call_command
import logging

logger = logging.getLogger(__name__)

@shared_task
def fetch_and_analyze_emails():
    """Tâche périodique pour récupérer et analyser les emails"""
    try:
        logger.info("🚀 Début de la tâche automatique fetch_and_analyze_emails")
        call_command('fetch_emails', '--limit', '50')
        logger.info("✅ Tâche fetch_and_analyze_emails terminée")
    except Exception as e:
        logger.error(f"❌ Erreur dans fetch_and_analyze_emails: {e}")

@shared_task
def execute_pending_actions():
    """Exécute les actions en attente (pour les actions avec délai)"""
    try:
        logger.info("🔧 Vérification des actions en attente")
        # Ici, tu pourrais implémenter la logique pour les actions différées
        # Par exemple, vérifier les IncidentLog avec status='detected' et appliquer des actions différées
        logger.info("✅ Vérification des actions terminée")
    except Exception as e:
        logger.error(f"❌ Erreur dans execute_pending_actions: {e}")

        #Les emails arrivent → Playbooks sont évalués → Actions exécutées → Logs créés.