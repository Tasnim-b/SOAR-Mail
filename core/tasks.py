# #Tâches Celery : analyse IMAP, exécution playbooks
# # core/tasks.py
# from celery import shared_task
# from core.playbook_engine import PlaybookEngine
# from core.models import EmailMessage

# @shared_task
# def run_playbooks_for_email(email_id):
#     """Tâche Celery pour exécuter les playbooks de manière asynchrone"""
#     try:
#         email = EmailMessage.objects.get(id=email_id)
#         engine = PlaybookEngine()
#         engine.run_all_playbooks_for_email(email)
#         return True
#     except Exception as e:
#         print(f"Erreur dans la tâche Celery: {e}")
#         return False