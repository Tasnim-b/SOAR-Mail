# Configuration Celery
# soar_mail/celery.py
#pouvoir exécuter des tâches en arrière-plan, comme la récupération d’emails, l’exécution de playbooks, ou tout processus long.
import os
from celery import Celery

# Set the default Django settings module
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'soar_mail_project.settings')

app = Celery('soar_mail_project')#load settings from Django settings, the CELERY namespace means

# Using a string here means the worker doesn't have to serialize
# the configuration object to child processes.
app.config_from_object('django.conf:settings', namespace='CELERY')

# Load task modules from all registered Django apps.
app.autodiscover_tasks()# Define a debug task

@app.task(bind=True)
def debug_task(self):
    print(f'Request: {self.request!r}')


# celery -A soar_mail_project worker --loglevel=info --pool=solo

#celery -A soar_mail_project beat --loglevel=info
