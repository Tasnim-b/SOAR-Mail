from django.contrib import admin

# Register your models here.

from django.contrib import admin
from .models import Playbook, PlaybookRule, PlaybookAction, IncidentLog

class PlaybookRuleInline(admin.TabularInline):
    model = PlaybookRule
    extra = 1

class PlaybookActionInline(admin.TabularInline):
    model = PlaybookAction
    extra = 1

@admin.register(Playbook)
class PlaybookAdmin(admin.ModelAdmin):
    list_display = ('name', 'is_active', 'priority', 'created_at')
    list_filter = ('is_active',)
    search_fields = ('name', 'description')
    inlines = [PlaybookRuleInline, PlaybookActionInline]

@admin.register(IncidentLog)
class IncidentLogAdmin(admin.ModelAdmin):
    list_display = ('id', 'email', 'playbook', 'status', 'created_at')
    list_filter = ('status', 'playbook')
    search_fields = ('email__sender', 'email__subject', 'notes')
    readonly_fields = ('created_at', 'updated_at')
    
    def has_add_permission(self, request):
        return False  # Les incidents sont créés automatiquement

















#admin@soar.com
#mdp:123456789