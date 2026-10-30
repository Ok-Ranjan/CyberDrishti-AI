from django.contrib import admin
from .models import ScanHistory


@admin.register(ScanHistory)
class ScanHistoryAdmin(admin.ModelAdmin):
    list_display = ('scan_type', 'risk_level', 'is_phishing', 'threat_category', 'created_at')
    list_filter = ('scan_type', 'risk_level', 'is_phishing')
    search_fields = ('input_text', 'threat_category')
    readonly_fields = ('id', 'result_json', 'aikosh_models_referenced', 'created_at')
    ordering = ('-created_at',)
