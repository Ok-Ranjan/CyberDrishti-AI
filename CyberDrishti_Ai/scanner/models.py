from django.db import models
import uuid


class ScanHistory(models.Model):
    """Stores every scan for the History page."""
    
    SCAN_TYPE_CHOICES = [
        ('sms', 'SMS'),
        ('email', 'Email'),
        ('email_header', 'Email Header'),
        ('whatsapp', 'WhatsApp'),
        ('url', 'URL'),
        ('general', 'General Message'),
    ]
    
    RISK_LEVEL_CHOICES = [
        ('Low', 'Low'),
        ('Medium', 'Medium'),
        ('High', 'High'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan_type = models.CharField(max_length=20, choices=SCAN_TYPE_CHOICES, default='general')
    input_text = models.TextField(help_text="The raw content submitted for scanning.")
    risk_score = models.IntegerField(default=0)
    risk_level = models.CharField(max_length=10, choices=RISK_LEVEL_CHOICES, default='Low')
    is_phishing = models.BooleanField(default=False)
    threat_category = models.CharField(max_length=100, default='No strong pattern detected')
    analysis_source = models.CharField(max_length=100, default='rules + aikosh_heuristics')
    result_json = models.JSONField(default=dict, help_text="Full JSON result for detail view.")
    aikosh_models_referenced = models.JSONField(default=list, help_text="AIKosh model IDs used.")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']
        verbose_name_plural = 'Scan histories'

    def __str__(self):
        return f"{self.scan_type} scan — {self.risk_level} risk — {self.created_at:%Y-%m-%d %H:%M}"
