from django import forms


SCAN_TYPE_CHOICES = [
    ('general', 'Auto-Detect'),
    ('sms', 'SMS Message'),
    ('email', 'Email Body'),
    ('email_header', 'Email Header (Spam Check)'),
    ('whatsapp', 'WhatsApp Message'),
    ('url', 'URL / Link'),
]


class ScanForm(forms.Form):
    scan_type = forms.ChoiceField(
        choices=SCAN_TYPE_CHOICES,
        initial='general',
        widget=forms.Select(
            attrs={
                'class': 'w-full rounded-lg border border-slate-700 bg-slate-950 px-4 py-3 text-white focus:outline-none focus:ring-2 focus:ring-cyan-500',
            }
        ),
    )
    message = forms.CharField(
        label="Content to Analyze",
        widget=forms.Textarea(
            attrs={
                'placeholder': 'Paste a suspicious SMS, email, WhatsApp message, email header, or URL here...',
                'rows': 6,
                'class': 'w-full rounded-lg border border-slate-700 bg-slate-950 px-4 py-3 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500 resize-vertical',
            }
        ),
        max_length=20000,
        strip=True,
    )
