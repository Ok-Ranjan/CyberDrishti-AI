from django import forms

class ScanForm(forms.Form):
    message = forms.CharField(
        label="Message or URL",
        widget=forms.Textarea(
            attrs={
                "placeholder":("Paste a suspicious SMS, email, or URL Here..."),
                "rows":6,
            }),
            max_length=10000,
            strip=True,
    )
