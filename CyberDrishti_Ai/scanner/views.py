import json

from django.shortcuts import render, get_object_or_404
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

from .forms import ScanForm
from .detection import analyze_message
from .models import ScanHistory
from .services.aikosh_engine import AIKOSH_MODELS


def home(request):
    """Home page with scan form."""
    if request.method == "POST":
        form = ScanForm(request.POST)

        if form.is_valid():
            message = form.cleaned_data['message']
            scan_type = form.cleaned_data['scan_type']
            result = analyze_message(message, scan_type)

            # Save to history
            history_entry = ScanHistory.objects.create(
                scan_type=scan_type,
                input_text=message,
                risk_score=result.get('score', 0),
                risk_level=result.get('risk_level', 'Low'),
                is_phishing=result.get('is_phishing', False),
                threat_category=result.get('threat_category', 'No strong pattern detected'),
                analysis_source=result.get('analysis_source', 'rules'),
                result_json=result,
                aikosh_models_referenced=[
                    model_info['id']
                    for model_info in AIKOSH_MODELS.values()
                ],
            )

            return render(request, 'scanner/result.html', {
                'message': message,
                'result': result,
                'scan_id': str(history_entry.id),
                'aikosh_models': AIKOSH_MODELS,
            })
    else:
        form = ScanForm()

    return render(request, 'scanner/home.html', {
        'form': form,
        'aikosh_models': AIKOSH_MODELS,
    })


def history(request):
    """History page showing all past scans."""
    scans = ScanHistory.objects.all()[:50]

    # Stats for the dashboard
    total_scans = ScanHistory.objects.count()
    phishing_count = ScanHistory.objects.filter(is_phishing=True).count()
    safe_count = total_scans - phishing_count
    high_risk = ScanHistory.objects.filter(risk_level='High').count()

    return render(request, 'scanner/history.html', {
        'scans': scans,
        'total_scans': total_scans,
        'phishing_count': phishing_count,
        'safe_count': safe_count,
        'high_risk': high_risk,
    })


def scan_detail(request, scan_id):
    """View a single past scan result in detail."""
    entry = get_object_or_404(ScanHistory, id=scan_id)
    result = entry.result_json
    return render(request, 'scanner/result.html', {
        'message': entry.input_text,
        'result': result,
        'scan_id': str(entry.id),
        'aikosh_models': AIKOSH_MODELS,
        'from_history': True,
    })


@csrf_exempt
def api_scan(request):
    """Simple JSON API endpoint for programmatic access."""
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)

    try:
        body = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)

    message = body.get('message', '').strip()
    scan_type = body.get('scan_type', 'general')

    if not message:
        return JsonResponse({'error': 'message is required'}, status=400)

    result = analyze_message(message, scan_type)

    # Save to history
    ScanHistory.objects.create(
        scan_type=scan_type,
        input_text=message,
        risk_score=result.get('score', 0),
        risk_level=result.get('risk_level', 'Low'),
        is_phishing=result.get('is_phishing', False),
        threat_category=result.get('threat_category', ''),
        analysis_source=result.get('analysis_source', 'rules'),
        result_json=result,
        aikosh_models_referenced=[
            m['id'] for m in AIKOSH_MODELS.values()
        ],
    )

    return JsonResponse(result)
