from django.shortcuts import render
from .forms import ScanForm
from .detection import analyze_message
# Create your views here.

def home(request):

    if request.method == "POST":
        form = ScanForm(request.POST)

        if form.is_valid():
            message = form.cleaned_data['message']
            result = analyze_message(message)

            return render(request, 'scanner/result.html', {'message': message, 'result': result})
    else:
        form = ScanForm()

    return render(request, 'scanner/home.html', {'form':form})

