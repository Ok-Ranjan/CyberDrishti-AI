from django.shortcuts import render
from .forms import ScanForm
# Create your views here.

def home(request):
    form = ScanForm()

    if request.method == "POST":
        form = ScanForm(request.POST)

        if form.is_valid():
            message = form.cleaned_data['message']

        return render(request, 'scanner/result.html', {'message': message, 'result': None})

    return render(request, 'scanner/home.html', {'form':form})
