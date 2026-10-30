from django.urls import path
from . import views

app_name = 'scanner'

urlpatterns = [
    path('', views.home, name='home'),
    path('history/', views.history, name='history'),
    path('history/<uuid:scan_id>/', views.scan_detail, name='scan_detail'),
    path('api/scan/', views.api_scan, name='api_scan'),
]