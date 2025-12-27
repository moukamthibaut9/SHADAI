from django.urls import path
from .views import home, services, contact, generate_keys, compute_secret, steganographier, steganalyser, detect_deepfake

urlpatterns = [
    path('', home, name='home'),
    path('home/contact/', contact, name='contact'),
    path('services/', services, name='services'),
    path('services/generate_keys/', generate_keys, name='generate_keys'),
    path('services/compute_secret/', compute_secret, name='compute_secret'),
    path('services/steganographier/', steganographier, name='steganographier'),
    path('services/steganalyser/', steganalyser, name='steganalyser'),
    path('services/detect_deepfake/', detect_deepfake, name='detect_deepfake'),
]