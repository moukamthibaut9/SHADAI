from django.shortcuts import render, redirect
from . import x25519
from django.conf import settings
from django.contrib import messages
from django.core.mail import send_mail
from django.http import HttpResponse
from django.http import FileResponse
from .stego_engine import StegoEngine
import os



def home(request):
    return render(request, 'index.html')


def services(request):
    return render(request, 'services.html')


# ------ Vue pour la gestion de l'envoi d'email via le formulaire de contact
def contact(request):
    # Pour redirriger l'utilisateur sur la meme page(Si HTTP_REFERER est vide, redirige vers "/")
    referer = request.META.get("HTTP_REFERER", "/")
    if request.method == "POST":
        name = request.POST.get('name')
        email = request.POST.get('email')
        subject = request.POST.get('subject')
        message = request.POST.get('message')
        if name and email and subject and message:
            full_message = f"\nMessage de {name}({email})\n\n"+message
            try:
                send_mail(subject, full_message, settings.DEFAULT_FROM_EMAIL, [settings.EMAIL_HOST_USER])
                messages.success(request, "Votre message a  été envoyé. Merci!")
            except:
                messages.warning(request, "Erreur lors de l'envoi; il pourrait s'agir d'un probleme de reseau.")
    return redirect(referer+'#contact')


# --- SECTION 1 : GÉNÉRATION DES CLÉS ---
def generate_keys(request):
    if request.method == 'POST':
        # 1. Générer l'objet clé privée
        private_key_obj = x25519.generate_x25519_key()
        # 2. Extraire la clé publique en bytes puis en Hex pour l'affichage
        public_key_bytes = x25519.get_public_key_bytes(private_key_obj)
        public_key_hex = public_key_bytes.hex()
        
        # 3. Sérialiser la clé privée pour qu'elle soit affichable (format Raw/Hex)
        private_key_bytes = private_key_obj.private_bytes(
            encoding=x25519.Encoding.Raw,
            format=x25519.PrivateFormat.Raw,
            encryption_algorithm=x25519.NoEncryption()
        )
        private_key_hex = private_key_bytes.hex()

        return render(request, 'services.html', {
            'public_key': public_key_hex,
            'private_key': private_key_hex
        })
    return render(request, 'services.html')


# --- SECTION 2 : CALCUL DU SECRET PARTAGÉ ---
def compute_secret(request):
    if request.method == 'POST':
        try:
            # Récupération des entrées Hex de l'utilisateur
            priv_hex = request.POST.get('my_private_key').strip()
            pub_hex_remote = request.POST.get('peer_public_key').strip()
            # Conversion Hex -> Bytes
            priv_bytes = bytes.fromhex(priv_hex)
            pub_bytes_remote = bytes.fromhex(pub_hex_remote)
            # Rechargement de la clé privée locale
            local_private_key = x25519.x25519.X25519PrivateKey.from_private_bytes(priv_bytes)
            # Calcul du secret (en utilisant ta fonction)
            shared_secret_bytes = x25519.derive_shared_secret(local_private_key, pub_bytes_remote)
            return render(request, 'services.html', {
                'shared_secret': shared_secret_bytes.hex()
            })
        except Exception as e:
            return render(request, 'services.html', {'ecdh_error': "Erreur : Clés invalides."})
    return render(request, 'services.html')


# --- SECTION 3 : STEGANOGRAPHIE (CACHER UN MESSAGE DANS UNE IMAGE/VIDEO)  ---
def steganographier(request):
    """Gère l'upload du fichier et le téléchargement du résultat encodé."""
    if request.method == 'POST':
        file = request.FILES.get('file')
        secret_key = request.POST.get('secret_key')
        message = request.POST.get('message')
        # Vérification de la taille du fichier côté serveur pour plus d'efficacité(limitation à 10Mo)
        if file.size > 10 * 1024 * 1024:
            return render(request, 'services.html', {'stego_error': "Fichier trop lourd (max 10Mo)"})

        temp_files_folder = os.path.join(settings.BASE_DIR, 'TEMP_FILES')
        os.makedirs(temp_files_folder, exist_ok=True)
        # Le fichier à stéganographier sera temporairement stocqué dans le dossier 'TEMP_FILES' à la base du projet
        in_path = os.path.join(temp_files_folder, os.path.basename(file.name))
        with open(in_path, 'wb+') as f:
            # Optimisation de la mémoire RAM (Copie du fichier morceau par morceau)
            for chunk in file.chunks(): f.write(chunk)

        ext = os.path.splitext(file.name)[1]
        out_name = f"SHADAI_OUTPUT_FILE{ext}"
        out_path = os.path.join(temp_files_folder, os.path.basename(out_name))
        try:
            engine = StegoEngine(secret_key)
            engine.encode(in_path, message, out_path)
            # On ne fait pas f.read() pour éviter de saturer la RAM avec une vidéo
            file_handle = open(out_path, 'rb')
            # On utilise FileResponse au lieu d'ouvrir le fichier normalement en mode lecture 
            # pour copier son contenu (car plus performant pour les gros fichiers)
            response = FileResponse(file_handle, content_type="application/octet-stream")
            response['Content-Disposition'] = f'attachment; filename={out_name}'
            # Nettoyage immédiat
            if os.path.exists(in_path): os.remove(in_path)
            if os.path.exists(out_path): os.remove(out_path)
            return response
        except Exception:
            if os.path.exists(in_path): os.remove(in_path)
            if os.path.exists(out_path): os.remove(out_path)
            return render(request, 'services.html', 
                {'stego_error':"Une erreur s'est produite. Le problème vient de votre fichier ou de votre clé"}
            )
    return render(request, 'services.html')


# --- SECTION 4 : STEGANALISE (DETECTER UN MESSAGE CACHE DANS UNE IMAGE/VIDEO)  ---
def steganalyser(request):
    """Gère l'analyse d'un fichier pour extraire un message caché."""
    if request.method == 'POST':
        file = request.FILES.get('file')
        secret_key = request.POST.get('secret_key')

        path = file.name
        with open(path, 'wb+') as f:
            for chunk in file.chunks(): f.write(chunk)

        engine = StegoEngine(secret_key)
        result = engine.decode(path)
        if 'information' in result.lower():
            context = {'anal_result': result, 'anal_status': 'info'}
        elif 'erreur' in result.lower():
            context = {'anal_result': result, 'anal_status': 'error'}
        else:
            context = {'anal_result': result, 'anal_status': 'success'}
        
        os.remove(path)
        return render(request, 'services.html', context)
    return render(request, 'services.html')


def detect_deepfake(request):
    # Logique à venir (IA)
    return render(request, 'services.html')