# SHADAI (Shadow of Data with AI)


## Presentation
Il s'agit ici d'une application web alimentée par l'IA qui offre trois principaux services:
* Un service de stégonographie permettant à un utilisateur émettteur de cacher un message dans une image avant de l'envoyer à un autre utilisateur récepteur
* Un service de stéganalyse permettant à un utilisateur récepteur de détecter si un message est caché dans une image qu'il a reçu, ainsi que de prendre connaissance de ce message  s'il dispose de la bonne clé
* Un service de detection de deep-fake pour les fausses images générées par des IA (Pas encore opérationnel)

## Principe
* L'émetteur se rend sur l'application et génère une paire de clés. Il devra garder ces clés en lieu sûr, surtout sa clé privée. Il va ensuite envoyer sa clé publique au récepteur
* Le récepteur va faire pareil vis à vis de l'émetteur
* Toujours depuis l'application, chaque partie va ensuite calculer le secret partagé qu'elles utiliseront toutes deux pour cacher des informations et les recupérer de façon sécurisée dans des images (Une section est dediée pour ça dans l'application)
* Une fois ce secret partagé obtenu, chaque partie peut alors s'en servir pour la stéganographie ou la stéganalyse

## Installation
* Ouvrez l'invite de commandes et naviguer jusqu'à la racine du dossier projet
* Il faut au préalable avoir python 3.12 minimun installé sur sa machine. Si c'est le cas, créer un environnement virtuel pour le projet et activer l'environnement:  
    python -m venv .venv  
    .\.venv\Scripts\activate.bat (Sur Windows) | ./.venv/bin/activate (Sur Linux)
* Installer les paquets necessaires:  
    pip install -r requirements.txt
* Créer un fichier '.env' à la racine du projet avec le contenu suivant:  
    SECRET_KEY = django-insecure-5aaq63pm)=3vx0brt)l1064hv-y#x6#&0x%ahmv5t&j7)@r!f49n  
    DEBUG = True  
    ALLOWED_HOSTS = 127.0.0.1, localhost  
    EMAIL_HOST_USER = noreply@domain.com  
    EMAIL_HOST_PASSWORD = password  
    DEFAULT_FROM_EMAIL = noreply@domain.com
* Executer les migrations et collecter les fichiers statiques du projet:  
    python manage.py makemigrations & python manage.py migrate & python manage.py collecstatic
* Demarrer le serveur django:  
    python manage.py runserver
* Dans un navigateur, consulter le site à l'adresse 127.0.0.1:8000/

## Autres Precisions
* Dans le dossier projet, le sous dossier 'main' contient le sous dossier 'templates' qui regroupe les principaux fichiers HTML de l'application.
* Parcourrir aussi tous les fichiers python de ce sous dossier pour prendre connaissance du code (des commentaires donnent plus d'explications)