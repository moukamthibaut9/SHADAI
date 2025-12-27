import os
import hashlib
import hmac
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


HASH_ALGORITHM = hashes.SHA256() # Algorithme de hachage à utiliser pour HKDF (SHA-256 est le standard)
KEY_LENGTH = 32 # Longueur désirée pour les clés dérivées (32 bytes = 256 bits)
TAG_LENGTH = 16 # Longueur du Tag d'Authentification ajouté par GCM (16 octets par défaut)
NONCE_LENGTH = 12 # Longueur du nonce en octet (pour le control d'integrité)
HKDF_SALT = b'\x0f\x9a_\x93i\xca\x04\xd2\x88u\x8b\xc7\xf1\x9duU\x04\x1d\r\x9e\x95\x82/NT\x94aw\x0f\x11\xb5\xf0'
#HKDF_SALT = os.urandom(KEY_LENGTH)


def generate_master_key():
    """ Génère une clé maître (IKM - Initial Keying Material) aléatoire et forte. """
    return os.urandom(KEY_LENGTH)


def derive_keys_with_hkdf(master_key: bytes, info_fields):
    """
    Dérive des clés indépendantes à partir de la clé maître en utilisant HKDF.
    Args:
        master_key: La clé maître d'entrée (IKM).
        info_fields: Un dictionnaire où chaque clé est le nom de l'usage (ex: 'encryption') 
                     et chaque valeur est la chaîne d'information (Context) unique requise par HKDF.
    Retourne un dictionnaire contenant les clés dérivées.
    """
    derived_keys = {}
    # Dérivation des clés avec HKDF (SHA-256)
    for usage, info in info_fields.items():
        try:
            # Création de l'objet KDF avec un 'salt' pour ajouter de l'entropie 
            hkdf = HKDF(
                algorithm=HASH_ALGORITHM,
                length=KEY_LENGTH,
                salt=HKDF_SALT,
                info=info,  # La chaîne d'information UNIQUE est CRUCIALE pour l'indépendance des clés.
            )
            # HKDF-Expand
            derived_key = hkdf.derive(master_key)
            derived_keys[usage] = derived_key
            #print(f"   -> Clé '{usage}' ({KEY_LENGTH} bytes) dérivée avec INFO='{info.decode()}'")
        except Exception as e:
            print(f"Erreur lors de la dérivation de la clé {usage}: {e}")
    return derived_keys


def encrypt_data(encryption_key: bytes, data: str):
    """ Chiffrement des données en utilisant AES-256-GCM pour une securité optimale) """
    aesgcm = AESGCM(encryption_key)
    nonce = os.urandom(NONCE_LENGTH)
    encrypt_data_with_tag = aesgcm.encrypt(nonce, data, b'')
    return nonce + encrypt_data_with_tag


def decrypt_data(encryption_key: bytes, encrypt_data: str):
    """Déchiffrement des données chiffrés avec la clé AES-256-GCM."""
    aesgcm = AESGCM(encryption_key)
    nonce = encrypt_data[:NONCE_LENGTH]
    encrypt_data_with_tag = encrypt_data[NONCE_LENGTH:]
    return aesgcm.decrypt(nonce, encrypt_data_with_tag, b'')


def calculate_integrity_hmac(integrity_key: bytes, data: str):
    """ Calcule l'HMAC pour garantir l'intégrité (authentification du message)  """
    h = hmac.new(integrity_key, data, hashlib.sha256)
    hmac_tag = h.hexdigest()
    return hmac_tag


def generate_session_id(session_key: bytes):
    """
    Génèration d'un identifiant de session sécurisé basé sur la clé.
    (Utilisation d'un hachage pour créer l'ID unique et non prévisible).
    """
    # La clé de session sert à générer un token/ID basé sur le hash de la clé + un nonce
    session_data = session_key + os.urandom(NONCE_LENGTH) # Ajout d'un nonce de 8 bytes/octects pour plus d'unicité
    session_id = hashlib.sha256(session_data).hexdigest()
    return session_id

# --- Fonction Principale (main) ---

def main():
    """ Implémentation complète de la dérivation et de l'utilisation des clés. """
    # 1. Génération de la Clé Maître
    master_key = generate_master_key()
    # 2. Définition des champs INFO (Contextes Uniques)
    info_fields = {
        'encryption': b'AES-256-Key-for-Data-Encryption',
        'integrity': b'HMAC-SHA256-Key-for-Message-Authentication',
        'session_id': b'Unique-Key-for-Session-Token-Generation'
    }
    # 3. Dérivation des Clés
    derived_keys = derive_keys_with_hkdf(master_key, info_fields)
   
    if len(derived_keys) != len(info_fields):
        print("\nERREUR: Toutes les clés n'ont pas été dérivées. Arrêt.")
        return
        
    encryption_key = derived_keys['encryption']
    integrity_key = derived_keys['integrity']
    session_key = derived_keys['session_id']
    
    print("\n--- Vérification de l'indépendance des clés dérivées ---")
    if encryption_key == integrity_key or encryption_key == session_key or integrity_key == session_key:
         print("Alerte : Les clés dérivées sont identiques. Arrêt.")
         return
    else:
        print("Bien: Les 3 clés dérivées sont distinctes et cryptographiquement indépendantes.")
        print(f"\t-> Clé de chiffrement: {encryption_key.hex()}")
        print(f"\t-> Clé d'intégrité (pour le calcul du HMAC): {integrity_key.hex()}")
        print(f"\t-> Clé de session utilisateur: {session_key.hex()}")
    # 4. Utilisation des Clés Dérivées
    print("\n--- Utilisation des Clés ---")
    # Données d'exemple
    file = "medical_file1.txt"
    with open(file, 'rb') as f:
        file_content = f.read()  
    # Usage 1 : Chiffrement
    encrypted_data = encrypt_data(encryption_key, file_content)    
    # Usage 2 : Intégrité
    hmac_tag = calculate_integrity_hmac(integrity_key, file_content)   
    # Usage 3 : Session ID
    session_id = generate_session_id(session_key)
    print(f"""
    Contenu du fichier:
{file_content.decode()}
    1. HMAC associé au contenu: {hmac_tag}
    2. Contenu chiffré avec la clé {encryption_key.hex()} (au format hexadécimal):
{encrypted_data.hex()}
    3. Contenu déchiffré avec la clé {encryption_key.hex()}:
{decrypt_data(encryption_key, encrypted_data).decode()}      
    """)

if __name__ == "__main__":
    # # Importation ici pour la fonction main() pour éviter les conflits dans le code utilisateur
    main()