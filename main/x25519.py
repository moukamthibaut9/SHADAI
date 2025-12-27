from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption


def generate_x25519_key():
    """ Génère la paire de clés X25519 pour un site (clé privée et clé publique). """
    # La méthode X25519PrivateKey.generate() génère une clé privée aléatoire
    private_key = x25519.X25519PrivateKey.generate()
    return private_key

def get_public_key_bytes(private_key: x25519.X25519PrivateKey):
    """
    Extrait la clé publique d'une clé privée et la sérialise en octets pour l'échange.
    Args:
        private_key: L'objet clé privée X25519.
    Retourne la clé publique sérialisée sur 32 octets.
    """
    # La clé publique est nécessaire pour l'échange et n'est pas secrète.
    public_key = private_key.public_key()
    
    # Sérialisation : C'est le format qui sera envoyé à l'autre partie.
    return public_key.public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw
    )

def derive_shared_secret(local_private_key: x25519.X25519PrivateKey, remote_public_key_bytes: bytes):
    """
    Calcule le secret partagé en utilisant la clé privée locale et la clé publique distante.
    Args:
        local_private_key: La clé privée locale du site.
        remote_public_key_bytes: La clé publique sérialisée de l'autre site.
        site_name: Le nom du site pour l'affichage.
    Retourne le secret partagé de 32 octets.
    """ 
    # 1. Désérialisation de la clé publique distante
    remote_public_key = x25519.X25519PublicKey.from_public_bytes(remote_public_key_bytes)
    # 2. Calcul du secret partagé (ECDH)
    shared_secret = local_private_key.exchange(remote_public_key)    
    return shared_secret

# --- Fonction Principale (main) ---

def main():
    """ Simule l'échange de clés X25519 entre deux sites (Hôpital A et B)."""
    # 1. Génération des paires de clés
    print("--- Échange de Clés X25519 (ECDH) entre deux sites ---")
    private_key_A = generate_x25519_key()
    private_key_B = generate_x25519_key()
    # 2. Échange des clés publiques
    print("\n--- Échange des Clés Publiques (Non Secrètes) ---")  
    public_key_bytes_A = get_public_key_bytes(private_key_A)
    print(f"Hôpital A : Publique A ({public_key_bytes_A.hex()[:10]}...) envoyée à B.")
    public_key_bytes_B = get_public_key_bytes(private_key_B)
    print(f"Hôpital B : Publique B ({public_key_bytes_B.hex()[:10]}...) envoyée à A.")
    # 3. Calcul du secret partagé par chaque site
    print("\n--- Calcul des Secrets Partagés (ECDH) ---")
    shared_secret_A = derive_shared_secret(
        private_key_A, 
        public_key_bytes_B, 
    )
    shared_secret_B = derive_shared_secret(
        private_key_B, 
        public_key_bytes_A, 
    )
    # 4. Vérification
    print("\n--- Vérification du Secret Partagé ---")
    if shared_secret_A == shared_secret_B:
        print("SUCCESS! Les secrets partagés sont identiques.")
        print(f"Secret commun : {shared_secret_A.hex()}")
        print("\nCe secret peut maintenant être utilisé comme clé de chiffrement symétrique (Ex: AES).")
    else:
        print("ECHEC! Les secrets ne correspondent pas. Erreur dans l'échange de clés.")


if __name__ == "__main__":
    main()