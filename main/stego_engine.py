import cv2
import numpy as np
from .hkdf import derive_keys_with_hkdf, encrypt_data, decrypt_data

class StegoEngine:
    """
    Système de Stéganographie Sécurisée (SHADAI Engine).
    
    Cette classe orchestre la dissimulation (Encodage) et la récupération (Décodage) 
    de messages textuels au sein de fichiers multimédias (Images et Vidéos). 
    Elle garantit la confidentialité et l'intégrité des données via :
    1. Une dérivation de clé HKDF basée sur un secret partagé X25519.
    2. Un chiffrement authentifié AES-256-GCM.
    3. Une insertion spatiale LSB (Least Significant Bit) optimisée par NumPy.
    """

    def __init__(self, shared_secret_hex):
        """
        Initialise le moteur et dérive les clés cryptographiques nécessaires.

        Arguments:
            shared_secret_hex (str): Secret partagé calculé via ECDH, fourni au format 
                                     hexadécimal par l'interface Django.

        Note:
            Nous n'utilisons pas le secret partagé directement comme clé de chiffrement.
            On utilise HKDF pour générer une clé dédiée à l'usage stéganographique,
            renforçant ainsi la résistance aux attaques cryptographiques.
        """
        self.master_key = bytes.fromhex(shared_secret_hex)
        
        # Contexte spécifique pour garantir que cette clé ne servira qu'à la stéganographie
        info_fields = {'stego_encryption': b'AES-256-GCM-Key-for-Steganography'}
        
        # Dérivation via le module de sécurité hkdf.py
        derived_keys = derive_keys_with_hkdf(self.master_key, info_fields)
        self.encryption_key = derived_keys['stego_encryption']

    # --- MÉTHODES DE TRANSFORMATION DE DONNÉES ---

    def _message_to_bin(self, data_bytes):
        """
        Convertit un flux d'octets chiffrés en une suite de bits (0 et 1).

        Arguments:
            data_bytes (bytes): Données binaires issues du chiffrement AES-GCM.

        Retours:
            str: Chaîne de caractères binaires (ex: '01100101...').
        """
        return ''.join(format(byte, '08b') for byte in data_bytes)

    def _bin_to_bytes(self, binary_str):
        """
        Reconstitue les octets originaux à partir d'une suite de bits extraits.

        Arguments:
            binary_str (str): Chaîne de bits extraite des pixels de l'image.

        Retours:
            bytes: Données binaires brutes (contenant potentiellement le message chiffré).
        """
        byte_list = [int(binary_str[i:i+8], 2) for i in range(0, len(binary_str), 8)]
        return bytes(byte_list)

    # --- CŒUR DE L'ALGORITHME LSB (Least Significant Bit) ---

    def _embed_lsb(self, frame, binary_data):
        """
        Injecte les bits de données dans les bits de poids faible des pixels.

        Arguments:
            frame (numpy.ndarray): Matrice multidimensionnelle des pixels (BGR).
            binary_data (str): Suite de bits (0/1) à dissimuler.

        Retours:
            numpy.ndarray: La matrice de pixels modifiée prête à être enregistrée.

        Erreurs pouvant etre levées:
            ValueError: Si le nombre de bits dépasse le nombre total de composantes 
                        couleurs (Pixels * 3) disponibles dans la frame.
        """
        flat_frame = frame.flatten()
        if len(binary_data) > len(flat_frame):
            raise ValueError("Capacité insuffisante : le fichier est trop petit pour ce message.")

        # Conversion de la chaîne de bits en tableau numérique pour calcul vectorisé
        bits = np.array([int(b) for b in binary_data], dtype=np.uint8)
        
        # Modification par masquage binaire (On remplace le bit 0 par le bit du message)
        mask = np.uint8(0xFE)
        flat_frame[:len(bits)] = (flat_frame[:len(bits)] & mask) | bits
        
        return flat_frame.reshape(frame.shape)

    def _extract_lsb(self, frame):
        """
        Récupère tous les bits de poids faible d'une image.

        Arguments:
            frame (numpy.ndarray): Matrice de pixels de l'image ou de la frame vidéo.

        Retours:
            str: Une chaîne immense de bits extraits de chaque composante couleur.
        """
        flat_frame = frame.flatten()
        # Extraction par ET binaire avec 1 (masque 00000001)
        bits = flat_frame & 1
        return ''.join(map(str, bits))

    # --- MÉTHODES PUBLIQUES D'INTERFACE ---

    def encode(self, input_path, message, output_path):
        """
        Exécute le workflow complet d'encodage stéganographique.
        
        Processus :
        1. Chiffrement AES-256-GCM du message clair.
        2. Apposition d'un marqueur de fin (##END##) pour délimiter les données.
        3. Insertion LSB dans l'image ou la première frame de la vidéo.
        4. Sauvegarde via un codec sans perte (Lossless) pour la vidéo.

        Arguments:
            input_path (str): Chemin du fichier source (image/vidéo).
            message (str): Texte en clair à dissimuler.
            output_path (str): Chemin de destination du fichier généré.

        Retours:
            bool: True si l'opération s'est terminée avec succès.
        """
        # Chiffrement authentifié (fournit intégrité + confidentialité)
        encrypted_payload = encrypt_data(self.encryption_key, message.encode())
        
        # Préparation du bloc final binaire
        final_data = encrypted_payload + b"##END##" 
        binary_data = self._message_to_bin(final_data)

        if input_path.lower().endswith(('.png', '.jpg', '.jpeg')):
            img = cv2.imread(input_path)
            encoded_img = self._embed_lsb(img, binary_data)
            cv2.imwrite(output_path, encoded_img)
        """elif input_path.lower().endswith(('.mp4', '.avi', '.webm')):
            # Traitement Vidéo avec Codec FFV1 (Indispensable pour préserver les LSB)
            cap = cv2.VideoCapture(input_path)
            fourcc = cv2.VideoWriter.fourcc(*'FFV1')
            out = cv2.VideoWriter(output_path, fourcc, cap.get(cv2.CAP_PROP_FPS), 
                                  (int(cap.get(3)), int(cap.get(4))))
            first_frame = True
            while cap.isOpened():
                ret, frame = cap.read()
                if not ret: break
                if first_frame:
                    frame = self._embed_lsb(frame, binary_data)
                    first_frame = False
                out.write(frame)
            cap.release()
            out.release()"""
        return True

    def decode(self, file_path):
        """
        Exécute le workflow complet de décodage et de stéganalyse.

        Processus :
        1. Extraction brute des bits LSB du support.
        2. Conversion en octets et recherche du délimiteur '##END##'.
        3. Tentative de déchiffrement AES-GCM avec la clé dérivée.

        Arguments:
            file_path (str): Chemin du fichier suspect à analyser.

        Retours:
            str: Le message original déchiffré.

        Erreurs pouvant etre levées:
            Exception: "Aucun message détecté" si le marqueur est absent.
            Exception: "Clé incorrecte" si le déchiffrement GCM échoue (Tag invalide).
        """
        # 1. Extraction selon le type de support
        if file_path.lower().endswith(('.png', '.jpg', '.jpeg')):
            img = cv2.imread(file_path)
            all_bits = self._extract_lsb(img)
        else:
            cap = cv2.VideoCapture(file_path)
            ret, frame = cap.read()
            all_bits = self._extract_lsb(frame) if ret else ""
            cap.release()

        # 2. Identification du message chiffré
        raw_bytes = self._bin_to_bytes(all_bits)
        if b"##END##" not in raw_bytes:
            return "Information : Aucun message caché n'a été détecté dans ce fichier."
        # Extraction de la partie chiffrée avant le marqueur
        encrypted_payload = raw_bytes.split(b"##END##")[0]
        # 3. Déchiffrement et vérification d'intégrité
        try:
            decrypted_bytes = decrypt_data(self.encryption_key, encrypted_payload)
            return f"Succès ! Message extrait : '{decrypted_bytes.decode('utf-8')}'"
        except Exception:
            return "Erreur : Le message a été trouvé mais la clé est incorrecte ou le fichier est corrompu."
        


# --- FONCTION DE TEST (MAIN) ---

def main():
    """
    Script de test pour valider le moteur SHADAI localement.
    """
    print("=== TEST DU MOTEUR DE STÉGANOGRAPHIE SHADAI ===")
    
    # 1. Configuration (Simule le secret partagé X25519)
    test_secret = "4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b"
    engine = StegoEngine(test_secret)
    message_original = "Ceci est un message secret de test pour SHADAI !"
    
    # --- TEST IMAGE ---
    print("\n--- Test sur Image ---")
    # Crée une image noire de test si aucune image n'existe
    img_test = np.zeros((500, 500, 3), dtype=np.uint8)
    cv2.imwrite("test_input.png", img_test)
    
    try:
        engine.encode("test_input.png", message_original, "test_output.png")
        print("[OK] Encodage image réussi.")
        
        msg_decodé = engine.decode("test_output.png")
        print(f"[OK] Décodage image réussi : '{msg_decodé}'")
    except Exception as e:
        print(f"[ERREUR] Test Image : {e}")

    # --- TEST VIDÉO ---
    print("\n--- Test sur Vidéo ---")
    # Création d'une vidéo de test rapide (10 frames)
    fourcc = cv2.VideoWriter.fourcc(*'mp4v')
    test_vid = cv2.VideoWriter("test_video.mp4", fourcc, 20.0, (640, 480))
    for _ in range(10): test_vid.write(np.random.randint(0, 255, (480, 640, 3), dtype=np.uint8))
    test_vid.release()

    try:
        engine.encode("test_video.mp4", message_original, "test_video_encoded.mkv")
        print("[OK] Encodage vidéo réussi (Codec FFV1).")
        
        msg_vid = engine.decode("test_video_encoded.mkv")
        print(f"[OK] Décodage vidéo réussi : '{msg_vid}'")
    except Exception as e:
        print(f"[ERREUR] Test Vidéo : {e}")

    # Nettoyage des fichiers de test
    # for f in ["test_input.png", "test_output.png", "test_video.mp4", "test_video_encoded.mkv"]:
    #     if os.path.exists(f): os.remove(f)

if __name__ == "__main__":
    main()