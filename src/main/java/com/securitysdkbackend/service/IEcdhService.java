package com.securitysdkbackend.service;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.util.Map;

/**
 * Contrat d'interface décrivant les opérations cryptographiques requises
 * pour le protocole de chiffrement de bout en bout (ECDH + AES-GCM).
 */
public interface IEcdhService {

    /**
     * Génère une paire de clés éphémères sur la courbe elliptique standard P-256 (secp256r1).
     * @return un objet KeyPair contenant la clé publique et la clé privée du serveur.
     */
    KeyPair generateKeyPair() throws Exception;

    /**
     * Extrait les octets bruts de la clé publique au format standard d'encodage ASN.1 X.509.
     * @param keyPair la paire de clés du serveur
     * @return un tableau d'octets compatible avec le décodage natif de Flutter.
     */
    byte[] getPublicKeyBytes(KeyPair keyPair);

    /**
     * Réalise l'accord de clé Diffie-Hellman (ECDH) et dérive une clé symétrique
     * hautement sécurisée AES-256 via la fonction de dérivation HKDF-SHA256.
     * @param keyPair la paire de clés éphémères contenant la clé privée du serveur
     * @param clientPublicKeyBytes la clé publique reçue du client Flutter (encodée en X.509)
     * @return l'objet SecretKey AES-256 final calculé de manière identique sur les deux nœuds.
     */
    SecretKey computeSharedAesKey(KeyPair keyPair, byte[] clientPublicKeyBytes) throws Exception;

    /**
     * Chiffre une chaîne de caractères en clair à l'aide de l'algorithme AES-256-GCM.
     * @param plainText le message JSON ou texte en clair à sécuriser
     * @param aesKey la clé secrète AES-256 récupérée de la session
     * @return une Map contenant les blocs 'cipherText', 'iv' et 'tag' encodés séparément en Base64.
     */
    Map<String, String> encrypt(String plainText, SecretKey aesKey) throws Exception;

    /**
     * Déchiffre une charge utile reçue de l'extérieur à l'aide de la clé de session AES-256-GCM.
     * @param payload la Map contenant les éléments 'cipherText', 'iv' et 'tag' encodés en Base64
     * @param aesKey la clé secrète AES-256 récupérée de Redis via le sessionId
     * @return la chaîne de caractères originale décodée en UTF-8 si le tag d'authentification est valide.
     */
    String decrypt(Map<String, String> payload, SecretKey aesKey) throws Exception;
}
