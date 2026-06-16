package com.securitysdkbackend.service;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@Slf4j
@Service
public class EcdhService implements IEcdhService {

    // Définition des algorithmes standards
    private static final String EC_ALGORITHM = "EC";
    private static final String ECDH_ALGORITHM = "ECDH";
    private static final String AES_GCM = "AES/GCM/NoPadding";
    private static final String P256_CURVE = "secp256r1"; // Courbe NIST P-256

    // Tailles de sécurité requises
    private static final int AES_KEY_SIZE = 32;  // 256 bits
    private static final int GCM_TAG_SIZE = 128; // bits (Authentication Tag)
    private static final int GCM_IV_SIZE = 12;   // bytes (Standard recommandé pour GCM)

    // Contexte de dérivation HKDF (doit matcher l'encodage UTF-8 côté Flutter)
    private static final byte[] HKDF_INFO = "ecdh-aes-key".getBytes(StandardCharsets.UTF_8);

    // SecureRandom partagé, thread-safe et non bloquant en production
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    @Override
    public KeyPair generateKeyPair() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(EC_ALGORITHM, "BC");
        kpg.initialize(new ECGenParameterSpec(P256_CURVE));
        KeyPair keyPair = kpg.generateKeyPair();
        log.debug("Paire de cles ephemeres ECDH generee cote serveur");
        return keyPair;
    }
    @Override
    public byte[] getPublicKeyBytes(KeyPair keyPair) {
        // Retourne le format X.509 ASN.1 standard, lisible par Flutter
        return keyPair.getPublic().getEncoded();
    }

    @Override
    public SecretKey computeSharedAesKey(KeyPair keyPair, byte[] clientPublicKeyBytes) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        log.info("Bytes recus de Flutter : longueur={}, premier byte={}",
                clientPublicKeyBytes.length,
                clientPublicKeyBytes[0]);

        // Reconstruction de la cle publique depuis les bytes bruts [0x04, x, y]
        // en utilisant les classes standard Java avec BC comme provider
        java.security.spec.ECPoint w = new java.security.spec.ECPoint(
                new java.math.BigInteger(1, java.util.Arrays.copyOfRange(clientPublicKeyBytes, 1, 33)),
                new java.math.BigInteger(1, java.util.Arrays.copyOfRange(clientPublicKeyBytes, 33, 65))
        );

        java.security.spec.ECParameterSpec ecSpec =
                ((java.security.interfaces.ECPublicKey)
                        KeyPairGenerator.getInstance("EC", "BC")
                                .generateKeyPair().getPublic())
                        .getParams();

        // Recuperer les parametres de la courbe P-256 proprement
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC", "BC");
        parameters.init(new ECGenParameterSpec(P256_CURVE));
        java.security.spec.ECParameterSpec ecParameterSpec =
                parameters.getParameterSpec(java.security.spec.ECParameterSpec.class);

        java.security.spec.ECPublicKeySpec pubKeySpec =
                new java.security.spec.ECPublicKeySpec(w, ecParameterSpec);

        KeyFactory kf = KeyFactory.getInstance(EC_ALGORITHM, "BC");
        PublicKey clientPublicKey = kf.generatePublic(pubKeySpec);

        // Accord ECDH
        KeyAgreement ka = KeyAgreement.getInstance(ECDH_ALGORITHM, "BC");
        ka.init(keyPair.getPrivate());
        ka.doPhase(clientPublicKey, true);
        byte[] sharedSecret = ka.generateSecret();
        log.info("Secret partage Java (premiers 8 bytes) : {}",
                java.util.Arrays.toString(java.util.Arrays.copyOf(sharedSecret, 8)));

        byte[] aesKeyBytes = hkdfDerive(sharedSecret, HKDF_INFO, AES_KEY_SIZE);
        log.info("Cle AES Java (premiers 8 bytes) : {}",
                java.util.Arrays.toString(java.util.Arrays.copyOf(aesKeyBytes, 8)));

        return new SecretKeySpec(aesKeyBytes, "AES");
    }

    @Override
    public Map<String, String> encrypt(String plainText, SecretKey aesKey) throws Exception {
        // 1. Génération d'un Vecteur d'Initialisation (IV) unique
        byte[] iv = new byte[GCM_IV_SIZE];
        SECURE_RANDOM.nextBytes(iv);

        // 2. Configuration et initialisation du chiffrement AES-GCM
        Cipher cipher = Cipher.getInstance(AES_GCM);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_SIZE, iv);
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, gcmSpec);

        // Java produit un bloc consolidé de la forme : [texte_chiffré | tag_authentification]
        byte[] cipherWithTag = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

        // 3. Découpage pour isoler le texte chiffré et le tag (Requis pour la compatibilité Flutter)
        int cipherTextLen = cipherWithTag.length - 16; // Le tag d'authentification GCM fait toujours 16 octets
        byte[] cipherText = new byte[cipherTextLen];
        byte[] tag = new byte[16];
        System.arraycopy(cipherWithTag, 0, cipherText, 0, cipherTextLen);
        System.arraycopy(cipherWithTag, cipherTextLen, tag, 0, 16);

        // 4. Encodage au format Base64 pour le transport au sein de la payload JSON
        Map<String, String> result = new HashMap<>();
        result.put("cipherText", Base64.getEncoder().encodeToString(cipherText));
        result.put("iv", Base64.getEncoder().encodeToString(iv));
        result.put("tag", Base64.getEncoder().encodeToString(tag));

        log.debug("Payload métier chiffrée en AES-256-GCM ✅");
        return result;
    }

    @Override
    public String decrypt(Map<String, String> payload, SecretKey aesKey) throws Exception {
        // 1. Décodage des trois composants transmis par le client mobile
        byte[] cipherText = Base64.getDecoder().decode(payload.get("cipherText"));
        byte[] iv = Base64.getDecoder().decode(payload.get("iv"));
        byte[] tag = Base64.getDecoder().decode(payload.get("tag"));

        // 2. Recollage au format attendu de manière native par l'API javax.crypto de Java
        byte[] cipherWithTag = new byte[cipherText.length + tag.length];
        System.arraycopy(cipherText, 0, cipherWithTag, 0, cipherText.length);
        System.arraycopy(tag, 0, cipherWithTag, cipherText.length, tag.length);

        // 3. Configuration et initialisation du déchiffrement
        // Si le tag a été altéré ou modifié, doFinal lèvera une AEADBadTagException
        Cipher cipher = Cipher.getInstance(AES_GCM);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_SIZE, iv);
        cipher.init(Cipher.DECRYPT_MODE, aesKey, gcmSpec);
        byte[] plainBytes = cipher.doFinal(cipherWithTag);

        log.debug("Payload métier déchiffrée avec succès (Tag d'intégrité valide) ✅");
        return new String(plainBytes, StandardCharsets.UTF_8);
    }

    /**
     * Algorithme interne de dérivation HKDF-SHA256 utilisant les composants natifs de Bouncy Castle
     */
    private byte[] hkdfDerive(byte[] secret, byte[] info, int outputLength) {
        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
        // L'argument du milieu correspond au sel (salt). Nous passons null car l'accord ECDH fournit déjà assez d'entropie
        hkdf.init(new HKDFParameters(secret, null, info));
        byte[] output = new byte[outputLength];
        hkdf.generateBytes(output, 0, outputLength);
        return output;
    }
}

