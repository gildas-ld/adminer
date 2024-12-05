<?php

/**
 * Chiffre une chaîne de caractères en utilisant AES.
 *
 * @param  string $plaintext Le texte en clair à chiffrer.
 * @param  string $key       La clé utilisée pour le
 *                           chiffrement.
 * @return string Le texte chiffré en base64.
 */

function encrypt_string($plaintext, $key)
{
    // Utilise SHA-512 et tronque la sortie à 32 octets (256 bits).
    $key = substr(hash('sha512', $key, true), 0, 32);

    // Génère un IV aléatoire de longueur appropriée.
    $iv = random_bytes(openssl_cipher_iv_length('aes-256-gcm'));
    $tag = ''; // Le tag d'authentification sera généré.

    // Chiffre les données en AES-256-GCM.
    $ciphertext = openssl_encrypt($plaintext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);

    // Encode en base64 la concaténation de IV, tag et texte chiffré.
    return base64_encode($iv . $tag . $ciphertext);
}

/**
 * Déchiffre une chaîne de caractères en utilisant AES avec une clé dérivée de SHA-512.
 *
 * @param  string $ciphertext_base64 Le texte chiffré en base64.
 * @param  string $key               La clé utilisée pour le
 *                                   déchiffrement.
 * @return string|false Le texte en clair déchiffré ou false si échec.
 */
function decrypt_string($ciphertext_base64, $key)
{
    // Utilise SHA-512 et tronque la sortie à 32 octets (256 bits).
    $key = substr(hash('sha512', $key, true), 0, 32);

    // Décode les données base64.
    $data = base64_decode($ciphertext_base64);

    // Extrait l'IV, le tag et le texte chiffré.
    $iv_length = openssl_cipher_iv_length('aes-256-gcm');
    $iv = substr($data, 0, $iv_length);
    $tag = substr($data, $iv_length, 16); // Tag d'authentification (16 octets pour GCM).
    $ciphertext = substr($data, $iv_length + 16);

    // Déchiffre les données.
    return openssl_decrypt($ciphertext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
}
