<?php

class KYC {
    public function generateKey() {
        $privateKey = openssl_pkey_new([
            "private_key_bits" => 2048,
            "private_key_type" => OPENSSL_KEYTYPE_RSA,
        ]);

        openssl_pkey_export($privateKey, $privateKeyPem);
        $keyDetails = openssl_pkey_get_details($privateKey);
        $publicKeyPem = $keyDetails['key'];

        return [
            'publicKey' => $publicKeyPem,
            'privateKey' => $privateKeyPem
        ];
    }

    public function generateSymmetricKey() {
        return random_bytes(32); // Generate 256-bit key
    }

    public function aesEncrypt($data, $symmetricKey) {
        $iv = random_bytes(12); // Generate 96-bit IV
        $ciphertext = openssl_encrypt(
            $data,
            'aes-256-gcm',
            $symmetricKey,
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );

        return $iv . $ciphertext . $tag;
    }

    public function aesDecrypt($encryptedData, $key) {
            $ivLength = 12;
            $tagLength = 16;
        
            if (strlen($encryptedData) < ($ivLength + $tagLength)) {
                throw new Exception("Invalid encrypted data length. Data received: " . bin2hex($encryptedData));
            }
        
            $iv = substr($encryptedData, 0, $ivLength);
            $ciphertext = substr($encryptedData, $ivLength, -$tagLength);
            $tag = substr($encryptedData, -$tagLength);
        
            if (strlen($iv) !== $ivLength || strlen($tag) !== $tagLength) {
                throw new Exception("Invalid IV or tag length. IV: " . bin2hex($iv) . ", Tag: " . bin2hex($tag));
            }
        
            $decrypted = openssl_decrypt(
                $ciphertext,
                'aes-256-gcm',
                $key,
                OPENSSL_RAW_DATA,
                $iv,
                $tag
            );
        
            if ($decrypted === false) {
                throw new Exception("Decryption failed: " . openssl_error_string());
            }
        
            return $decrypted;
    }

    public function encryptMessage($message, $pubPem) {
        $aesKey = $this->generateSymmetricKey();
        
        // Encrypt AES key using RSA public key
        openssl_public_encrypt($aesKey, $wrappedAesKey, $pubPem, OPENSSL_PKCS1_OAEP_PADDING);

        // Encrypt the message using AES key
        $encryptedMessage = $this->aesEncrypt($message, $aesKey);

        // Concatenate the wrapped AES key and encrypted message
        $payload = $wrappedAesKey . $encryptedMessage;

        // Format as base64 with tags
        return "-----BEGIN ENCRYPTED MESSAGE-----\r\n" .
            chunk_split(base64_encode($payload), 64) .
            "-----END ENCRYPTED MESSAGE-----";
    }

    public function decryptMessage($message, $privateKeyPem) {
        $beginTag = "-----BEGIN ENCRYPTED MESSAGE-----";
        $endTag = "-----END ENCRYPTED MESSAGE-----";

        $messageContent = str_replace(
            [$beginTag, $endTag, "\r", "\n"],
            '',
            $message
        );

        $binaryDerString = base64_decode($messageContent);
        $wrappedKeyLength = 256; // RSA 2048-bit key size
        $wrappedKey = substr($binaryDerString, 0, $wrappedKeyLength);
        $encryptedMessage = substr($binaryDerString, $wrappedKeyLength);

        // Decrypt the wrapped AES key using private key
        openssl_private_decrypt($wrappedKey, $aesKey, $privateKeyPem, OPENSSL_PKCS1_OAEP_PADDING);

        // Decrypt the message using the AES key
        return $this->aesDecrypt($encryptedMessage, $aesKey);
    }

    public function generateUrl($agentName, $agentNik, $accessToken) {
        $keyPair = $this->generateKey();
        $publicKey = $keyPair['publicKey'];
        $privateKey = $keyPair['privateKey'];

        $apiUrl = 'https://api-satusehat-stg.dto.kemkes.go.id/kyc/v1/generate-url';

        $pubPem = <<<PEM
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwqoicEXIYWYV3PvLIdvB
qFkHn2IMhPGKTiB2XA56enpPb0UbI9oHoetRF41vfwMqfFsy5Yd5LABxMGyHJBbP
+3fk2/PIfv+7+9/dKK7h1CaRTeT4lzJBiUM81hkCFlZjVFyHUFtaNfvQeO2OYb7U
kK5JrdrB4sgf50gHikeDsyFUZD1o5JspdlfqDjANYAhfz3aam7kCjfYvjgneqkV8
pZDVqJpQA3MHAWBjGEJ+R8y03hs0aafWRfFG9AcyaA5Ct5waUOKHWWV9sv5DQXmb
EAoqcx0ZPzmHJDQYlihPW4FIvb93fMik+eW8eZF3A920DzuuFucpblWU9J9o5w+2
oQIDAQAB
-----END PUBLIC KEY-----
PEM;

        $data = [
            'agent_name' => $agentName,
            'agent_nik' => $agentNik,
            'public_key' => $publicKey
        ];

        $jsonData = json_encode($data);
        $encryptedPayload = $this->encryptMessage($jsonData, $pubPem);

        $headers = [
            'Content-Type: text/plain',
            "Authorization: Bearer $accessToken"
        ];

        $ch = curl_init($apiUrl);
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $encryptedPayload);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($httpCode != 200) {
            echo "HTTP error: $httpCode\n";
            return null;
        }

        return $this->decryptMessage($response, $privateKey);
    }
}

$kyc = new KYC();
$result = $kyc->generateUrl('Doyok Putih', '################', 'lJo5SgxpQyNFWit5WIG6UWvtxGmK');
echo "Result of generateUrl:\n";
print_r($result);

