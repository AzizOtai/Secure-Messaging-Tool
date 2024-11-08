// app.js
(async () => {
    const messagesDiv = document.getElementById('messages');
    const input = document.getElementById('message-input');
    const sendButton = document.getElementById('send-button');

    // Generate RSA key pairs for the server
    const serverRSAKeys = await window.crypto.subtle.generateKey(
        {
            name: "RSA-OAEP",
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: "SHA-256",
        },
        true,
        ["encrypt", "decrypt"]
    );

    // Diffie-Hellman parameters
    const dhParams = await window.crypto.subtle.generateKey(
        {
            name: "ECDH",
            namedCurve: "P-256",
        },
        true,
        ["deriveKey", "deriveBits"]
    );

    // Exchange public keys (simulated here)
    const clientPublicKey = dhParams.publicKey;
    const serverPublicKey = dhParams.publicKey; // In a real scenario, this would be different

    // Compute shared secret
    const sharedSecret = await window.crypto.subtle.deriveKey(
        {
            name: "ECDH",
            public: serverPublicKey,
        },
        dhParams.privateKey,
        {
            name: "AES-GCM",
            length: 256,
        },
        false,
        ["encrypt", "decrypt"]
    );

    // Utility function to convert ArrayBuffer to Hex String
    function arrayBufferToHex(buffer) {
        const byteArray = new Uint8Array(buffer);
        const hexCodes = [...byteArray].map(value => {
            return value.toString(16).padStart(2, '0');
        });
        return hexCodes.join('');
    }

    // Event listener for sending messages
    sendButton.addEventListener('click', async () => {
        const message = input.value.trim();
        if (message === "") return; // Do not send empty messages
        input.value = '';

        try {
            // Encrypt the message using RSA public key
            const encryptedMessage = await window.crypto.subtle.encrypt(
                {
                    name: "RSA-OAEP",
                },
                serverRSAKeys.publicKey,
                new TextEncoder().encode(message)
            );

            // Convert encrypted ArrayBuffer to Hex String for display
            const encryptedHex = arrayBufferToHex(encryptedMessage);

            // Display the encrypted message
            const encryptedElement = document.createElement('div');
            encryptedElement.classList.add('message', 'encrypted');
            encryptedElement.textContent = `Encrypted: ${encryptedHex}`;
            messagesDiv.appendChild(encryptedElement);

            // Decrypt the message using RSA private key
            const decryptedMessageBuffer = await window.crypto.subtle.decrypt(
                {
                    name: "RSA-OAEP",
                },
                serverRSAKeys.privateKey,
                encryptedMessage
            );

            const decryptedMessage = new TextDecoder().decode(decryptedMessageBuffer);

            // Display the decrypted message
            const decryptedElement = document.createElement('div');
            decryptedElement.classList.add('message', 'decrypted');
            decryptedElement.textContent = `Decrypted: ${decryptedMessage}`;
            messagesDiv.appendChild(decryptedElement);

            // Scroll to the bottom to show the latest messages
            messagesDiv.scrollTop = messagesDiv.scrollHeight;
        } catch (error) {
            console.error("Encryption/Decryption Error:", error);
            const errorElement = document.createElement('div');
            errorElement.classList.add('message', 'decrypted');
            errorElement.textContent = `Error: ${error.message}`;
            messagesDiv.appendChild(errorElement);
        }
    });
})();
