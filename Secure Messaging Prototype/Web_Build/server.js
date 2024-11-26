// web/app.js
(async () => {
    const messagesDiv = document.getElementById('messages');
    const input = document.getElementById('message-input');
    const sendButton = document.getElementById('send-button');

    console.log("Initializing Secure Messaging Application...");

    // Generate RSA key pairs for the server
    console.log("Generating RSA key pair for the server...");
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
    console.log("RSA key pair generated.");

    // Export and log the RSA public key (for demonstration purposes)
    const exportedRSAKey = await window.crypto.subtle.exportKey("spki", serverRSAKeys.publicKey);
    console.log("Server RSA Public Key (Base64):", arrayBufferToBase64(exportedRSAKey));

    // Diffie-Hellman parameters (Elliptic Curve Diffie-Hellman)
    console.log("Generating ECDH key pair...");
    const dhParams = await window.crypto.subtle.generateKey(
        {
            name: "ECDH",
            namedCurve: "P-256",
        },
        true,
        ["deriveKey", "deriveBits"]
    );
    console.log("ECDH key pair generated.");

    // Export and log the ECDH public key (for demonstration purposes)
    const exportedDHPublicKey = await window.crypto.subtle.exportKey("raw", dhParams.publicKey);
    console.log("Client ECDH Public Key (Hex):", arrayBufferToHex(exportedDHPublicKey));

    // Exchange public keys (simulated here)
    console.log("Simulating public key exchange...");
    const clientPublicKey = dhParams.publicKey;
    const serverPublicKey = dhParams.publicKey; // In a real scenario, this would be different
    console.log("Public key exchange completed.");

    // Compute shared secret
    console.log("Deriving shared secret using ECDH...");
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
    console.log("Shared secret derived.");

    // Utility function to convert ArrayBuffer to Hex String
    function arrayBufferToHex(buffer) {
        const byteArray = new Uint8Array(buffer);
        const hexCodes = [...byteArray].map(value => {
            return value.toString(16).padStart(2, '0');
        });
        return hexCodes.join('');
    }

    // Utility function to convert ArrayBuffer to Base64 String
    function arrayBufferToBase64(buffer) {
        let binary = '';
        const bytes = new Uint8Array(buffer);
        bytes.forEach((b) => binary += String.fromCharCode(b));
        return window.btoa(binary);
    }

    // Event listener for sending messages
    sendButton.addEventListener('click', async () => {
        const message = input.value.trim();
        if (message === "") {
            console.log("Empty message. Nothing to send.");
            return; // Do not send empty messages
        }
        console.log(`User input message: "${message}"`);
        input.value = '';

        try {
            // Encrypt the message using RSA public key
            console.log("Encrypting the message with RSA-OAEP...");
            const encryptedMessage = await window.crypto.subtle.encrypt(
                {
                    name: "RSA-OAEP",
                },
                serverRSAKeys.publicKey,
                new TextEncoder().encode(message)
            );
            console.log("Message encrypted.");

            // Convert encrypted ArrayBuffer to Hex String for display
            const encryptedHex = arrayBufferToHex(encryptedMessage);
            console.log("Encrypted Message (Hex):", encryptedHex);

            // Display the encrypted message
            const encryptedElement = document.createElement('div');
            encryptedElement.classList.add('message', 'encrypted');
            encryptedElement.textContent = `Encrypted: ${encryptedHex}`;
            messagesDiv.appendChild(encryptedElement);
            console.log("Encrypted message displayed in UI.");

            // Decrypt the message using RSA private key
            console.log("Decrypting the message with RSA-OAEP...");
            const decryptedMessageBuffer = await window.crypto.subtle.decrypt(
                {
                    name: "RSA-OAEP",
                },
                serverRSAKeys.privateKey,
                encryptedMessage
            );
            console.log("Message decrypted.");

            const decryptedMessage = new TextDecoder().decode(decryptedMessageBuffer);
            console.log("Decrypted Message:", decryptedMessage);

            // Display the decrypted message
            const decryptedElement = document.createElement('div');
            decryptedElement.classList.add('message', 'decrypted');
            decryptedElement.textContent = `Decrypted: ${decryptedMessage}`;
            messagesDiv.appendChild(decryptedElement);
            console.log("Decrypted message displayed in UI.");

            // Scroll to the bottom to show the latest messages
            messagesDiv.scrollTop = messagesDiv.scrollHeight;
            console.log("Scrolled to the latest message.");
        } catch (error) {
            console.error("Encryption/Decryption Error:", error);
            const errorElement = document.createElement('div');
            errorElement.classList.add('message', 'decrypted');
            errorElement.textContent = `Error: ${error.message}`;
            messagesDiv.appendChild(errorElement);
            console.log("Error message displayed in UI.");
        }
    });
})();
