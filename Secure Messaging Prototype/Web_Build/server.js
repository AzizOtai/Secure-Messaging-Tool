(async () => {
    const messagesDiv = document.getElementById('messages');
    const input = document.getElementById('message-input');
    const sendButton = document.getElementById('send-button');

    console.log("Initializing Secure Messaging Application...");

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

    const exportedRSAKey = await window.crypto.subtle.exportKey("spki", serverRSAKeys.publicKey);
    console.log("Server RSA Public Key (Base64):", arrayBufferToBase64(exportedRSAKey));

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

    const exportedDHPublicKey = await window.crypto.subtle.exportKey("raw", dhParams.publicKey);
    console.log("Client ECDH Public Key (Hex):", arrayBufferToHex(exportedDHPublicKey));

    console.log("Simulating public key exchange...");
    const clientPublicKey = dhParams.publicKey;
    const serverPublicKey = dhParams.publicKey; 
    console.log("Public key exchange completed.");

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

    function arrayBufferToHex(buffer) {
        const byteArray = new Uint8Array(buffer);
        const hexCodes = [...byteArray].map(value => {
            return value.toString(16).padStart(2, '0');
        });
        return hexCodes.join('');
    }

    function arrayBufferToBase64(buffer) {
        let binary = '';
        const bytes = new Uint8Array(buffer);
        bytes.forEach((b) => binary += String.fromCharCode(b));
        return window.btoa(binary);
    }

    sendButton.addEventListener('click', async () => {
        const message = input.value.trim();
        if (message === "") {
            console.log("Empty message. Nothing to send.");
            return;
        }
        console.log(`User input message: "${message}"`);
        input.value = '';

        try {
            console.log("Encrypting the message with RSA-OAEP...");
            const encryptedMessage = await window.crypto.subtle.encrypt(
                {
                    name: "RSA-OAEP",
                },
                serverRSAKeys.publicKey,
                new TextEncoder().encode(message)
            );
            console.log("Message encrypted.");

            const encryptedHex = arrayBufferToHex(encryptedMessage);
            console.log("Encrypted Message (Hex):", encryptedHex);

            const encryptedElement = document.createElement('div');
            encryptedElement.classList.add('message', 'encrypted');
            encryptedElement.textContent = `Encrypted: ${encryptedHex}`;
            messagesDiv.appendChild(encryptedElement);
            console.log("Encrypted message displayed in UI.");

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

            const decryptedElement = document.createElement('div');
            decryptedElement.classList.add('message', 'decrypted');
            decryptedElement.textContent = `Decrypted: ${decryptedMessage}`;
            messagesDiv.appendChild(decryptedElement);
            console.log("Decrypted message displayed in UI.");

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
