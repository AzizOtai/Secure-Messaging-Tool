(async () => {
    const messagesDiv = document.getElementById('messages');
    const input = document.getElementById('message-input');
    const sendButton = document.getElementById('send-button');

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

    const dhParams = await window.crypto.subtle.generateKey(
        {
            name: "ECDH",
            namedCurve: "P-256",
        },
        true,
        ["deriveKey", "deriveBits"]
    );

    const clientPublicKey = dhParams.publicKey;
    const serverPublicKey = dhParams.publicKey; 


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


    function arrayBufferToHex(buffer) {
        const byteArray = new Uint8Array(buffer);
        const hexCodes = [...byteArray].map(value => {
            return value.toString(16).padStart(2, '0');
        });
        return hexCodes.join('');
    }

    sendButton.addEventListener('click', async () => {
        const message = input.value.trim();
        if (message === "") return; 
        input.value = '';

        try {

            const encryptedMessage = await window.crypto.subtle.encrypt(
                {
                    name: "RSA-OAEP",
                },
                serverRSAKeys.publicKey,
                new TextEncoder().encode(message)
            );

            const encryptedHex = arrayBufferToHex(encryptedMessage);

            const encryptedElement = document.createElement('div');
            encryptedElement.classList.add('message', 'encrypted');
            encryptedElement.textContent = `Encrypted: ${encryptedHex}`;
            messagesDiv.appendChild(encryptedElement);

            const decryptedMessageBuffer = await window.crypto.subtle.decrypt(
                {
                    name: "RSA-OAEP",
                },
                serverRSAKeys.privateKey,
                encryptedMessage
            );

            const decryptedMessage = new TextDecoder().decode(decryptedMessageBuffer);

            const decryptedElement = document.createElement('div');
            decryptedElement.classList.add('message', 'decrypted');
            decryptedElement.textContent = `Decrypted: ${decryptedMessage}`;
            messagesDiv.appendChild(decryptedElement);

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
