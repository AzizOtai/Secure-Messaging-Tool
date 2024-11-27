# Secure Messaging App Prototype with RSA & Diffie-Hellman

Secure Messaging App Prototype with RSA & Diffie-Hellman. Includes Web (HTML/CSS/JS) and Java Implementations.

## 📚 Table of Contents

- [Introduction](#introduction)
- [Features](#features)
- [Technologies Used](#technologies-used)
- [Repository Structure](#repository-structure)
- [Getting Started](#getting-started)
  - [Web-Based Implementation](#web-based-implementation)
    - [Prerequisites](#prerequisites)
    - [Installation](#installation)
    - [Usage](#usage)
  - [Java Implementation](#java-implementation)
    - [Prerequisites](#prerequisites-1)
    - [Installation](#installation-1)
    - [Usage](#usage-1)
- [Project Overview](#project-overview)
  - [Web-Based Implementation](#web-based-implementation-1)
  - [Java Implementation](#java-implementation-1)
- [Evaluation Criteria](#evaluation-criteria)
- [Future Enhancements](#future-enhancements)
- [License](#license)
- [Contact](#contact)

## 🧐 Introduction

Welcome to the **Secure Messaging Application** repository! This project demonstrates the implementation of **RSA** and **Diffie-Hellman** algorithms within a secure messaging system. The application allows two parties to exchange encrypted messages securely over an insecure channel.

This repository includes two distinct implementations:
1. **Web-Based Implementation**: Built using HTML, CSS, and JavaScript, leveraging the Web Crypto API.
2. **Java Implementation**: A console-based application demonstrating the same cryptographic principles using Java's standard libraries.

## ✨ Features

- **Diffie-Hellman Key Exchange**: Establishes a shared secret key between client and server without prior secret sharing.
- **RSA Encryption/Decryption**: Secures messages using RSA public and private keys.
- **Client-Server Simulation**: Demonstrates key exchanges and message encryption/decryption.
- **Encrypted and Decrypted Message Display**: Visualizes both encrypted ciphertext and decrypted plaintext.
- **Modular Design**: Separate classes for Diffie-Hellman and RSA operations enhance code maintainability.

## 🛠️ Technologies Used

- **Web-Based Implementation**:
  - HTML5
  - CSS3
  - JavaScript (ES6)
  - Web Crypto API

- **Java Implementation**:
  - Java SE (Standard Edition)
  - Java Cryptography Architecture (JCA)

## 📂 Repository Structure

secure-messaging-app/ ├── README.md ├── web/ │ ├── index.html │ ├── styles.css │ └── app.js └── java/ ├── DHKeyExchange.java ├── RSAEncryption.java └── Main.java

markdown
Copy code


## 🚀 Getting Started

Follow the instructions below to set up and run both the web-based and Java implementations of the Secure Messaging Application.

### 🌐 Web-Based Implementation

#### 🔍 Prerequisites

- A modern web browser (e.g., Chrome, Firefox, Edge) with JavaScript enabled.
- (Optional) A local web server for serving the files (e.g., [Live Server](https://marketplace.visualstudio.com/items?itemName=ritwickdey.LiveServer) extension for VS Code).

#### 📥 Installation

1. **Clone the Repository**

       git clone https://github.com/your-username/secure-messaging-app.git
   
2. Navigate to the Web Directory

    cd secure-messaging-app/web


▶️ Usage
1. Open the Application

Option 1: Directly open the index.html file in your web browser.

Locate the index.html file in the web directory.
Double-click to open it in your default browser.
Option 2: Use a local web server for better compatibility.

If you have the Live Server extension in VS Code:
Open the web folder in VS Code.
Right-click on index.html and select "Open with Live Server".
Interact with the Application

Enter a message in the input field.
Click the "Send" button.
Observe both the encrypted and decrypted messages displayed in the conversation area.
Open the browser's developer console to view detailed logs of the cryptographic processes.
☕ Java Implementation
🔍 Prerequisites
Java Development Kit (JDK) 8 or higher: Ensure that Java is installed on your system.

Download JDK:

  Oracle JDK: Download from Oracle
  OpenJDK: Download from OpenJDK
Verify Installation:

    java -version
    
You should see output indicating the installed Java version.

IDE or Text Editor: (Optional) Use an IDE like IntelliJ IDEA, Eclipse, or VS Code for easier development.

📥 Installation
Clone the Repository


    git clone https://github.com/your-username/secure-messaging-app.git

Navigate to the Java Directory

    cd secure-messaging-app/java
    
▶️ Usage
Compile the Java Program

    javac DHKeyExchange.java RSAEncryption.java Main.java
    
This command compiles the .java files and generates corresponding .class files.

Run the Java Program
    
    java Main
    
Observe the Output

The program will display the encrypted and decrypted messages in the console, demonstrating the RSA and Diffie-Hellman operations.

Example Output:

    DH Key Pair Generated.
    DH Key Pair Generated.
    Shared Secret Generated.
    Shared Secret (Hex): a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
    DH Key Pair Generated.
    DH Key Pair Generated.
    Shared Secret Generated.
    Shared Secret (Hex): a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
    Shared secrets match. Key Exchange Successful.
    
    RSA Key Pair Generated.
    RSA Key Pair Generated.
    
    Original Message: Hello, Secure World!
    Message Encrypted.
    Encrypted Message: (Base64 Encoded Ciphertext)
    Message Decrypted.
    Decrypted Message: Hello, Secure World!
    Note: The actual encrypted message will be a long Base64-encoded string representing the ciphertext.

# 🔍 Project Overview

🌐 Web-Based Implementation

The web-based application leverages the Web Crypto API to perform cryptographic operations directly in the browser. It simulates a client-server model where both parties generate RSA and ECDH keys, establish a shared secret, and encrypt/decrypt messages securely.

Key Components:

- HTML/CSS:
  Provides the user interface for message input and display.
- JavaScript (app.js):
  - Generates RSA key pairs for the server.
  - Performs ECDH key exchange to derive a shared secret.
  - Encrypts messages using RSA-OAEP.
  - Decrypts messages using the server's RSA private key.
  - Displays both encrypted and decrypted messages for educational purposes.
  - Logs detailed cryptographic operations to the browser console.
  
☕ Java Implementation

The Java application demonstrates the same cryptographic principles in a console-based environment. It showcases the generation of RSA and Diffie-Hellman key pairs, the establishment of a shared secret, and the encryption/decryption of messages.

Key Components:

- DHKeyExchange.java:
  - Manages Diffie-Hellman key pair generation.
  - Derives shared secrets using peer public keys.
  
- RSAEncryption.java:
  - Manages RSA key pair generation.
  - Handles encryption and decryption of messages.
- Main.java:
  - Demonstrates the usage of DHKeyExchange and RSAEncryption.
  - Simulates client-server key exchanges and message encryption/decryption.
  - Verifies that shared secrets match to ensure successful key exchange.

# 📝 License
This project is licensed under the MIT License.

# Credits:
- Web Build:
  - Abdulaziz Al-Otaishan 
- Java Build:
  - Abdullah Al-Bekairi
  - Ibrahim Al-Halaki
