import express, { Request, Response } from 'express';
import morgan from 'morgan';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import cors from 'cors';

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(morgan('combined'));
app.use(cors());
let publicKey: crypto.webcrypto.CryptoKey;
let privateKey: crypto.webcrypto.CryptoKey;

async function generateKeyPair(): Promise<void> {
    const keyPair = await crypto.webcrypto.subtle.generateKey(
        {
            name: 'RSA-OAEP',
            modulusLength: 2048,
            publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
            hash: { name: 'SHA-256' },
        },
        true,
        ['encrypt', 'decrypt']
    );
    publicKey = keyPair.publicKey;
    privateKey = keyPair.privateKey;

    
    const exportedPrivateKey = await crypto.webcrypto.subtle.exportKey('pkcs8', privateKey);
    fs.writeFileSync(
        path.join(__dirname, 'keys', 'private_key.pem'),
        Buffer.from(exportedPrivateKey) // Guardar como buffer binario
    );

    const exportedPublicKey = await crypto.webcrypto.subtle.exportKey('spki', publicKey);
    fs.writeFileSync(
        path.join(__dirname, 'keys', 'public_key.pem'),
        Buffer.from(exportedPublicKey) // Guardar como buffer binario
    );
}


async function loadKeyPair(): Promise<void> {
    try {
        const privateKeyBuffer = fs.readFileSync(path.join(__dirname, 'keys', 'private_key.pem'));
        const publicKeyBuffer = fs.readFileSync(path.join(__dirname, 'keys', 'public_key.pem'));

        privateKey = await crypto.webcrypto.subtle.importKey(
            'pkcs8', 
            privateKeyBuffer, 
            {
                name: 'RSA-OAEP', 
                hash: { name: 'SHA-256' }
            },
            true,
            ['decrypt']
        );

        publicKey = await crypto.webcrypto.subtle.importKey(
            'spki', 
            publicKeyBuffer, 
            {
                name: 'RSA-OAEP', 
                hash: { name: 'SHA-256' }
            },
            true,
            ['encrypt']
        );
    } catch (error) {
        console.log('Generando nuevas claves...');
        await generateKeyPair();
    }
}

loadKeyPair();

app.get('/api/public-key', async (req: Request, res: Response) => {
    const exportedPublicKey = await crypto.webcrypto.subtle.exportKey('jwk', publicKey);
    res.status(200).json(exportedPublicKey);
});


app.post('/api/login', async (req: Request, res: Response) => {
    const { encryptedEmail, encryptedPassword } = req.body;
    try {
        const decryptedPasswordBuffer = await crypto.webcrypto.subtle.decrypt(
            { name: 'RSA-OAEP' },
            privateKey,
            new Uint8Array(Buffer.from(encryptedPassword, 'base64'))
        );
        const decryptedEmailBuffer = await crypto.webcrypto.subtle.decrypt(
            { name: 'RSA-OAEP' },
            privateKey,
            new Uint8Array(Buffer.from(encryptedEmail, 'base64'))
        );
        const decryptedPassword = new TextDecoder().decode(decryptedPasswordBuffer);
        const decryptedEmail = new TextDecoder().decode(decryptedEmailBuffer);
        if (decryptedPassword === 'root123' && decryptedEmail === 'admin') {
            res.status(201).json({ success: true });
        } else {
            res.status(401).json({ success: false, message: 'Invalid credentials' });
        }
    } catch (error) {
        console.error('Error durante el login:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

export default app;
