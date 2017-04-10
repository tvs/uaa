package org.cloudfoundry.identity.uaa.util;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.KeyPair;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;

public class KeyWithCert {
    private X509Certificate cert;
    private KeyPair pkey;

    public KeyWithCert(String key, String passphrase, String certificate) throws CertificateException {
        if(passphrase == null) { passphrase = ""; }


        PEMParser parser;
        try {
            parser = new PEMParser(new InputStreamReader(new ByteArrayInputStream(key.getBytes())));
            Object object = parser.readObject();
            PEMDecryptorProvider decryptor = new JcePEMDecryptorProviderBuilder().build(passphrase.toCharArray());
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
            if (object instanceof PEMEncryptedKeyPair) {
                pkey = converter.getKeyPair(((PEMEncryptedKeyPair) object).decryptKeyPair(decryptor));
            } else {
                pkey = converter.getKeyPair((PEMKeyPair) object);
            }

            if(pkey == null) {
                throw new CertificateException("Failed to read private key. The security provider could not parse it.");
            }
        } catch (IOException ex) {
            throw new CertificateException("Failed to read private key.", ex);
        }
        try {
            parser = new PEMParser(new InputStreamReader(new ByteArrayInputStream(certificate.getBytes())));
            X509CertificateHolder holder = (X509CertificateHolder) parser.readObject();
            cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(holder);
            if(cert == null) {
                throw new CertificateException("Failed to read certificate. The security provider could not parse it.");
            }
        } catch (IOException ex) {
            throw new CertificateException("Failed to read certificate.", ex);
        }

        if (!cert.getPublicKey().equals(pkey.getPublic())) {
            throw new CertificateException("Certificate does not match private key.");
        }
    }

    public X509Certificate getCert() {
        return cert;
    }

    public KeyPair getPkey() {
        return pkey;
    }

}
