package br.ufsc.labsec.pbad.hiring.criptografia.chave;

import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.KeySpec;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

/**
 * Classe responsável por ler uma chave assimétrica do disco.
 *
 * @see KeyFactory
 * @see KeySpec
 */
public class LeitorDeChaves {

    /**
     * Lê a chave privada do local indicado.
     * 
     * Referência: https://www.baeldung.com/java-read-pem-file-keys
     *
     * @param caminhoChave local do arquivo da chave privada.
     * @return Chave privada.
     */
    public static PrivateKey lerChavePrivadaDoDisco(String caminhoChave)
    throws FileNotFoundException, IOException {
        try (PEMParser parser = new PEMParser(new FileReader(caminhoChave))) {
            Object object = parser.readObject();

            PrivateKeyInfo info = PrivateKeyInfo.getInstance(object);
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            return converter.getPrivateKey(info);
        }
    }

    /**
     * Lê a chave pública do local indicado.
     * 
     * Referência: https://www.baeldung.com/java-read-pem-file-keys
     *
     * @param caminhoChave local do arquivo da chave pública.
     * @return Chave pública.
     */
    public static PublicKey lerChavePublicaDoDisco(String caminhoChave)
    throws FileNotFoundException, IOException {
        try (PEMParser parser = new PEMParser(new FileReader(caminhoChave))) {
            Object obj = parser.readObject();

            SubjectPublicKeyInfo info = SubjectPublicKeyInfo.getInstance(obj);
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            return converter.getPublicKey(info);
        }
    }
}
