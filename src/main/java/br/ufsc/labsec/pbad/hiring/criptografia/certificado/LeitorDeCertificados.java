package br.ufsc.labsec.pbad.hiring.criptografia.certificado;

import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMParser;

/**
 * Classe responsável por ler um certificado do disco.
 *
 * @see CertificateFactory
 */
public class LeitorDeCertificados {

    /**
     * Lê um certificado do local indicado.
     * 
     * Referência: https://stackoverflow.com/questions/74066314/pemparser-bouncy-castle-read-certificate-and-private-key-from-pem
     *
     * @param caminhoCertificado caminho do certificado a ser lido.
     * @return Objeto do certificado.
     */
    public static X509Certificate lerCertificadoDoDisco(String caminhoCertificado)
    throws FileNotFoundException, IOException, CertificateException {
        try (PEMParser parser = new PEMParser(new FileReader(caminhoCertificado))) {
            Object object = parser.readObject();

            JcaX509CertificateConverter converter = new JcaX509CertificateConverter();

            if (object instanceof X509CertificateHolder) {
                X509CertificateHolder cert_object = (X509CertificateHolder) object;
                return converter.getCertificate(cert_object);
            }
        }    

        throw new SecurityException("Não foi possível ler certificado em '" + caminhoCertificado + "'.");
    }
}
