package br.ufsc.labsec.pbad.hiring.criptografia.certificado;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.security.cert.Certificate;

import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

/**
 * Classe responsável por escrever um certificado no disco.
 */
public class EscritorDeCertificados {

    /**
     * Escreve o certificado indicado no disco.
     *
     * @param nomeArquivo           caminho que será escrito o certificado.
     * @param certificado Objeto do certificado.
     */
    public static void escreveCertificado(String nomeArquivo, Certificate certificado)
    throws IOException {
        File file = new File(nomeArquivo);
        file.getParentFile().mkdirs();
        
        try (JcaPEMWriter writer = new JcaPEMWriter(new FileWriter(file))) {
            writer.writeObject(certificado);
        }
    }
}
