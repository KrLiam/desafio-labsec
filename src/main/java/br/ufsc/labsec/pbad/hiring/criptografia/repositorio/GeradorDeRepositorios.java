package br.ufsc.labsec.pbad.hiring.criptografia.repositorio;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import br.ufsc.labsec.pbad.hiring.Constantes;

/**
 * Classe responsável por gerar um repositório de chaves PKCS#12.
 *
 * @see KeyStore
 */
public class GeradorDeRepositorios {

    /**
     * Gera um PKCS#12 para a chave privada/certificado passados como parâmetro.
     * 
     * Referência: https://docs.oracle.com/javase/8/docs/api/java/security/KeyStore.html
     *
     * @param chavePrivada  chave privada do titular do certificado.
     * @param certificado   certificado do titular.
     * @param caminhoPkcs12 caminho onde será escrito o PKCS#12.
     * @param alias         nome amigável dado à entrada do PKCS#12, que
     *                      comportará a chave e o certificado.
     * @param senha         senha de acesso ao PKCS#12.
     */
    public static void gerarPkcs12(PrivateKey chavePrivada, X509Certificate certificado,
                                   String caminhoPkcs12, String alias, char[] senha)
    throws KeyStoreException, FileNotFoundException, IOException, NoSuchAlgorithmException, CertificateException {
        KeyStore store = KeyStore.getInstance(Constantes.formatoRepositorio);
    
        store.load(null, null);

        store.setKeyEntry(alias, chavePrivada, senha, new X509Certificate[]{certificado});

        File file = new File(caminhoPkcs12);
        file.getParentFile().mkdirs();
        
        try (FileOutputStream stream = new FileOutputStream(caminhoPkcs12)) {
            store.store(stream, senha);
        }
    }
}
