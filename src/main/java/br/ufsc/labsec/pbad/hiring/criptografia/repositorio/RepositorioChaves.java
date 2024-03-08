package br.ufsc.labsec.pbad.hiring.criptografia.repositorio;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * Essa classe representa um repositório de chaves do tipo PKCS#12.
 *
 * @see KeyStore
 */
public class RepositorioChaves {

    private KeyStore repositorio;
    private char[] senha;

    /**
     * Construtor.
     */
    public RepositorioChaves(String formatoRepositorio) throws KeyStoreException {
        repositorio = KeyStore.getInstance(formatoRepositorio);
    }

    /**
     * Abre o repositório do local indicado.
     *
     * @param caminhoRepositorio caminho do PKCS#12.
     * @param senha Senha do repositório.
     */
    public void abrir(String caminhoRepositorio, char[] senha)
    throws IOException, NoSuchAlgorithmException, CertificateException {
        try (FileInputStream stream = new FileInputStream(caminhoRepositorio)) {
            repositorio.load(stream, senha);
        }
        
        this.senha = senha;
    }

    /**
     * Obtém a chave privada do PKCS#12.
     * 
     * @param alias O alias relacionado ao certificado desejado.
     * @return Chave privada.
     */
    public PrivateKey pegarChavePrivada(String alias)
    throws NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException {
        KeyStore.PasswordProtection param = new KeyStore.PasswordProtection(senha);
        
        KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry) repositorio.getEntry(alias, param);
        return entry.getPrivateKey();
    }
    
    /**
     * Obtém do certificado do PKCS#12.
     *
     * @param alias O alias relacionado ao certificado desejado.
     * @return Certificado.
     */
    public X509Certificate pegarCertificado(String alias)
    throws NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException {
        KeyStore.PasswordProtection param = new KeyStore.PasswordProtection(senha);

        KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry) repositorio.getEntry(alias, param);
        return (X509Certificate) entry.getCertificate();
    }
}
