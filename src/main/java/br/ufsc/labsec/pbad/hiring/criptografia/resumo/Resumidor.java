package br.ufsc.labsec.pbad.hiring.criptografia.resumo;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Classe responsável por executar a função de resumo criptográfico.
 *
 * @see MessageDigest
 */
public class Resumidor {

    private MessageDigest md;
    private String algoritmo;

    /**
     * Construtor.
     */
    public Resumidor(String algoritmo) throws NoSuchAlgorithmException {
        this.algoritmo = algoritmo;
        md = MessageDigest.getInstance(this.algoritmo);
    }

    /**
     * Calcula o resumo criptográfico do arquivo indicado.
     *
     * @param arquivoDeEntrada arquivo a ser processado.
     * @return Bytes do resumo.
     */
    public byte[] resumir(File arquivoDeEntrada) throws FileNotFoundException, IOException {
        FileInputStream stream = new FileInputStream(arquivoDeEntrada);
        
        byte[] buffer = new byte[256];
        md.reset();

        while(true) {
            int length = stream.read(buffer);
            if (length == -1) break;

            md.update(buffer, 0, length);
        }

        stream.close();
        return md.digest();
    }

    /**
     * Escreve o resumo criptográfico no local indicado.
     *
     * @param resumo         resumo criptográfico em bytes.
     * @param caminhoArquivo caminho do arquivo.
     */
    public void escreveResumoEmDisco(byte[] resumo, String caminhoArquivo) {
        // TODO implementar
    }

}
