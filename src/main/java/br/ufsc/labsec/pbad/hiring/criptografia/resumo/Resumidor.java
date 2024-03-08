package br.ufsc.labsec.pbad.hiring.criptografia.resumo;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
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

    private static final byte[] hex_chars = "0123456789abcdef".getBytes();

    /**
     * Escreve o resumo criptográfico no local indicado.
     *
     * @param resumo         resumo criptográfico em bytes.
     * @param caminhoArquivo caminho do arquivo.
     */
    public void escreveResumoEmDisco(byte[] resumo, String caminhoArquivo) throws IOException {
        byte[] chars = new byte[resumo.length * 2];

        for (int i = 0; i < resumo.length; i++) {
            int value = resumo[i] & 0xFF;

            chars[2*i] = hex_chars[value >>> 4];
            chars[2*i + 1] = hex_chars[value % 16];
        }

        String hex = new String(chars, StandardCharsets.UTF_8);

        try (FileWriter writer = new FileWriter(caminhoArquivo)) {
            writer.write(hex);
        }
    }
}
