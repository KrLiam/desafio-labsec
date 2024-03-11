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
    public byte[] resumir(File arquivoDeEntrada) throws IOException {
        try (FileInputStream stream = new FileInputStream(arquivoDeEntrada)) {
            md.reset();
    
            while(true) {
                int value = stream.read();
                if (value == -1) break;
    
                md.update((byte) value);
            }
    
            return md.digest();
        }
        
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

        File file = new File(caminhoArquivo);
        file.getParentFile().mkdirs();
        
        try (FileWriter writer = new FileWriter(caminhoArquivo)) {
            writer.write(hex);
        }
    }
}
