package br.ufsc.labsec.pbad.hiring.criptografia.chave;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.security.Key;
import java.security.PrivateKey;

import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;

/**
 * Essa classe é responsável por escrever uma chave assimétrica no disco. Note
 * que a chave pode ser tanto uma chave pública quanto uma chave privada.
 *
 * @see Key
 */
public class EscritorDeChaves {

    /**
     * Escreve uma chave no local indicado.
     *
     * @param chave         chave assimétrica a ser escrita em disco.
     * @param nomeDoArquivo nome do local onde será escrita a chave.
     */
    public static void escreveChaveEmDisco(Key chave, String nomeDoArquivo) throws IOException {
        File file = new File(nomeDoArquivo);
        file.getParentFile().mkdirs();

        JcaPEMWriter writer = new JcaPEMWriter(new FileWriter(file));

        try {
            Object objeto = chave;

            if (chave instanceof PrivateKey) {
                JcaPKCS8Generator generator = new JcaPKCS8Generator((PrivateKey) chave, null);
                objeto = generator.generate();
            }

            writer.writeObject(objeto);
        }
        finally {
            writer.close();
        }
    }

}
