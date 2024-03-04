package br.ufsc.labsec.pbad.hiring.etapas;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;

import br.ufsc.labsec.pbad.hiring.Constantes;
import br.ufsc.labsec.pbad.hiring.criptografia.resumo.Resumidor;

/**
 * <b>Primeira etapa - obter o resumo criptográfico de um documento</b>
 * <p>
 * Basta obter o resumo criptográfico do documento {@code textoPlano.txt}.
 * <p>
 * Os pontos a serem verificados para essa etapa ser considerada concluída
 * são os seguintes:
 * <ul>
 * <li>
 * obter o resumo criptográfico do documento, especificado na descrição
 * dessa etapa, usando o algoritmo de resumo criptográfico conhecido por
 * SHA-256;
 * </li>
 * <li>
 * armazenar em disco o arquivo contendo o resultado do resumo criptográfico,
 * em formato hexadecimal.
 * </li>
 * </ul>
 */
public class PrimeiraEtapa {

    public static void executarEtapa() {
        try {
            Resumidor resumidor = new Resumidor(Constantes.algoritmoResumo);

            File input = new File(Constantes.caminhoTextoPlano);
            byte[] resumo = resumidor.resumir(input);

            resumidor.escreveResumoEmDisco(resumo, Constantes.caminhoResumoCriptografico);
        }
        catch (NoSuchAlgorithmException exc) {
            System.out.println("Algoritmo '" + Constantes.algoritmoResumo + "' não está disponível.");
        }
        catch (FileNotFoundException exc) {
            System.out.println("O arquivo '" + Constantes.caminhoTextoPlano + "' não existe.");
        }
        catch (IOException exc) {
            System.out.println("Falha de leitura/escrita de arquivo.");
        }
    }
}
