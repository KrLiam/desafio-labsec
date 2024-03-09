package br.ufsc.labsec.pbad.hiring.etapas;

import java.io.File;

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

            File entrada = new File(Constantes.caminhoTextoPlano);
            byte[] resumo = resumidor.resumir(entrada);

            resumidor.escreveResumoEmDisco(resumo, Constantes.caminhoResumoCriptografico);
        }
        catch (Exception exc) {
            System.out.println("Erro ao executar a primeira etapa:");
            exc.printStackTrace();
        }
    }
}
