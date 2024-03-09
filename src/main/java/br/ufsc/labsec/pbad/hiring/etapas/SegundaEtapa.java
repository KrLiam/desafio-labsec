package br.ufsc.labsec.pbad.hiring.etapas;

import java.security.KeyPair;

import br.ufsc.labsec.pbad.hiring.Constantes;
import br.ufsc.labsec.pbad.hiring.criptografia.chave.EscritorDeChaves;
import br.ufsc.labsec.pbad.hiring.criptografia.chave.GeradorDeChaves;

/**
 * <b>Segunda etapa - gerar chaves assimétricas</b>
 * <p>
 * A partir dessa etapa, tudo que será feito envolve criptografia assimétrica.
 * A tarefa aqui é parecida com a etapa anterior, pois refere-se apenas a
 * criar e armazenar chaves, mas nesse caso será usado um algoritmo de
 * criptografia assimétrica, o ECDSA.
 * <p>
 * Os pontos a serem verificados para essa etapa ser considerada concluída
 * são os seguintes:
 * <ul>
 * <li>
 * gerar um par de chaves usando o algoritmo ECDSA com o tamanho de 256 bits;
 * </li>
 * <li>
 * gerar outro par de chaves, mas com o tamanho de 521 bits. Note que esse
 * par de chaves será para a AC-Raiz;
 * </li>
 * <li>
 * armazenar em disco os pares de chaves em formato PEM.
 * </li>
 * </ul>
 */
public class SegundaEtapa {

    public static void executarEtapa() {
        try {
            GeradorDeChaves gen_chaves = new GeradorDeChaves(Constantes.algoritmoChave);

            KeyPair usuario = gen_chaves.gerarParDeChaves(256);
            EscritorDeChaves.escreveChaveEmDisco(usuario.getPublic(), Constantes.caminhoChavePublicaUsuario);
            EscritorDeChaves.escreveChaveEmDisco(usuario.getPrivate(), Constantes.caminhoChavePrivadaUsuario);
            
            KeyPair ac = gen_chaves.gerarParDeChaves(521);
            EscritorDeChaves.escreveChaveEmDisco(ac.getPublic(), Constantes.caminhoChavePublicaAc);
            EscritorDeChaves.escreveChaveEmDisco(ac.getPrivate(), Constantes.caminhoChavePrivadaAc);
        }
        catch (Exception exc) {
            System.out.println("Erro ao executar a segunda etapa: " + exc.getMessage());
        }
    }

}
