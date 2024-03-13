package br.ufsc.labsec.pbad.hiring.etapas;

import java.io.File;
import java.io.FileOutputStream;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import org.bouncycastle.cms.CMSSignedData;

import br.ufsc.labsec.pbad.hiring.Constantes;
import br.ufsc.labsec.pbad.hiring.criptografia.assinatura.GeradorDeAssinatura;
import br.ufsc.labsec.pbad.hiring.criptografia.repositorio.RepositorioChaves;

/**
 * <b>Quinta etapa - gerar uma assinatura digital</b>
 * <p>
 * Essa etapa é um pouco mais complexa, pois será necessário que
 * implemente um método para gerar assinaturas digitais. O padrão de
 * assinatura digital adotado será o Cryptographic Message Syntax (CMS).
 * Esse padrão usa a linguagem ASN.1, que é uma notação em binário, assim
 * não será possível ler o resultado obtido sem o auxílio de alguma
 * ferramenta. Caso tenha interesse em ver a estrutura da assinatura
 * gerada, recomenda-se o uso da ferramenta {@code dumpasn1}.
 * <p>
 * Os pontos a serem verificados para essa etapa ser considerada concluída
 * são os seguintes:
 * <ul>
 * <li>
 * gerar um assinatura digital usando o algoritmo de resumo criptográfico
 * SHA-256 e o algoritmo de criptografia assimétrica ECDSA;
 * </li>
 * <li>
 * o assinante será você. Então, use o repositório de chaves recém gerado para
 * seu certificado e chave privada;
 * </li>
 * <li>
 * assinar o documento {@code textoPlano.txt}, onde a assinatura deverá ser do
 * tipo "anexada", ou seja, o documento estará embutido no arquivo de
 * assinatura;
 * </li>
 * <li>
 * gravar a assinatura em disco.
 * </li>
 * </ul>
 */
public class QuintaEtapa {
    public static void executarEtapa() {
        try {
            RepositorioChaves repositorio = new RepositorioChaves(Constantes.formatoRepositorio);
            repositorio.abrir(Constantes.caminhoPkcs12Usuario, Constantes.senhaMestre);
            
            PrivateKey chave_privada = repositorio.pegarChavePrivada(Constantes.aliasUsuario);
            X509Certificate certificado = repositorio.pegarCertificado(Constantes.aliasUsuario);

            GeradorDeAssinatura gerador_assinatura = new GeradorDeAssinatura();
            gerador_assinatura.informaAssinante(certificado, chave_privada);
            CMSSignedData dados_assinados = gerador_assinatura.assinar(Constantes.caminhoTextoPlano);

            File saida = new File(Constantes.caminhoAssinatura);
            saida.getParentFile().mkdirs();
            gerador_assinatura.escreveAssinatura(new FileOutputStream(saida), dados_assinados);
        }
        catch (Exception exc) {
            System.out.println("Erro ao executar a quinta etapa: " + exc.getMessage());
        }
    }
}
