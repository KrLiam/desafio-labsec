package br.ufsc.labsec.pbad.hiring.etapas;

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
            RepositorioChaves chaves = new RepositorioChaves(Constantes.formatoRepositorio);
            chaves.abrir(Constantes.caminhoPkcs12AcRaiz, Constantes.senhaMestre);
            
            PrivateKey privada_ac = chaves.pegarChavePrivada(Constantes.aliasAc);
            X509Certificate cert_ac = chaves.pegarCertificado(Constantes.aliasAc);

            GeradorDeAssinatura assinaturas = new GeradorDeAssinatura();
            assinaturas.informaAssinante(cert_ac, privada_ac);

            CMSSignedData signed = assinaturas.assinar(Constantes.caminhoTextoPlano);

            FileOutputStream output = new FileOutputStream(Constantes.caminhoAssinatura);
            assinaturas.escreveAssinatura(output, signed);
        }
        catch (Exception exc) {
            System.out.println("Erro ao executar etapa 5:");
            exc.printStackTrace();
        }
    }

}
