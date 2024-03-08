package br.ufsc.labsec.pbad.hiring.etapas;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import br.ufsc.labsec.pbad.hiring.Constantes;
import br.ufsc.labsec.pbad.hiring.criptografia.certificado.LeitorDeCertificados;
import br.ufsc.labsec.pbad.hiring.criptografia.chave.LeitorDeChaves;
import br.ufsc.labsec.pbad.hiring.criptografia.repositorio.GeradorDeRepositorios;

/**
 * <b>Quarta etapa - gerar repositório de chaves seguro</b>
 * <p>
 * Essa etapa tem como finalidade gerar um repositório seguro de chaves
 * assimétricas. Esse repositório deverá ser no formato PKCS#12. Note que
 * esse repositório é basicamente um tabela de espalhamento com pequenas
 * mudanças. Por exemplo, sua estrutura seria algo como {@code <Alias,
 * <Certificado, Chave Privada>>}, onde o _alias_ é um nome amigável dado a
 * uma entrada da estrutura, e o certificado e chave privada devem ser
 * correspondentes à mesma identidade. O _alias_ serve como elemento de busca
 * dessa identidade. O PKCS#12 ainda conta com uma senha, que serve para
 * cifrar a estrutura (isso é feito de modo automático).
 * <p>
 * Os pontos a serem verificados para essa etapa ser considerada concluída
 * são os seguintes:
 * <ul>
 * <li>
 * gerar um repositório para o seu certificado/chave privada com senha e
 * alias de acordo com as constantes fornecidas;
 * </li>
 * <li>
 * gerar um repositório para o certificado/chave privada da AC-Raiz com senha
 * e alias de acordo com as constantes fornecidas.
 * </li>
 * </ul>
 */
public class QuartaEtapa {

    public static void executarEtapa() {
        try {
            PrivateKey privada_usuario = LeitorDeChaves.lerChavePrivadaDoDisco(Constantes.caminhoChavePrivadaUsuario);
            X509Certificate cert_usuario = LeitorDeCertificados.lerCertificadoDoDisco(Constantes.caminhoCertificadoUsuario);

            GeradorDeRepositorios.gerarPkcs12(
                privada_usuario,
                cert_usuario,
                Constantes.caminhoPkcs12Usuario,
                Constantes.aliasUsuario,
                Constantes.senhaMestre
            );

            PrivateKey privada_ac = LeitorDeChaves.lerChavePrivadaDoDisco(Constantes.caminhoChavePrivadaAc);
            X509Certificate cert_ac = LeitorDeCertificados.lerCertificadoDoDisco(Constantes.caminhoCertificadoAcRaiz);

            GeradorDeRepositorios.gerarPkcs12(
                privada_ac,
                cert_ac,
                Constantes.caminhoPkcs12AcRaiz,
                Constantes.aliasAc,
                Constantes.senhaMestre
            );
        }
        catch (Exception exc) {
            System.out.println("Erro ao executar a quarta etapa:");
            exc.printStackTrace();
        }
    }
}
