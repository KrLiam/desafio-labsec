package br.ufsc.labsec.pbad.hiring.etapas;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.x509.TBSCertificate;

import br.ufsc.labsec.pbad.hiring.Constantes;
import br.ufsc.labsec.pbad.hiring.criptografia.certificado.EscritorDeCertificados;
import br.ufsc.labsec.pbad.hiring.criptografia.certificado.GeradorDeCertificados;
import br.ufsc.labsec.pbad.hiring.criptografia.chave.LeitorDeChaves;

/**
 * <b>Terceira etapa - gerar certificados digitais</b>
 * <p>
 * Aqui você terá que gerar dois certificados digitais. A identidade ligada
 * a um dos certificados digitais deverá ser a sua. A entidade emissora do
 * seu certificado será a AC-Raiz, cuja chave privada já foi previamente
 * gerada. Também deverá ser feito o certificado digital para a AC-Raiz,
 * que deverá ser autoassinado.
 * <p>
 * Os pontos a serem verificados para essa etapa ser considerada concluída
 * são os seguintes:
 * <ul>
 * <li>
 * emitir um certificado digital autoassinado no formato X.509 para a AC-Raiz;
 * </li>
 * <li>
 * emitir um certificado digital no formato X.509, assinado pela AC-Raiz. O
 * certificado deve ter as seguintes características:
 * <ul>
 * <li>
 * {@code Subject} deverá ser o seu nome;
 * </li>
 * <li>
 * {@code SerialNumber} deverá ser o número da sua matrícula;
 * </li>
 * <li>
 * {@code Issuer} deverá ser a AC-Raiz.
 * </li>
 * </ul>
 * </li>
 * <li>
 * anexar ao desafio os certificados emitidos em formato PEM;
 * </li>
 * <li>
 * as chaves utilizadas nessa etapa deverão ser as mesmas já geradas.
 * </li>
 * </ul>
 */
public class TerceiraEtapa {
    public static void executarEtapa() {
        try {
            GeradorDeCertificados gerador = new GeradorDeCertificados(Constantes.algoritmoAssinatura);

            PrivateKey privada_ac = LeitorDeChaves.lerChavePrivadaDoDisco(Constantes.caminhoChavePrivadaAc);

            PublicKey publica_usuario = LeitorDeChaves.lerChavePublicaDoDisco(Constantes.caminhoChavePublicaUsuario);
            TBSCertificate tbs_usuario = gerador.gerarEstruturaCertificado(
                publica_usuario,
                Constantes.numeroDeSerie,
                Constantes.nomeUsuario,
                Constantes.nomeAcRaiz,
                Constantes.validadeCertificado
            );
            DERBitString assinatura_usuario = gerador.geraValorDaAssinaturaCertificado(tbs_usuario, privada_ac);
            X509Certificate certificado_usuario = gerador.gerarCertificado(tbs_usuario, assinatura_usuario);
            EscritorDeCertificados.escreveCertificado(Constantes.caminhoCertificadoUsuario, certificado_usuario);

            PublicKey publica_ac = LeitorDeChaves.lerChavePublicaDoDisco(Constantes.caminhoChavePublicaAc);
            TBSCertificate tbs_ac = gerador.gerarEstruturaCertificado(
                publica_ac,
                Constantes.numeroSerieAc,
                Constantes.nomeAcRaiz,
                Constantes.nomeAcRaiz,
                Constantes.validadeCertificado
            );
            DERBitString assinatura_ac = gerador.geraValorDaAssinaturaCertificado(tbs_ac, privada_ac);
            X509Certificate certificado_ac = gerador.gerarCertificado(tbs_ac, assinatura_ac);
            EscritorDeCertificados.escreveCertificado(Constantes.caminhoCertificadoAcRaiz, certificado_ac);
        }
        catch (Exception exc) {
            System.out.println("Erro ao executar a terceira etapa:");
            exc.printStackTrace();
        }
    }
}
