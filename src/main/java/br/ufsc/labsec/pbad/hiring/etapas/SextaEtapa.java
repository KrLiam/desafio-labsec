package br.ufsc.labsec.pbad.hiring.etapas;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.security.Security;
import java.security.cert.X509Certificate;

import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import br.ufsc.labsec.pbad.hiring.Constantes;
import br.ufsc.labsec.pbad.hiring.criptografia.assinatura.VerificadorDeAssinatura;
import br.ufsc.labsec.pbad.hiring.criptografia.repositorio.RepositorioChaves;

/**
 * <b>Sexta etapa - verificar uma assinatura digital</b>
 * <p>
 * Por último, será necessário verificar a integridade da assinatura
 * recém gerada. Note que o processo de validação de uma assinatura
 * digital pode ser muito complexo, mas aqui o desafio será simples. Para
 * verificar a assinatura será necessário apenas decifrar o valor da
 * assinatura (resultante do processo de cifra do resumo criptográfico do
 * arquivo {@code textoPlano.txt} com as informações da estrutura da
 * assinatura) e comparar esse valor com o valor do resumo criptográfico do
 * arquivo assinado. Como dito na fundamentação, para assinar é usada a chave
 * privada, e para decifrar (verificar) é usada a chave pública.
 * <p>
 * Os pontos a serem verificados para essa etapa ser considerada concluída
 * são os seguintes:
 * <ul>
 * <li>
 * verificar a assinatura gerada na etapa anterior, de acordo com o
 * processo descrito, e apresentar esse resultado.
 * </li>
 * </ul>
 */
public class SextaEtapa {
    public static void executarEtapa() {
        Security.addProvider(new BouncyCastleProvider());

        try (FileInputStream stream = new FileInputStream(Constantes.caminhoAssinatura)) {
            ByteArrayInputStream assinatura = new ByteArrayInputStream(stream.readAllBytes());

            RepositorioChaves chaves = new RepositorioChaves(Constantes.formatoRepositorio);

            chaves.abrir(Constantes.caminhoPkcs12Usuario, Constantes.senhaMestre);
            X509Certificate certificado = chaves.pegarCertificado(Constantes.aliasUsuario);

            VerificadorDeAssinatura verificador = new VerificadorDeAssinatura();
            boolean result = verificador.verificarAssinatura(certificado, new CMSSignedData(assinatura));

            System.out.println("Assinatura válida: " + String.valueOf(result));
        }
        catch (Exception exc) {
            System.out.println("Erro ao executar sexta etapa:");
            exc.printStackTrace();
        }
    }
}
