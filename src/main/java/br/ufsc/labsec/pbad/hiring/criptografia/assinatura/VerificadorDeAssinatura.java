package br.ufsc.labsec.pbad.hiring.criptografia.assinatura;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;

import java.security.cert.X509Certificate;
import java.util.Iterator;

/**
 * Classe responsável por verificar a integridade de uma assinatura.
 */
public class VerificadorDeAssinatura {

    /**
     * Verifica a integridade de uma assinatura digital no padrão CMS.
     *
     * @param certificado certificado do assinante.
     * @param assinatura  documento assinado.
     * @return {@code true} se a assinatura for íntegra, e {@code false} do
     * contrário.
     */
    public boolean verificarAssinatura(X509Certificate certificado, CMSSignedData assinatura)
    throws OperatorCreationException {
        SignerInformationVerifier verifier = geraVerificadorInformacoesAssinatura(certificado);
        SignerInformation signer = pegaInformacoesAssinatura(assinatura);

        try {
            return signer.verify(verifier);
        }
        catch (CMSException exc) {
            return false;
        }
    }

    /**
     * Gera o verificador de assinaturas a partir das informações do assinante.
     *
     * @param certificado certificado do assinante.
     * @return Objeto que representa o verificador de assinaturas.
     */
    private SignerInformationVerifier geraVerificadorInformacoesAssinatura(X509Certificate certificado)
    throws OperatorCreationException {
        JcaSimpleSignerInfoVerifierBuilder builder = new JcaSimpleSignerInfoVerifierBuilder();
        
        builder.setProvider(BouncyCastleProvider.PROVIDER_NAME);
        return builder.build(certificado);
    }

    /**
     * Classe responsável por pegar as informações da assinatura dentro do CMS.
     *
     * @param assinatura documento assinado.
     * @return Informações da assinatura.
     */
    private SignerInformation pegaInformacoesAssinatura(CMSSignedData assinatura) {
        SignerInformationStore signers = assinatura.getSignerInfos();
        
        // considera somente o primeiro assinante
        Iterator<SignerInformation> iter = signers.iterator();
        return iter.next();
    }
}
