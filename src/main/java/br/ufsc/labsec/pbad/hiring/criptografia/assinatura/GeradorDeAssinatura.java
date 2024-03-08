package br.ufsc.labsec.pbad.hiring.criptografia.assinatura;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import br.ufsc.labsec.pbad.hiring.Constantes;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.OutputStream;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * Classe responsável por gerar uma assinatura digital.
 * <p>
 * Aqui será necessário usar a biblioteca Bouncy Castle, pois ela já possui a
 * estrutura básica da assinatura implementada.
 */
public class GeradorDeAssinatura {

    private X509Certificate certificado;
    private PrivateKey chavePrivada;
    private CMSSignedDataGenerator geradorAssinaturaCms;

    /**
     * Construtor.
     */
    public GeradorDeAssinatura() {
        geradorAssinaturaCms = new CMSSignedDataGenerator();
    }

    /**
     * Informa qual será o assinante.
     *
     * @param certificado  certificado, no padrão X.509, do assinante.
     * @param chavePrivada chave privada do assinante.
     */
    public void informaAssinante(X509Certificate certificado,
                                 PrivateKey chavePrivada) throws CertificateEncodingException, CMSException {
        this.certificado = certificado;
        this.chavePrivada = chavePrivada;

        List<X509Certificate> cert_array = new ArrayList<X509Certificate>();
        cert_array.add(certificado);
        JcaCertStore certs = new JcaCertStore(cert_array);

        geradorAssinaturaCms.addCertificates(certs);
    }

    /**
     * Gera uma assinatura no padrão CMS.
     *
     * @param caminhoDocumento caminho do documento que será assinado.
     * @return Documento assinado.
     */
    public CMSSignedData assinar(String caminhoDocumento)
    throws FileNotFoundException, IOException, CertificateEncodingException, OperatorCreationException, CMSException {
        CMSTypedData data = preparaDadosParaAssinar(caminhoDocumento);
        SignerInfoGenerator signer = preparaInformacoesAssinante(chavePrivada, certificado);

        geradorAssinaturaCms.addSignerInfoGenerator(signer);

        return geradorAssinaturaCms.generate(data, true);
    }

    /**
     * Transforma o documento que será assinado para um formato compatível
     * com a assinatura.
     *
     * @param caminhoDocumento caminho do documento que será assinado.
     * @return Documento no formato correto.
     */
    private CMSTypedData preparaDadosParaAssinar(String caminhoDocumento)
    throws FileNotFoundException, IOException {
        try (FileInputStream stream = new FileInputStream(caminhoDocumento)) {
            return new CMSProcessableByteArray(stream.readAllBytes());
        }
    }

    /**
     * Gera as informações do assinante na estrutura necessária para ser
     * adicionada na assinatura.
     *
     * @param chavePrivada chave privada do assinante.
     * @param certificado  certificado do assinante.
     * @return Estrutura com informações do assinante.
     */
    private SignerInfoGenerator preparaInformacoesAssinante(
        PrivateKey chavePrivada, X509Certificate certificado
    ) throws CertificateEncodingException, OperatorCreationException {
        JcaDigestCalculatorProviderBuilder provider_builder = new JcaDigestCalculatorProviderBuilder();
        DigestCalculatorProvider provider = provider_builder.build();
        
        JcaContentSignerBuilder signer_builder = new JcaContentSignerBuilder(Constantes.algoritmoAssinatura);
        ContentSigner signer = signer_builder.build(chavePrivada);

        JcaSignerInfoGeneratorBuilder info_builder = new JcaSignerInfoGeneratorBuilder(provider);

        return info_builder.build(signer, certificado);
    }

    /**
     * Escreve a assinatura no local apontado.
     *
     * @param arquivo    arquivo que será escrita a assinatura.
     * @param assinatura objeto da assinatura.
     */
    public void escreveAssinatura(OutputStream arquivo, CMSSignedData assinatura) throws IOException {
        byte[] encoded = assinatura.getEncoded(ASN1Encoding.DER);
        arquivo.write(encoded);
    }
}
