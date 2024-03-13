package br.ufsc.labsec.pbad.hiring.criptografia.certificado;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.V1TBSCertificateGenerator;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;

import br.ufsc.labsec.pbad.hiring.Constantes;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Calendar;


/**
 * Classe responsável por gerar certificados no padrão X.509.
 * <p>
 * Um certificado é basicamente composto por três partes, que são:
 * <ul>
 * <li>
 * Estrutura de informações do certificado;
 * </li>
 * <li>
 * Algoritmo de assinatura;
 * </li>
 * <li>
 * Valor da assinatura.
 * </li>
 * </ul>
 */

public class GeradorDeCertificados {
    AlgorithmIdentifier algoritmoDeAssinatura;
    Signature signature;

    public GeradorDeCertificados(String algoritmoAssinatura) throws NoSuchAlgorithmException {
        DefaultSignatureAlgorithmIdentifierFinder finder = new DefaultSignatureAlgorithmIdentifierFinder();

        algoritmoDeAssinatura = finder.find(algoritmoAssinatura);
        signature = Signature.getInstance(algoritmoAssinatura);
    }

    /**
     * Gera a estrutura de informações de um certificado.
     * 
     * Referência: http://www.java2s.com/example/java-src/pkg/com/vmware/identity/rest/core/test/util/certificategenerator-9d67d.html
     *
     * @param chavePublica  chave pública do titular.
     * @param numeroDeSerie número de série do certificado.
     * @param nome          nome do titular.
     * @param nomeAc        nome da autoridade emissora.
     * @param dias          a partir da data atual, quantos dias de validade
     *                      terá o certificado.
     * @return Estrutura de informações do certificado.
     */
    public TBSCertificate gerarEstruturaCertificado(PublicKey chavePublica,
                                                    int numeroDeSerie, String nome,
                                                    String nomeAc, int dias) {
        V1TBSCertificateGenerator generator = new V1TBSCertificateGenerator();

        SubjectPublicKeyInfo public_info = SubjectPublicKeyInfo.getInstance(chavePublica.getEncoded());
        generator.setSubjectPublicKeyInfo(public_info);
        generator.setSignature(algoritmoDeAssinatura);

        generator.setSerialNumber(new ASN1Integer(numeroDeSerie));
        
        generator.setIssuer(new X500Name(nomeAc));
        generator.setSubject(new X500Name(nome));

        Calendar calendar = Calendar.getInstance();
        generator.setStartDate(new Time(calendar.getTime()));

        calendar.add(Calendar.DATE, dias);
        generator.setEndDate(new Time(calendar.getTime()));

        return generator.generateTBSCertificate();
    }

    /**
     * Gera valor da assinatura do certificado.
     * 
     * Referência: http://www.java2s.com/example/java-src/pkg/com/vmware/identity/rest/core/test/util/certificategenerator-9d67d.html
     *
     * @param estruturaCertificado estrutura de informações do certificado.
     * @param chavePrivadaAc       chave privada da AC que emitirá esse
     *                             certificado.
     * @return Bytes da assinatura.
     */
    public DERBitString geraValorDaAssinaturaCertificado(
        TBSCertificate estruturaCertificado, PrivateKey chavePrivadaAc
    ) throws InvalidKeyException, SignatureException, IOException {
        signature.initSign(chavePrivadaAc);

        signature.update(estruturaCertificado.getEncoded());
        byte[] bytes = signature.sign();

        return new DERBitString(bytes);
    }

    /**
     * Gera um certificado.
     * 
     * Referência: http://www.java2s.com/example/java-src/pkg/com/vmware/identity/rest/core/test/util/certificategenerator-9d67d.html
     *
     * @param estruturaCertificado  estrutura de informações do certificado.
     * @param valorDaAssinatura     valor da assinatura.
     * @return Objeto que representa o certificado.
     * @see ASN1EncodableVector
     */
    public X509Certificate gerarCertificado(
        TBSCertificate estruturaCertificado, DERBitString valorDaAssinatura
    ) throws CertificateException, IOException {
        
        ASN1EncodableVector vector = new ASN1EncodableVector();

        vector.add(estruturaCertificado);
        vector.add(algoritmoDeAssinatura);
        vector.add(valorDaAssinatura);
        
        CertificateFactory factory = CertificateFactory.getInstance(Constantes.formatoCertificado);
        byte[] encoded = new DERSequence(vector).getEncoded(ASN1Encoding.DER);
        return (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(encoded));
    }
}
