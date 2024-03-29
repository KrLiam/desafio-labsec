package br.ufsc.labsec.pbad.hiring.criptografia.chave;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

/**
 * Classe responsável por gerar pares de chaves assimétricas.
 *
 * @see KeyPair
 * @see PublicKey
 * @see PrivateKey
 */
public class GeradorDeChaves {
    private String algoritmo;
    private KeyPairGenerator generator;
    private SecureRandom random = new SecureRandom();

    /**
     * Construtor.
     *
     * @param algoritmo algoritmo de criptografia assimétrica a ser usado.
     */
    public GeradorDeChaves(String algoritmo) throws NoSuchAlgorithmException {
        this.algoritmo = algoritmo;
        this.generator = KeyPairGenerator.getInstance(this.algoritmo);
    }

    /**
     * Gera um par de chaves, usando o algoritmo definido pela classe, com o
     * tamanho da chave especificado.
     * 
     * Referência: https://www.txedo.com/blog/java-generate-rsa-keys-write-pem-file/
     *
     * @param tamanhoDaChave tamanho em bits das chaves geradas.
     * @return Par de chaves.
     * @see SecureRandom
     */
    public KeyPair gerarParDeChaves(int tamanhoDaChave) {
        generator.initialize(tamanhoDaChave, random);
        return generator.generateKeyPair();
    }
}
