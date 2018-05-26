package io.github.encrypter;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Date;

import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.util.io.Streams;

/**
 * Class used to encrypt/decrypt data.
 * 
 * @author Lukas M
 *
 */
public class PGPEncrypter {

    private KeyPairGenerator keyPairGenerator;

    /**
     * @param keySize generated key size
     * @throws Exception
     */
    public PGPEncrypter(int keySize) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
        keyPairGenerator.initialize(new RSAKeyGenParameterSpec(keySize, RSAKeyGenParameterSpec.F4));
    }

    /**
     * @return PGP key pair, containing a public and a private key
     * @throws GeneralSecurityException
     * @throws PGPException
     */
    public PGPKeyPair generateKeyPair() throws GeneralSecurityException, PGPException {
        return new JcaPGPKeyPair(PublicKeyAlgorithmTags.RSA_ENCRYPT, keyPairGenerator.generateKeyPair(), new Date());
    }

    /**
     * Encrypts specified data.
     * @param encryptionKey public key used to encrypt the data
     * @param data data to encrypt
     * @return
     * @throws PGPException
     * @throws IOException
     */
    public byte[] encrypt(PGPPublicKey encryptionKey, byte[] data) throws PGPException, IOException {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();

        OutputStream pOut = lData.open(bOut, PGPLiteralData.BINARY, PGPLiteralData.CONSOLE, data.length, new Date());
        pOut.write(data);
        pOut.close();

        byte[] plainText = bOut.toByteArray();

        ByteArrayOutputStream encOut = new ByteArrayOutputStream();

        PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(
                new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256).setWithIntegrityPacket(true)
                        .setSecureRandom(new SecureRandom()).setProvider("BC"));

        encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(encryptionKey).setProvider("BC"));

        OutputStream cOut = encGen.open(encOut, plainText.length);

        cOut.write(plainText);

        cOut.close();

        return encOut.toByteArray();
    }

    /**
     * Decrypts specified data.
     * @param privateKey private key used to decrypt the data
     * @param pgpEncryptedData data to decrypt
     * @return
     * @throws PGPException
     * @throws IOException
     */
    public byte[] decrypt(PGPPrivateKey privateKey, byte[] pgpEncryptedData)
            throws PGPException, IOException {
        PGPObjectFactory pgpFact = new JcaPGPObjectFactory(pgpEncryptedData);

        PGPEncryptedDataList encList = (PGPEncryptedDataList) pgpFact.nextObject();

        PGPPublicKeyEncryptedData encData = (PGPPublicKeyEncryptedData) encList.get(0);

        PublicKeyDataDecryptorFactory dataDecryptorFactory = new JcePublicKeyDataDecryptorFactoryBuilder()
                .setProvider("BC").build(privateKey);

        InputStream clear = encData.getDataStream(dataDecryptorFactory);

        byte[] literalData = Streams.readAll(clear);

        if (encData.verify()) {
            PGPObjectFactory litFact = new JcaPGPObjectFactory(literalData);
            PGPLiteralData litData = (PGPLiteralData) litFact.nextObject();

            byte[] data = Streams.readAll(litData.getInputStream());

            return data;
        }

        throw new IllegalStateException("modification check failed");
    }

}
