package tlsLight;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

public class CertificateHelpers {
	
	static PrivateKey loadRSAPrivateKey(String filePath) {
		//BigInteger privateKey = null;
		PrivateKey privateKey = null;
		try {
			InputStream inputStream = new FileInputStream(filePath);
			PKCS8EncodedKeySpec privateKeyBytes = new PKCS8EncodedKeySpec(inputStream.readAllBytes());
			//privateKey = new BigInteger(privateKeyBytes.getEncoded());
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			privateKey = keyFactory.generatePrivate(privateKeyBytes);
			inputStream.close();
		} catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
			e.printStackTrace();
			System.out.print("Error loading Private key");
		}
		return privateKey;
	}
	
	
	static Certificate readInCert(String filePath) {
		Certificate certificate = null; 
		try {
			CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
			InputStream certificateInputStream = new FileInputStream(filePath);
			certificate = certificateFactory.generateCertificate(certificateInputStream);
		} catch (CertificateException | FileNotFoundException e) {
			e.printStackTrace();
			System.out.print("Something went wrong loading the certificate");
			System.exit(1);
		}
		return certificate;
	}
	
	static Signature initSignitureForSigning(PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeyException {
		Signature signature = Signature.getInstance("SHA256WithRSA");
		SecureRandom secureRandom = new SecureRandom();
//		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA");
//		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		signature.initSign(privateKey, secureRandom);
		return signature;
	}
	
	static byte [] signWithRSAPrivateKey(PrivateKey privateKey, byte [] data) throws SignatureException, InvalidKeyException, NoSuchAlgorithmException {
		Signature signature = Signature.getInstance("SHA256WithRSA");
		SecureRandom secureRandom = new SecureRandom();
		signature.initSign(privateKey, secureRandom);
		signature.update(data);
		byte[] digitalSignature = signature.sign();
		return digitalSignature;
	}
	
	static boolean verifyDigitalSignature(Certificate publicCertificate, byte [] data, byte [] digitalSignature) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		Signature signature = Signature.getInstance("SHA256WithRSA");
		signature.initVerify(publicCertificate);
		signature.update(data);
		boolean verified = signature.verify(digitalSignature);
		return verified;
	}
}
