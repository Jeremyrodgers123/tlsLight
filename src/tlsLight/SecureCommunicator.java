package tlsLight;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.util.ArrayList;

import javax.crypto.spec.IvParameterSpec;

public abstract class SecureCommunicator {
	SecureCommunicator(){
		dHPrivateKey = null;
		dHPublicKey = null;
	}
	
	SecureCommunicator(String rsaPrivKPath, String rsaPubKPath, String CAPrivKPath, String CAPubKPath ) throws SignatureException{
		generateDHPrivateKey();
		dHPublicKey = DiffieHellmanHelpers.generatePublicKey(dHPrivateKey);
		rsaPrivateKey = CertificateHelpers.loadRSAPrivateKey(rsaPrivKPath);
		CASignedPublicCertificate = CertificateHelpers.readInCert(rsaPubKPath);
		CAPublicCertificate = CertificateHelpers.readInCert(CAPubKPath);
		try {
			signature = CertificateHelpers.initSignitureForSigning(rsaPrivateKey);
			digitalSignature = sign(dHPublicKey.toByteArray());
		} catch (InvalidKeyException | NoSuchAlgorithmException e) {
			System.out.println("Error creating signature");
			System.exit(1);
			e.printStackTrace();
		}
	}
	
	protected byte [] digitalSignature;
	protected PrivateKey rsaPrivateKey;
	protected BigInteger dHPrivateKey;
	protected BigInteger dHPublicKey;
	protected BigInteger sharedDHPrivateKey;
	protected Signature signature;
	protected Certificate CASignedPublicCertificate;
	protected Certificate CAPublicCertificate;
	//protected Certificate CASignedPublicCertificate;
	
	/*****
	 * subkeys
	 * *****/
	protected byte [] serverEncrypt;
	protected byte [] clientEncrypt;
	protected byte [] serverMac;
	protected byte [] clientMac;
	protected IvParameterSpec serverIV;
	protected IvParameterSpec clientIV;

	
	private void generateDHPrivateKey() {
		byte [] randomBytes = SecurityHelpers.generateRandomBytes(256);
		dHPrivateKey = new BigInteger(randomBytes);
	}
	
	protected byte [] sign(byte [] data) throws SignatureException, InvalidKeyException, NoSuchAlgorithmException {
		return CertificateHelpers.signWithRSAPrivateKey(rsaPrivateKey, data);
	}

	
	protected void setDHPublicKey(BigInteger _dHPublicKey) {
		dHPublicKey = _dHPublicKey;
	}
	
//	public abstract void dHhandshake() throws IOException, CertificateEncodingException, ClassNotFoundException, InvalidKeyException, NoSuchAlgorithmException; 

	public abstract byte [] getNonce();
	
	public void createSharedDHPrivateKey(BigInteger publicKey) {
		sharedDHPrivateKey = DiffieHellmanHelpers.createSharedDHPrivateKey(publicKey, dHPrivateKey );
	}
	
	public Certificate getSignedCertificate() {
		return CASignedPublicCertificate;
	}
	
	public void makeSecretKeys(byte [] clientNonce, BigInteger sharedDHPrivateKey) throws InvalidKeyException, NoSuchAlgorithmException{
		byte [] prk = SecurityHelpers.hmac(clientNonce, sharedDHPrivateKey.toByteArray());
		serverEncrypt = SecurityHelpers.hdkfExpand(prk, "server Encrypt".getBytes());
		clientEncrypt = SecurityHelpers.hdkfExpand(prk, "client Encrypt".getBytes());
		serverMac = SecurityHelpers.hdkfExpand(prk, "server Mac".getBytes());
		clientMac = SecurityHelpers.hdkfExpand(prk, "client Mac".getBytes());
		serverIV = new IvParameterSpec( SecurityHelpers.hdkfExpand(prk, "server IV".getBytes()) );
		clientIV = new IvParameterSpec( SecurityHelpers.hdkfExpand(prk, "client IV".getBytes()) );
	}
	
	public byte[] readInFile(String fileName){
		FileInputStream inputStream = null;
		byte [] bytes = null;
		try {
			File file = new File(fileName);
			inputStream = new FileInputStream(file);
			bytes = new byte [(int)file.length()];
			inputStream.read(bytes);
		} catch (IOException e) {
			System.out.println("file not found.");
			e.printStackTrace();
			System.exit(1);
		}
		return bytes;
	}
	
	public byte [] macMsgsSoFar(byte [] key, ArrayList<byte []> msgsSofar) throws InvalidKeyException, NoSuchAlgorithmException {
		// TODO Auto-generated method stub
		int size = 0;
		for( byte [] arr : msgsSofar) {
			size += arr.length;
		}
		byte [] allMsgs = new byte [size];
		
		int current = 0;
		for( byte [] arr : msgsSofar ) {
			for(int i = 0; i < arr.length; i++) {
				allMsgs[current] = arr[i];
				current++;
			}
		}
		return SecurityHelpers.hmac(key, allMsgs);
	}
	/**
	 * 
	 * Testing Helper Functions
	 * */
	
	public BigInteger getDHPublicKey() {
		//System.out.println("DHPublicKey: " + dHPublicKey);
		if(dHPublicKey == null) {
			System.out.println("DHPublicKey is null");
			System.exit(1);
		}
		return dHPublicKey;
	}
	
	public byte [] getDigitalSignature() {
		return digitalSignature;
	}
	
	public BigInteger getSharedDHPrivateKey() {
		//System.out.println("shared Private Key: " + sharedDHPrivateKey);
		return sharedDHPrivateKey;
	}
	
	public byte[] getServerEncrypt() {
		return serverEncrypt;
	}
	public byte[] getClientEncrypt() {
		return clientEncrypt;
	}
	
	public byte[] getServerMac() {
		return serverMac;
	}
	public byte[] getClientMac() {
		return clientMac;
	}
	public IvParameterSpec getServerIV() {
		return serverIV;
	}
	public IvParameterSpec getClientIV() {
		return clientIV;
	}
}
