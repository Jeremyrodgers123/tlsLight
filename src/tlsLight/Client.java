package tlsLight;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.Arrays;

public class Client extends SecureCommunicator{
	
	Client() throws SignatureException{
		super("./clientPrivateKey.der", "./CASignedClientCertificate.pem", "./CAprivateKey.pem", "./CAcertificate.pem");
		msgsSofar = new ArrayList<byte []>();
	}
	ArrayList<byte []> msgsSofar;
	private byte [] nonce;
	private Certificate serverCert;
	public BigInteger serverDHPubKey;
	public byte [] serverSigniture;
	public byte [] serverAllMsgHmac;
	public byte [] allMsgHmac;
	public ObjectOutputStream objOutStream;
	public ObjectInputStream objInStream;
	

	public void setServerCert(Certificate _cert) {
		serverCert = _cert;
	}
	
	public Certificate getServerCert() {
		return serverCert;
	}
	
	public byte [] createNonce() {
		nonce = SecurityHelpers.generateRandomBytes(32);
		return nonce;
	}
	
	@Override
	public byte [] getNonce() {
		assert (nonce != null);
		return nonce;
	}
	
	public void connect(ObjectOutputStream os) {
		objOutStream = os;
	}
	
	public void connect(ObjectInputStream is) {
		objInStream = is;
	}
	
	public void dHhandshake() throws IOException, CertificateEncodingException, ClassNotFoundException, InvalidKeyException, NoSuchAlgorithmException {
		initiateConnection();
		receiveServerCredentials();
		sendCredentials();
		createSharedDHPrivateKey(serverDHPubKey);
		makeSecretKeys(getNonce(), getSharedDHPrivateKey());
		receiveAndVerifyHMacFromServer();
		sendHMacVerification();
	}
	
	public void initiateConnection() throws IOException {
		objOutStream.writeObject(createNonce());
		msgsSofar.add(getNonce());
	}
	
	public void receiveServerCredentials() throws ClassNotFoundException, IOException, CertificateEncodingException {
		Certificate serverCert = (Certificate) objInStream.readObject();
		serverDHPubKey = (BigInteger) objInStream.readObject();
		serverSigniture = (byte []) objInStream.readObject();
		setServerCert(serverCert);
		
		msgsSofar.add(serverCert.getEncoded());
		msgsSofar.add(serverDHPubKey.toByteArray());
		msgsSofar.add(serverSigniture);
	}
	
	
	public void receiveAndVerifyHMacFromServer() throws ClassNotFoundException, IOException, CertificateEncodingException, InvalidKeyException, NoSuchAlgorithmException {
		serverAllMsgHmac = (byte []) objInStream.readObject();
		byte [] expectedServerHmac = macMsgsSoFar(getServerMac(), msgsSofar);
		
		assert(Arrays.equals(serverAllMsgHmac, expectedServerHmac));
		if(!Arrays.equals(serverAllMsgHmac, expectedServerHmac)) {
			
			System.out.println("can't verify hmac of messages so far from server");
			System.exit(1);
		}
		
		msgsSofar.add(serverAllMsgHmac);
	}
	
	public void sendHMacVerification() throws IOException, InvalidKeyException, NoSuchAlgorithmException {
		allMsgHmac = macMsgsSoFar(getClientMac(), msgsSofar);
		objOutStream.writeObject(allMsgHmac);
	}
	
	public void sendCredentials() throws ClassNotFoundException, IOException, CertificateEncodingException {
		objOutStream.writeObject(getSignedCertificate());
		objOutStream.writeObject(getDHPublicKey());
		objOutStream.writeObject(getDigitalSignature());
		
		msgsSofar.add(getSignedCertificate().getEncoded());
		msgsSofar.add(getDHPublicKey().toByteArray());
		msgsSofar.add(getDigitalSignature());
	}
	
	public byte [] parseAndVerifyFile(byte [] message) throws InvalidKeyException, NoSuchAlgorithmException {
		byte [] file = SecurityHelpers.getSubArray(message, 0, message.length - 32);
		byte [] serverMac = SecurityHelpers.getSubArray(message, file.length, message.length);
		byte [] expectedMac = SecurityHelpers.hmac(getServerMac(), file);
		assert(Arrays.equals(serverMac, expectedMac));
		if(!Arrays.equals(serverMac, expectedMac)) {
			System.out.println("Message length: " + message.length);
			System.out.println("file length: " + file.length);
			System.out.println("serverMac length: " + serverMac.length);
			System.out.println("expectedMac length: " + expectedMac.length);
			System.out.println("can't verify message hmac");
			System.exit(1);
		}
		return file;
	}
	
}
