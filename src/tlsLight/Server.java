package tlsLight;

import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.Arrays;

public class Server extends SecureCommunicator {
	
	Server() throws SignatureException{
		super("./serverPrivateKey.der", "./CASignedServerCertificate.pem", "./CAprivateKey.pem", "./CAcertificate.pem");
		
	}
	
	private byte [] clientNonce;
	private Certificate clientCertificate;
	public BigInteger clientDHPubKey;
	public byte [] clientSignature;
	public byte [] allMsgHmac;
	public byte [] clientAllMsgHmac;
	
	public void setClientNonce(byte [] _nonce) {
		clientNonce = _nonce;
	}
	
	public byte [] getClientNonce() {
		return clientNonce;
	}
	
	public void setclientCert(Certificate _cert) {
		clientCertificate = _cert;
	}
	
	public Certificate getClientCert() {
		return clientCertificate;
	}
	
	public void run(int port) throws IOException{
		ServerSocket serverSocket = new ServerSocket(8080);
		while(true) {
			Socket socket = serverSocket.accept();
			
			Thread thread = new Thread(()-> {
				ArrayList<byte []> msgsSofar = new ArrayList<byte []>();
				try {
					InputStream iStream = socket.getInputStream();
					ObjectInputStream objInStream = new ObjectInputStream(iStream);
					OutputStream outputStream = socket.getOutputStream();
					ObjectOutputStream objOutStream = new ObjectOutputStream(outputStream);
					
					byte [] nonce = (byte [])  objInStream.readObject();
					setClientNonce(nonce);
					msgsSofar.add(nonce);
					
					objOutStream.writeObject(getSignedCertificate());
					objOutStream.writeObject(getDHPublicKey());
					objOutStream.writeObject(getDigitalSignature());
					
					msgsSofar.add(getSignedCertificate().getEncoded());
					msgsSofar.add(getDHPublicKey().toByteArray());
					msgsSofar.add(getDigitalSignature());
					
					/** RECIEVE 3RD MESSAGE **/
					Certificate clientCert = (Certificate) objInStream.readObject();
					clientDHPubKey = (BigInteger) objInStream.readObject();
					clientSignature = (byte []) objInStream.readObject();
					setclientCert(clientCert);
					msgsSofar.add(clientCert.getEncoded());
					msgsSofar.add(clientDHPubKey.toByteArray());
					msgsSofar.add(clientSignature);
				
					createSharedDHPrivateKey(clientDHPubKey);
					makeSecretKeys(getClientNonce(), getSharedDHPrivateKey());
					allMsgHmac = macMsgsSoFar(getServerMac(), msgsSofar);
					objOutStream.writeObject(allMsgHmac);
					msgsSofar.add(allMsgHmac);
					clientAllMsgHmac = ( byte [] ) objInStream.readObject();
					byte [] expectedMsgsSoFarMac = macMsgsSoFar(getClientMac(), msgsSofar);
					if(!Arrays.equals(clientAllMsgHmac, expectedMsgsSoFarMac)) {
						System.out.println("client all message HMAC was different than expected");
						System.exit(1);
					}else {
						System.out.println("HANDSHAKE COMPLETED SUCCESSFULLY");
					}
					
					byte [] fileBytes = readInFile("./bayOfFundy.jpg");
					byte [] fileHmac = SecurityHelpers.hmac(getServerMac(), fileBytes);
					byte [] filePayload = SecurityHelpers.joinArrays(fileBytes, fileHmac);
					objOutStream.writeObject(filePayload);
				} catch (IOException | ClassNotFoundException | InvalidKeyException | NoSuchAlgorithmException | CertificateEncodingException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			});//End of Thread
			thread.start();
		}
	}

//	@Override
//	public void dHhandshake() {
//	}

	@Override
	public byte[] getNonce() {
		assert (clientNonce != null);
		return clientNonce;
	}

}

