package tlsLight;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;


public class clientProcess {

	public static void main(String[] args) throws UnknownHostException, IOException, ClassNotFoundException, SignatureException, InvalidKeyException, NoSuchAlgorithmException, CertificateEncodingException {
		Client client = new Client();
		Socket socket = new Socket( InetAddress.getByName("localhost"), 8080);
		OutputStream outStream = socket.getOutputStream();
		ObjectOutputStream objOutStream = new ObjectOutputStream(outStream);
		InputStream inStream = socket.getInputStream();
		ObjectInputStream objInStream = new ObjectInputStream(inStream);
		
		client.connect(objInStream);
		client.connect(objOutStream);
		client.dHhandshake();
		byte [] payload = (byte []) objInStream.readObject();
		byte [] file = client.parseAndVerifyFile(payload);
		File transferedFile = new File("./transferedFile.jpg");
		FileOutputStream fos = new FileOutputStream(transferedFile);
		System.out.println("File received");
		fos.write(file);
		fos.close();
		socket.close();
	}

}
