package tlsLight;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.junit.Assert;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;



class testSecurityHelpers {
	Server server;
	Client client;
	@BeforeEach
	void setUp() throws Exception {
		server = new Server();
		client = new Client();
		client.createSharedDHPrivateKey(server.getDHPublicKey());
		server.createSharedDHPrivateKey(client.getDHPublicKey());
	}

	@AfterEach
	void tearDown() throws Exception {
	}

	@Test
	void testCopyArr() {
		byte [] start = new byte [] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
		byte [] end = new byte [] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
		byte [] newArr = new byte [21];
		SecurityHelpers.copyBytes(start, newArr, 0);
		Assert.assertEquals(1, newArr[0]);
		Assert.assertEquals(0, newArr[10]);
		SecurityHelpers.copyBytes(end, newArr, start.length);
		Assert.assertEquals(1, newArr[10]);
	}
	@Test
	void testmakeSecretKeys() {
		BigInteger clientDHSharedPrivateKey = client.getSharedDHPrivateKey();
		BigInteger serverDHSharedPrivateKey = client.getSharedDHPrivateKey();
		
		Assert.assertArrayEquals(clientDHSharedPrivateKey.toByteArray(), serverDHSharedPrivateKey.toByteArray());
		try {
			client.makeSecretKeys(client.createNonce(), clientDHSharedPrivateKey);
			server.makeSecretKeys(client.getNonce(), serverDHSharedPrivateKey);
		} catch (InvalidKeyException | NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		Assert.assertArrayEquals(client.getServerEncrypt(), server.getServerEncrypt());
		Assert.assertArrayEquals(client.getClientEncrypt(), server.getClientEncrypt());
		Assert.assertArrayEquals(client.getServerMac(), server.getServerMac());
		Assert.assertArrayEquals(client.getClientMac(), server.getClientMac());
		Assert.assertArrayEquals(client.getServerIV().getIV(), server.getServerIV().getIV());
		Assert.assertArrayEquals(client.getClientIV().getIV(), server.getClientIV().getIV());
	}
	
	@Test
	void testGetSubArray() {
		byte [] original = new byte [] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
		byte [] newArr = SecurityHelpers.getSubArray(original, 0, 5);
		byte [] expected = new byte [] {1,2,3,4,5};
		Assert.assertArrayEquals(expected, newArr);
	}
	
	@Test
	void testCypher() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		BigInteger clientDHSharedPrivateKey = client.getSharedDHPrivateKey();
		BigInteger serverDHSharedPrivateKey = client.getSharedDHPrivateKey();
		Assert.assertArrayEquals(clientDHSharedPrivateKey.toByteArray(), serverDHSharedPrivateKey.toByteArray());
		try {
			client.makeSecretKeys(client.createNonce(), clientDHSharedPrivateKey);
			server.makeSecretKeys(client.getNonce(), serverDHSharedPrivateKey);
		} catch (InvalidKeyException | NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		byte [] encryptedMsg = SecurityHelpers.encryptMessage(client.getClientEncrypt(), client.getClientMac(), client.getClientIV(), client.readInFile("./AdventureofHuckleberryFinn.txt"));
		byte [] decryptedMsg = SecurityHelpers.decryptMessage(server.getClientEncrypt(), server.getClientMac(), server.getClientIV(), encryptedMsg);
		Assert.assertArrayEquals(client.readInFile("./AdventureofHuckleberryFinn.txt"), decryptedMsg);
	}
	
	
	

}
