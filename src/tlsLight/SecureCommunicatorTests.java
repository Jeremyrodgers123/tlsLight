package tlsLight;


import org.junit.Assert;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;



class SecureCommunicatorTests {
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
	void testFileUpload() {
		String pathName = "./AdventureofHuckleberryFinn.txt";
		byte [] file = client.readInFile(pathName);
		Assert.assertNotNull(file);
	}

}
