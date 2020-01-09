package tlsLight;

import java.io.IOException;
import java.security.SignatureException;

public class Main {


	public static void main(String[] args) throws IOException, SignatureException {	
		Server server = new Server();
		server.run(8080);
	}
}
