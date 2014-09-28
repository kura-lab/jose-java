package net.kuralab.sample;

import java.util.Date;

import net.kuralab.jose.JsonWebToken;

/**
 * JSON Web Token Class Sample
 * @author kura
 *
 */
public class Sample {

	public static void main(String[] args) {

		// Create JWT Object
		JsonWebToken jwt = JsonWebToken.createObjectBuilder()
				.setIssuer("example.com")
				.setAudience("client_id", "client_id2")
				.setExpiration(new Date().getTime() / 1000 + 3600)
				.setNonce("abcdefg");
		// Create JWT String
		String result = jwt.encode("secret", JsonWebToken.HS512);
		System.out.println("JSON Web Token: " + result);

		// Create JWT Object
		JsonWebToken jwt2 = new JsonWebToken(result);

		if (jwt2.verify("secret", "example.com", "client_id", "abcdefg")) {
			System.out.println("the token is valid.");
			// Decode JWT String
			jwt2.decode();
			// Get header, payload and signature
			System.out.println("header: " + jwt2.getHeader());
			System.out.println("payload: " + jwt2.getPayload());
			System.out.println("signature: " + jwt2.getSignature());
		} else {
			System.out.println("error: " + jwt2.getVerifyError());
			System.out.println("error detail: " + jwt2.getVerifyErrorDetail());
		}
	}

}
