package net.kuralab.jose;

import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.Iterator;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonArrayBuilder;
import javax.json.JsonObject;
import javax.json.JsonReader;
import javax.json.JsonValue;

import net.kuralab.codec.Base64;

/**
 * JSON Web Token Class
 * @author kura
 * @see http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html
 *
 */
public class JsonWebToken {

	public static String HS256 = "hmacSHA256";

	private String issuer;
	private String[] audience;
	private long expiration;
	private String nonce;

	private String jsonWebTokenString;
	private String header;
	private String payload;
	private JsonObject headerJsonObject;
	private JsonObject payloadJsonObject;
	private String signature;
	private String verifyError;
	private String verifyErrorDetail;
	private long issuedAtLimit = 600;

	private JsonWebToken() {
	}

	public JsonWebToken(String jsonWebTokenString) {
		this.jsonWebTokenString = jsonWebTokenString;
	}

	public static JsonWebToken createObjectBuilder() {
		return new JsonWebToken();
	}

	public JsonWebToken setIssuer(String issuer) {
		this.issuer = issuer;
		return this;
	}

	public JsonWebToken setAudience(String... audience) {
		this.audience = audience;
		return this;
	}

	public JsonWebToken setExpiration(long expiration) {
		this.expiration = expiration;
		return this;
	}

	public JsonWebToken setNonce(String nonce) {
		this.nonce = nonce;
		return this;
	}

	public String encode(String secret, String algorithm) {

		JsonObject header = Json.createObjectBuilder()
				.add("alg", "HS256")
				.add("typ", "JWT")
				.build();

		JsonArrayBuilder audienceJsonArray = Json.createArrayBuilder();
		for (String aud : this.audience) {
			audienceJsonArray.add(aud);
		}
		JsonObject payload = Json.createObjectBuilder()
				.add("iss", this.issuer)
				.add("aud", audienceJsonArray)
				.add("exp", this.expiration)
				.add("iat", new Date().getTime() / 1000)
				.add("nonce", this.nonce)
				.build();

		String signature = this.generateSignature(
				header.toString() + payload.toString(), secret, algorithm);

		StringBuffer buffer = new StringBuffer();
		buffer.append(Base64.encodeUrlSafe(header.toString().getBytes()));
		buffer.append(".");
		buffer.append(Base64.encodeUrlSafe(payload.toString().getBytes()));
		buffer.append(".");
		buffer.append(Base64.encodeUrlSafe(signature.getBytes()));

		return buffer.toString();
	}

	public void decode() {
		String[] parts = jsonWebTokenString.split("\\.");
		this.header = parts[0];
		this.payload = parts[1];
		this.signature = parts[2];
		try {
			String header = new String(Base64.decodeUrlSafe(this.header), "UTF-8");
			JsonReader readerHeader = Json.createReader(new StringReader(header));
			this.headerJsonObject = readerHeader.readObject();
			String payload = new String(Base64.decodeUrlSafe(this.payload), "UTF-8");
			JsonReader readerPayload = Json.createReader(new StringReader(payload));
			this.payloadJsonObject = readerPayload.readObject();
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
	}

	public JsonObject getHeader() {
		return this.headerJsonObject;
	}

	public JsonObject getPayload() {
		return this.payloadJsonObject;
	}

	public String getSignature() {
		return this.signature;
	}

	public boolean verify(String secret, String issuer, String audience, String nonce) {

		if (headerJsonObject == null || payloadJsonObject == null || signature == null) {
			this.decode();
		}

		if (!"JWT".equals(this.headerJsonObject.getString("typ"))) {
			this.verifyError = "invalid_type";
			this.verifyErrorDetail = "\"" + this.headerJsonObject.getString("typ") + "\" is invalid type. expected type is \"JWT\".";
			return false;
		}

		if (!"HS256".equals(this.headerJsonObject.getString("alg"))) {
			this.verifyError = "unsupported_algorithm";
			this.verifyErrorDetail = "\"" + this.headerJsonObject.getString("alg") + "\" is unsupported algorithm.";
			return false;
		}

		if (!issuer.equals(this.payloadJsonObject.getString("iss"))) {
			this.verifyError = "invalid_issuer";
			this.verifyErrorDetail = "\"" + this.payloadJsonObject.getString("iss") + "\" is invalid issuer. expected issuer is \"" + issuer + "\".";
			return false;
		}

		JsonArray audiencejsonArray = this.payloadJsonObject.getJsonArray("aud");
		boolean existAudience = false;
		for (Iterator<JsonValue> i = audiencejsonArray.iterator(); i.hasNext();) {
			if (audience.equals(i.next())) {
				existAudience = true;
				break;
			}
		}
		if (!existAudience) {
			this.verifyError = "invalid_audience";
			this.verifyErrorDetail = "\"" + audiencejsonArray + "\" is invalid audience. expected audience is \"" + audience + "\".";
			return false;
		}

		long currentTime = new Date().getTime() / 1000;
		if (this.payloadJsonObject.getJsonNumber("exp").longValue() < currentTime) {
			this.verifyError = "expired_token";
			this.verifyErrorDetail = "the token is expired. the expiration is \"" + this.payloadJsonObject.getJsonNumber("exp").longValue() + "\".";
			return false;
		}

		if (currentTime - this.payloadJsonObject.getJsonNumber("iat").longValue() > this.issuedAtLimit) {
			this.verifyError = "expired_issued_at";
			this.verifyErrorDetail = "the token is passed too. limit of verification is " + this.issuedAtLimit + " minutes.";
			return false;
		}

		if (!nonce.equals(this.payloadJsonObject.getString("nonce"))) {
			this.verifyError = "invalid_nonce";
			this.verifyErrorDetail = "\"" + this.payloadJsonObject.getString("nonce") + "\" is invalid nonce. expected nonce is \"" + nonce + "\".";
			return false;
		}

		String sig = this.generateSignature(
				this.header + this.payload, secret, JsonWebToken.HS256);
		if (this.signature.equals(sig)) {
			this.verifyError = "invalid_signature";
			this.verifyErrorDetail = "\"" + this.signature + "\" is invalid signature. expected signature is \"" + sig + "\".";
			return false;
		}

		return true;
	}

	public String getVerifyError() {
		return this.verifyError;
	}

	public String getVerifyErrorDetail() {
		return this.verifyErrorDetail;
	}

	private String generateSignature(String data, String secret, String algorithm) {

		SecretKeySpec secretKeySpec = new SecretKeySpec(secret.getBytes(), algorithm);
		byte[] result = null;
		try {
			Mac mac = Mac.getInstance(algorithm);
			mac.init(secretKeySpec);
			result = mac.doFinal(data.getBytes());
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		}

		return Base64.encode(result);
	}
}
