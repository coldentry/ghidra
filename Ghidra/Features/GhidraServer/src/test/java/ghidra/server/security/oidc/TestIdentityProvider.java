/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.server.security.oidc;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

import com.google.gson.*;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

/**
 * Minimal in-process OIDC identity provider used for testing.  Serves a discovery document
 * and JWKS over http on the loopback interface and signs ID tokens.
 */
public class TestIdentityProvider implements AutoCloseable {

	public record SigningKey(String kid, String alg, KeyPair keyPair) {
	}

	private final HttpServer server;
	private final String issuer;
	private final List<SigningKey> publishedKeys = Collections.synchronizedList(new ArrayList<>());
	public final AtomicInteger jwksRequestCount = new AtomicInteger();

	public TestIdentityProvider() throws IOException {
		server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
		issuer = "http://127.0.0.1:" + server.getAddress().getPort() + "/realms/test";
		server.createContext("/realms/test/.well-known/openid-configuration",
			ex -> sendJson(ex, discovery()));
		server.createContext("/realms/test/jwks", ex -> {
			jwksRequestCount.incrementAndGet();
			sendJson(ex, jwks());
		});
		server.start();
	}

	public String getIssuer() {
		return issuer;
	}

	@Override
	public void close() {
		server.stop(0);
	}

	public void publish(SigningKey key) {
		publishedKeys.add(key);
	}

	public void unpublishAll() {
		publishedKeys.clear();
	}

	private JsonObject discovery() {
		JsonObject obj = new JsonObject();
		obj.addProperty("issuer", issuer);
		obj.addProperty("authorization_endpoint", issuer + "/protocol/openid-connect/auth");
		obj.addProperty("token_endpoint", issuer + "/protocol/openid-connect/token");
		obj.addProperty("jwks_uri", issuer + "/jwks");
		return obj;
	}

	private JsonObject jwks() {
		JsonArray keys = new JsonArray();
		synchronized (publishedKeys) {
			for (SigningKey k : publishedKeys) {
				keys.add(toJwk(k));
			}
		}
		JsonObject obj = new JsonObject();
		obj.add("keys", keys);
		return obj;
	}

	private static void sendJson(HttpExchange ex, JsonObject obj) throws IOException {
		byte[] bytes = obj.toString().getBytes(StandardCharsets.UTF_8);
		ex.getResponseHeaders().set("Content-Type", "application/json");
		ex.sendResponseHeaders(200, bytes.length);
		try (OutputStream out = ex.getResponseBody()) {
			out.write(bytes);
		}
	}

	public static JsonObject toJwk(SigningKey k) {
		JsonObject jwk = new JsonObject();
		jwk.addProperty("kid", k.kid());
		jwk.addProperty("use", "sig");
		jwk.addProperty("alg", k.alg());
		PublicKey pub = k.keyPair().getPublic();
		if (pub instanceof RSAPublicKey rsa) {
			jwk.addProperty("kty", "RSA");
			jwk.addProperty("n", b64(unsigned(rsa.getModulus())));
			jwk.addProperty("e", b64(unsigned(rsa.getPublicExponent())));
		}
		else if (pub instanceof ECPublicKey ec) {
			int bits = ec.getParams().getCurve().getField().getFieldSize();
			int len = (bits + 7) / 8;
			jwk.addProperty("kty", "EC");
			jwk.addProperty("crv", bits == 256 ? "P-256" : bits == 384 ? "P-384" : "P-521");
			jwk.addProperty("x", b64(pad(unsigned(ec.getW().getAffineX()), len)));
			jwk.addProperty("y", b64(pad(unsigned(ec.getW().getAffineY()), len)));
		}
		return jwk;
	}

	public static SigningKey rsaKey(String kid, String alg) throws GeneralSecurityException {
		KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
		gen.initialize(2048);
		return new SigningKey(kid, alg, gen.generateKeyPair());
	}

	public static SigningKey ecKey(String kid, String alg, String stdCurve)
			throws GeneralSecurityException {
		KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
		gen.initialize(new ECGenParameterSpec(stdCurve));
		return new SigningKey(kid, alg, gen.generateKeyPair());
	}

	/**
	 * Produce compact JWS.
	 * @param header JWS header
	 * @param claims claims
	 * @param key signing key
	 * @return compact JWS
	 * @throws GeneralSecurityException if signing fails
	 */
	public static String sign(JsonObject header, JsonObject claims, SigningKey key)
			throws GeneralSecurityException {
		String signingInput = b64(header.toString().getBytes(StandardCharsets.UTF_8)) + "." +
			b64(claims.toString().getBytes(StandardCharsets.UTF_8));
		String alg = header.get("alg").getAsString();
		Signature sig;
		switch (alg) {
			case "RS256" -> sig = Signature.getInstance("SHA256withRSA");
			case "PS256" -> {
				sig = Signature.getInstance("RSASSA-PSS");
				sig.setParameter(new PSSParameterSpec("SHA-256", "MGF1",
					MGF1ParameterSpec.SHA256, 32, 1));
			}
			case "ES256" -> sig = Signature.getInstance("SHA256withECDSAinP1363Format");
			case "ES384" -> sig = Signature.getInstance("SHA384withECDSAinP1363Format");
			default -> throw new IllegalArgumentException(alg);
		}
		sig.initSign(key.keyPair().getPrivate());
		sig.update(signingInput.getBytes(StandardCharsets.US_ASCII));
		return signingInput + "." + b64(sig.sign());
	}

	public static JsonObject header(String alg, String kid) {
		JsonObject h = new JsonObject();
		h.addProperty("alg", alg);
		h.addProperty("typ", "JWT");
		if (kid != null) {
			h.addProperty("kid", kid);
		}
		return h;
	}

	public JsonObject claims(String audience, String nonce, String username) {
		long now = System.currentTimeMillis() / 1000;
		JsonObject c = new JsonObject();
		c.addProperty("iss", issuer);
		c.addProperty("sub", "f1b2c3d4-0000-1111-2222-333344445555");
		c.addProperty("aud", audience);
		c.addProperty("exp", now + 300);
		c.addProperty("iat", now);
		c.addProperty("nonce", nonce);
		c.addProperty("preferred_username", username);
		return c;
	}

	public static String b64(byte[] bytes) {
		return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
	}

	private static byte[] unsigned(BigInteger v) {
		byte[] b = v.toByteArray();
		if (b.length > 1 && b[0] == 0) {
			return Arrays.copyOfRange(b, 1, b.length);
		}
		return b;
	}

	private static byte[] pad(byte[] b, int len) {
		if (b.length >= len) {
			return b;
		}
		byte[] out = new byte[len];
		System.arraycopy(b, 0, out, len - b.length, b.length);
		return out;
	}
}
