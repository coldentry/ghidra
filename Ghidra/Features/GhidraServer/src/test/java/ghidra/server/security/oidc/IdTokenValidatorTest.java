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

import static ghidra.server.security.oidc.TestIdentityProvider.*;
import static org.junit.Assert.*;

import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.*;
import java.util.Properties;

import javax.security.auth.login.FailedLoginException;

import org.junit.*;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import generic.test.AbstractGenericTest;

public class IdTokenValidatorTest extends AbstractGenericTest {

	private static final String CLIENT_ID = "ghidra-server";
	private static final String NONCE = "test-nonce-value";

	private static SigningKey rsaKey;
	private static SigningKey psKey;
	private static SigningKey ecKey;
	private static SigningKey otherRsaKey;

	private TestIdentityProvider idp;
	private MutableClock clock;
	private IdTokenValidator validator;

	static class MutableClock extends Clock {
		long millis = System.currentTimeMillis();

		@Override
		public ZoneId getZone() {
			return ZoneOffset.UTC;
		}

		@Override
		public Clock withZone(ZoneId zone) {
			return this;
		}

		@Override
		public Instant instant() {
			return Instant.ofEpochMilli(millis);
		}

		@Override
		public long millis() {
			return millis;
		}
	}

	@BeforeClass
	public static void generateKeys() throws Exception {
		rsaKey = rsaKey("rsa1", "RS256");
		psKey = rsaKey("ps1", "PS256");
		ecKey = ecKey("ec1", "ES256", "secp256r1");
		otherRsaKey = rsaKey("rsa1", "RS256"); // same kid, different key
	}

	@Before
	public void setUp() throws Exception {
		idp = new TestIdentityProvider();
		idp.publish(rsaKey);
		idp.publish(psKey);
		idp.publish(ecKey);
		clock = new MutableClock();
		validator = createValidator(new Properties());
	}

	@After
	public void tearDown() {
		idp.close();
	}

	private IdTokenValidator createValidator(Properties extra) {
		Properties props = new Properties();
		props.setProperty(OIDCConfiguration.ISSUER, idp.getIssuer());
		props.setProperty(OIDCConfiguration.CLIENT_ID, CLIENT_ID);
		props.putAll(extra);
		OIDCConfiguration config = new OIDCConfiguration(props);
		OIDCProvider provider =
			new OIDCProvider(config.getIssuer(), HttpClient.newHttpClient(), clock);
		return new IdTokenValidator(config, provider, clock);
	}

	private JsonObject claims() {
		return idp.claims(CLIENT_ID, NONCE, "alice");
	}

	private void assertRejected(String token, String expectedMessagePart) throws Exception {
		try {
			validator.validate(token, NONCE);
			fail("Expected token to be rejected: " + expectedMessagePart);
		}
		catch (FailedLoginException e) {
			assertTrue("Unexpected message: " + e.getMessage(),
				e.getMessage().contains(expectedMessagePart));
		}
	}

	@Test
	public void testValidRS256() throws Exception {
		String token = sign(header("RS256", "rsa1"), claims(), rsaKey);
		JsonObject c = validator.validate(token, NONCE);
		assertEquals("alice", c.get("preferred_username").getAsString());
	}

	@Test
	public void testValidPS256() throws Exception {
		validator.validate(sign(header("PS256", "ps1"), claims(), psKey), NONCE);
	}

	@Test
	public void testValidES256() throws Exception {
		validator.validate(sign(header("ES256", "ec1"), claims(), ecKey), NONCE);
	}

	@Test
	public void testNoKidSingleCandidate() throws Exception {
		// only one EC P-256 key is published so kid may be omitted
		validator.validate(sign(header("ES256", null), claims(), ecKey), NONCE);
	}

	@Test
	public void testBadSignature() throws Exception {
		assertRejected(sign(header("RS256", "rsa1"), claims(), otherRsaKey), "signature");
	}

	@Test
	public void testTamperedPayload() throws Exception {
		String token = sign(header("RS256", "rsa1"), claims(), rsaKey);
		String[] parts = token.split("\\.");
		JsonObject c = claims();
		c.addProperty("preferred_username", "admin");
		String tampered =
			parts[0] + "." + b64(c.toString().getBytes(StandardCharsets.UTF_8)) + "." + parts[2];
		assertRejected(tampered, "signature");
	}

	@Test
	public void testAlgNoneRejected() throws Exception {
		JsonObject h = header("none", null);
		String token = b64(h.toString().getBytes(StandardCharsets.UTF_8)) + "." +
			b64(claims().toString().getBytes(StandardCharsets.UTF_8)) + ".";
		assertRejected(token, "encoding"); // empty signature
		String token2 = b64(h.toString().getBytes(StandardCharsets.UTF_8)) + "." +
			b64(claims().toString().getBytes(StandardCharsets.UTF_8)) + ".AAAA";
		assertRejected(token2, "algorithm not allowed");
	}

	@Test
	public void testHS256Rejected() throws Exception {
		JsonObject h = header("HS256", "rsa1");
		String token = b64(h.toString().getBytes(StandardCharsets.UTF_8)) + "." +
			b64(claims().toString().getBytes(StandardCharsets.UTF_8)) + ".AAAA";
		assertRejected(token, "algorithm not allowed");
	}

	@Test
	public void testAlgorithmNotInAllowList() throws Exception {
		Properties p = new Properties();
		p.setProperty(OIDCConfiguration.ALLOWED_ALGORITHMS, "RS256");
		validator = createValidator(p);
		assertRejected(sign(header("ES256", "ec1"), claims(), ecKey), "algorithm not allowed");
	}

	@Test
	public void testKeyTypeAlgorithmMismatch() throws Exception {
		// ES256 header referencing an RSA key ID must not be accepted
		assertRejected(sign(header("ES256", "rsa1"), claims(), ecKey), "No identity provider");
	}

	@Test
	public void testCritHeaderRejected() throws Exception {
		JsonObject h = header("RS256", "rsa1");
		JsonArray crit = new JsonArray();
		crit.add("exp");
		h.add("crit", crit);
		assertRejected(sign(h, claims(), rsaKey), "critical");
	}

	@Test
	public void testWrongIssuer() throws Exception {
		JsonObject c = claims();
		c.addProperty("iss", "https://evil.example.com/realms/test");
		assertRejected(sign(header("RS256", "rsa1"), c, rsaKey), "issuer");
	}

	@Test
	public void testWrongAudience() throws Exception {
		JsonObject c = claims();
		c.addProperty("aud", "some-other-client");
		assertRejected(sign(header("RS256", "rsa1"), c, rsaKey), "audience");
	}

	@Test
	public void testMultipleAudiencesRequireAzp() throws Exception {
		JsonObject c = claims();
		JsonArray aud = new JsonArray();
		aud.add(CLIENT_ID);
		aud.add("account");
		c.add("aud", aud);
		assertRejected(sign(header("RS256", "rsa1"), c, rsaKey), "azp");

		c.addProperty("azp", "account");
		assertRejected(sign(header("RS256", "rsa1"), c, rsaKey), "authorized party");

		c.addProperty("azp", CLIENT_ID);
		validator.validate(sign(header("RS256", "rsa1"), c, rsaKey), NONCE);
	}

	@Test
	public void testExpired() throws Exception {
		JsonObject c = claims();
		c.addProperty("exp", clock.millis() / 1000 - 600);
		assertRejected(sign(header("RS256", "rsa1"), c, rsaKey), "expired");
	}

	@Test
	public void testExpiredWithinSkewAccepted() throws Exception {
		JsonObject c = claims();
		c.addProperty("exp", clock.millis() / 1000 - 60); // default skew 120s
		validator.validate(sign(header("RS256", "rsa1"), c, rsaKey), NONCE);
	}

	@Test
	public void testNotYetValid() throws Exception {
		JsonObject c = claims();
		c.addProperty("nbf", clock.millis() / 1000 + 600);
		assertRejected(sign(header("RS256", "rsa1"), c, rsaKey), "not yet valid");
	}

	@Test
	public void testIssuedInFuture() throws Exception {
		JsonObject c = claims();
		c.addProperty("iat", clock.millis() / 1000 + 600);
		assertRejected(sign(header("RS256", "rsa1"), c, rsaKey), "future");
	}

	@Test
	public void testMissingExp() throws Exception {
		JsonObject c = claims();
		c.remove("exp");
		assertRejected(sign(header("RS256", "rsa1"), c, rsaKey), "'exp'");
	}

	@Test
	public void testNonceMismatch() throws Exception {
		JsonObject c = claims();
		c.addProperty("nonce", "other");
		assertRejected(sign(header("RS256", "rsa1"), c, rsaKey), "nonce");
		c.remove("nonce");
		assertRejected(sign(header("RS256", "rsa1"), c, rsaKey), "nonce");
	}

	@Test
	public void testMalformed() throws Exception {
		assertRejected("abc", "compact JWS");
		assertRejected("a.b.c.d", "compact JWS");
		assertRejected("!!!.e30.AAAA", "encoding");
		assertRejected(b64("[]".getBytes()) + ".e30.AAAA", "JSON object");
	}

	@Test
	public void testKeyRotation() throws Exception {
		validator.validate(sign(header("RS256", "rsa1"), claims(), rsaKey), NONCE);
		assertEquals(1, idp.jwksRequestCount.get());

		SigningKey rotated = rsaKey("rsa2", "RS256");
		idp.publish(rotated);
		String token = sign(header("RS256", "rsa2"), claims(), rotated);

		// Within minimum refresh interval unknown kid does not trigger refresh
		clock.millis += 1000;
		assertRejected(token, "No identity provider signing key");
		assertEquals(1, idp.jwksRequestCount.get());

		// After minimum refresh interval unknown kid triggers refresh
		clock.millis += JwksKeyCache.MIN_REFRESH_INTERVAL_MS;
		validator.validate(sign(header("RS256", "rsa2"), claims(), rotated), NONCE);
		assertEquals(2, idp.jwksRequestCount.get());
	}

	@Test
	public void testRemovedKeyRejectedAfterCacheExpiry() throws Exception {
		validator.validate(sign(header("RS256", "rsa1"), claims(), rsaKey), NONCE);
		idp.unpublishAll();
		idp.publish(ecKey);
		clock.millis += JwksKeyCache.CACHE_TTL_MS + 1000;
		assertRejected(sign(header("RS256", "rsa1"), claims(), rsaKey),
			"No identity provider signing key");
	}

	@Test
	public void testDiscoveryIssuerMismatch() throws Exception {
		Properties props = new Properties();
		props.setProperty(OIDCConfiguration.ISSUER, idp.getIssuer() + "/");
		props.setProperty(OIDCConfiguration.CLIENT_ID, CLIENT_ID);
		OIDCConfiguration config = new OIDCConfiguration(props);
		OIDCProvider provider =
			new OIDCProvider(config.getIssuer(), HttpClient.newHttpClient(), clock);
		try {
			provider.discover();
			fail("Expected discovery failure");
		}
		catch (java.io.IOException e) {
			assertTrue(e.getMessage().contains("issuer mismatch"));
		}
	}
}
