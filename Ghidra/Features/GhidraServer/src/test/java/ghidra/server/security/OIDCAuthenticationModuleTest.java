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
package ghidra.server.security;

import static ghidra.server.security.oidc.TestIdentityProvider.*;
import static org.junit.Assert.*;

import java.net.http.HttpClient;
import java.time.Clock;
import java.util.Properties;

import javax.security.auth.callback.Callback;
import javax.security.auth.login.FailedLoginException;

import org.junit.*;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import generic.test.AbstractGenericTest;
import ghidra.framework.remote.OIDCCallback;
import ghidra.server.security.oidc.*;
import ghidra.server.security.oidc.TestIdentityProvider.SigningKey;

public class OIDCAuthenticationModuleTest extends AbstractGenericTest {

	private static final String CLIENT_ID = "ghidra-server";

	private static SigningKey key;

	private TestIdentityProvider idp;

	@BeforeClass
	public static void generateKeys() throws Exception {
		key = rsaKey("k1", "RS256");
	}

	@Before
	public void setUp() throws Exception {
		idp = new TestIdentityProvider();
		idp.publish(key);
	}

	@After
	public void tearDown() {
		idp.close();
	}

	private OIDCAuthenticationModule createModule(String... extraProps) throws Exception {
		Properties props = new Properties();
		props.setProperty(OIDCConfiguration.ISSUER, idp.getIssuer());
		props.setProperty(OIDCConfiguration.CLIENT_ID, CLIENT_ID);
		for (int i = 0; i < extraProps.length; i += 2) {
			props.setProperty(extraProps[i], extraProps[i + 1]);
		}
		OIDCConfiguration config = new OIDCConfiguration(props);
		Clock clock = Clock.systemUTC();
		OIDCProvider provider =
			new OIDCProvider(config.getIssuer(), HttpClient.newHttpClient(), clock);
		return new OIDCAuthenticationModule(config, provider, clock);
	}

	private OIDCCallback getCallback(OIDCAuthenticationModule module) {
		Callback[] callbacks = module.getAuthenticationCallbacks();
		assertEquals(1, callbacks.length);
		return (OIDCCallback) callbacks[0];
	}

	private String login(OIDCAuthenticationModule module, JsonObject claims) throws Exception {
		OIDCCallback cb = getCallback(module);
		claims.addProperty("nonce", cb.getNonce());
		cb.setIdToken(sign(header("RS256", "k1"), claims, key));
		return module.authenticate(null, null, new Callback[] { cb });
	}

	private JsonObject claims(String username) {
		return idp.claims(CLIENT_ID, null, username);
	}

	private void assertLoginFails(OIDCAuthenticationModule module, JsonObject claims,
			String expectedMessagePart) throws Exception {
		try {
			String user = login(module, claims);
			fail("Expected login failure but authenticated as " + user);
		}
		catch (FailedLoginException e) {
			assertTrue("Unexpected message: " + e.getMessage(),
				e.getMessage().contains(expectedMessagePart));
		}
	}

	@Test
	public void testCallbackContents() throws Exception {
		OIDCAuthenticationModule module =
			createModule(OIDCConfiguration.REDIRECT_PORT, "8400", OIDCConfiguration.AUTH_PARAMS,
				"prompt=select_account");
		OIDCCallback cb = getCallback(module);
		assertEquals(idp.getIssuer(), cb.getIssuer());
		assertEquals(CLIENT_ID, cb.getClientId());
		assertEquals("openid profile email", cb.getScope());
		assertEquals(8400, cb.getRedirectPort());
		assertEquals("prompt=select_account", cb.getAuthParams());
		assertEquals(300, cb.getLoginTimeoutSeconds());
		assertNotNull(cb.getNonce());
		assertFalse(module.isNameCallbackAllowed());
		assertFalse(module.anonymousCallbacksAllowed());
	}

	@Test
	public void testLoginAndReplay() throws Exception {
		OIDCAuthenticationModule module = createModule();
		OIDCCallback cb = getCallback(module);
		JsonObject c = claims("alice");
		c.addProperty("nonce", cb.getNonce());
		cb.setIdToken(sign(header("RS256", "k1"), c, key));

		assertEquals("alice", module.authenticate(null, null, new Callback[] { cb }));

		// same callback/ID token may not be reused
		try {
			module.authenticate(null, null, new Callback[] { cb });
			fail("Expected replay to fail");
		}
		catch (FailedLoginException e) {
			assertTrue(e.getMessage().contains("reused"));
		}
	}

	@Test
	public void testIdTokenBoundToCallback() throws Exception {
		OIDCAuthenticationModule module = createModule();
		OIDCCallback cb1 = getCallback(module);
		OIDCCallback cb2 = getCallback(module);
		JsonObject c = claims("alice");
		c.addProperty("nonce", cb1.getNonce());
		// ID token for cb1 returned with cb2
		cb2.setIdToken(sign(header("RS256", "k1"), c, key));
		try {
			module.authenticate(null, null, new Callback[] { cb2 });
			fail("Expected nonce mismatch");
		}
		catch (FailedLoginException e) {
			assertTrue(e.getMessage().contains("nonce"));
		}
	}

	@Test
	public void testUnissuedTokenRejected() throws Exception {
		OIDCAuthenticationModule module = createModule();
		byte[] forged = new byte[64];
		OIDCCallback cb = new OIDCCallback(idp.getIssuer(), CLIENT_ID, "openid", null, 0, 300,
			forged);
		JsonObject c = claims("alice");
		c.addProperty("nonce", cb.getNonce());
		cb.setIdToken(sign(header("RS256", "k1"), c, key));
		try {
			module.authenticate(null, null, new Callback[] { cb });
			fail("Expected failure");
		}
		catch (FailedLoginException e) {
			assertTrue(e.getMessage().contains("Stale or reused"));
		}
	}

	@Test
	public void testMissingIdToken() throws Exception {
		OIDCAuthenticationModule module = createModule();
		OIDCCallback cb = getCallback(module);
		try {
			module.authenticate(null, null, new Callback[] { cb });
			fail("Expected failure");
		}
		catch (FailedLoginException e) {
			assertTrue(e.getMessage().contains("missing"));
		}
		try {
			module.authenticate(null, null, new Callback[0]);
			fail("Expected failure");
		}
		catch (FailedLoginException e) {
			assertTrue(e.getMessage().contains("callback not found"));
		}
	}

	@Test
	public void testStripDomainAndLowercase() throws Exception {
		assertEquals("alice.smith", login(createModule(), claims("Alice.Smith@Contoso.com")));
	}

	@Test
	public void testNoLowercase() throws Exception {
		assertEquals("Alice",
			login(createModule(OIDCConfiguration.LOWERCASE_USERNAME, "false"),
				claims("Alice@contoso.com")));
	}

	@Test
	public void testNoStripDomainInvalidName() throws Exception {
		assertLoginFails(createModule(OIDCConfiguration.STRIP_DOMAIN, "false"),
			claims("alice@contoso.com"), "not a valid Ghidra user name");
	}

	@Test
	public void testInvalidUserName() throws Exception {
		assertLoginFails(createModule(), claims("alice smith"), "not a valid Ghidra user name");
		assertLoginFails(createModule(), claims("../etc"), "not a valid Ghidra user name");
	}

	@Test
	public void testAllowedDomains() throws Exception {
		OIDCAuthenticationModule module =
			createModule(OIDCConfiguration.ALLOWED_DOMAINS, "contoso.com, fabrikam.com");
		assertEquals("bob", login(module, claims("bob@CONTOSO.com")));
		assertEquals("eve", login(module, claims("eve@fabrikam.com")));
		assertLoginFails(module, claims("mallory@evil.com"), "domain not allowed");
		assertLoginFails(module, claims("nodomain"), "domain not allowed");
		assertLoginFails(module, claims("x@contoso.com.evil.com"), "domain not allowed");
	}

	@Test
	public void testCustomUsernameClaim() throws Exception {
		OIDCAuthenticationModule module =
			createModule(OIDCConfiguration.USERNAME_CLAIM, "email");
		JsonObject c = claims("ignored");
		c.addProperty("email", "carol@example.com");
		assertEquals("carol", login(module, c));

		assertLoginFails(module, claims("alice"), "lacks 'email' claim");
	}

	@Test
	public void testRequiredClaimArray() throws Exception {
		OIDCAuthenticationModule module = createModule(OIDCConfiguration.REQUIRED_CLAIM,
			"roles", OIDCConfiguration.REQUIRED_CLAIM_VALUES, "Ghidra.User,Ghidra.Admin");
		JsonObject c = claims("alice");
		JsonArray roles = new JsonArray();
		roles.add("Other");
		roles.add("Ghidra.User");
		c.add("roles", roles);
		assertEquals("alice", login(module, c));

		JsonObject c2 = claims("bob");
		JsonArray roles2 = new JsonArray();
		roles2.add("Other");
		c2.add("roles", roles2);
		assertLoginFails(module, c2, "required 'roles'");

		assertLoginFails(module, claims("carol"), "required 'roles'");
	}

	@Test
	public void testRequiredClaimNestedPath() throws Exception {
		OIDCAuthenticationModule module = createModule(OIDCConfiguration.REQUIRED_CLAIM,
			"realm_access.roles", OIDCConfiguration.REQUIRED_CLAIM_VALUES, "ghidra-user");
		JsonObject c = claims("alice");
		JsonObject realmAccess = new JsonObject();
		JsonArray roles = new JsonArray();
		roles.add("ghidra-user");
		realmAccess.add("roles", roles);
		c.add("realm_access", realmAccess);
		assertEquals("alice", login(module, c));
	}

	@Test
	public void testInvalidConfiguration() {
		assertBadConfig("missing required property: issuer", OIDCConfiguration.CLIENT_ID, "x");
		assertBadConfig("missing required property: client_id", OIDCConfiguration.ISSUER,
			"https://idp.example.com");
		assertBadConfig("must use https", OIDCConfiguration.ISSUER, "http://idp.example.com",
			OIDCConfiguration.CLIENT_ID, "x");
		assertBadConfig("multi-tenant", OIDCConfiguration.ISSUER,
			"https://login.microsoftonline.com/common/v2.0", OIDCConfiguration.CLIENT_ID, "x");
		assertBadConfig("unknown property", OIDCConfiguration.ISSUER, "https://idp.example.com",
			OIDCConfiguration.CLIENT_ID, "x", "clientid", "y");
		assertBadConfig("openid", OIDCConfiguration.ISSUER, "https://idp.example.com",
			OIDCConfiguration.CLIENT_ID, "x", OIDCConfiguration.SCOPES, "profile email");
		assertBadConfig("unsupported algorithm", OIDCConfiguration.ISSUER,
			"https://idp.example.com", OIDCConfiguration.CLIENT_ID, "x",
			OIDCConfiguration.ALLOWED_ALGORITHMS, "RS256,HS256");
		assertBadConfig("required_claim_values", OIDCConfiguration.ISSUER,
			"https://idp.example.com", OIDCConfiguration.CLIENT_ID, "x",
			OIDCConfiguration.REQUIRED_CLAIM, "groups");
		assertBadConfig("redirect_port", OIDCConfiguration.ISSUER, "https://idp.example.com",
			OIDCConfiguration.CLIENT_ID, "x", OIDCConfiguration.REDIRECT_PORT, "70000");

		// Keycloak realm named 'common' is fine
		Properties ok = new Properties();
		ok.setProperty(OIDCConfiguration.ISSUER, "https://kc.example.com/realms/common");
		ok.setProperty(OIDCConfiguration.CLIENT_ID, "x");
		new OIDCConfiguration(ok);
	}

	private void assertBadConfig(String expectedMessagePart, String... kv) {
		Properties props = new Properties();
		for (int i = 0; i < kv.length; i += 2) {
			props.setProperty(kv[i], kv[i + 1]);
		}
		try {
			new OIDCConfiguration(props);
			fail("Expected invalid config: " + expectedMessagePart);
		}
		catch (IllegalArgumentException e) {
			assertTrue("Unexpected message: " + e.getMessage(),
				e.getMessage().contains(expectedMessagePart));
		}
	}

	@Test
	public void testTokenTimeToLive() throws Exception {
		byte[] shortToken = TokenGenerator.getNewToken(1);
		Thread.sleep(50);
		assertFalse(TokenGenerator.isValidToken(shortToken));

		byte[] longToken = TokenGenerator.getNewToken(300_000);
		assertTrue(TokenGenerator.isValidToken(longToken));
		assertFalse(TokenGenerator.isValidToken(longToken)); // single use

		byte[] defaultToken = TokenGenerator.getNewToken();
		assertTrue(TokenGenerator.isValidToken(defaultToken));
	}
}
