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
package ghidra.framework.client;

import static org.junit.Assert.*;

import java.io.IOException;
import java.io.OutputStream;
import java.net.*;
import java.net.http.*;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.StandardCharsets;
import java.util.*;

import org.junit.*;

import com.google.gson.JsonObject;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import generic.test.AbstractGenericTest;
import ghidra.framework.remote.OIDCCallback;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitorAdapter;

public class OIDCLoginClientTest extends AbstractGenericTest {

	private static final String CLIENT_ID = "ghidra-server";

	private HttpServer idpServer;
	private String issuer;
	private HttpClient httpClient;

	// state captured by mock IdP
	private volatile Map<String, String> authRequest;
	private volatile Map<String, String> tokenRequest;
	private volatile String authorizeError;
	private volatile String tokenError;
	private volatile String discoveryIssuer;

	@Before
	public void setUp() throws Exception {
		idpServer =
			HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
		issuer = "http://127.0.0.1:" + idpServer.getAddress().getPort() + "/realms/test";
		discoveryIssuer = issuer;
		idpServer.createContext("/realms/test/.well-known/openid-configuration", ex -> {
			JsonObject obj = new JsonObject();
			obj.addProperty("issuer", discoveryIssuer);
			obj.addProperty("authorization_endpoint", issuer + "/auth");
			obj.addProperty("token_endpoint", issuer + "/token");
			obj.addProperty("jwks_uri", issuer + "/jwks");
			send(ex, 200, "application/json", obj.toString());
		});
		idpServer.createContext("/realms/test/auth", this::handleAuthorize);
		idpServer.createContext("/realms/test/token", this::handleToken);
		idpServer.start();
		httpClient = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();
	}

	@After
	public void tearDown() {
		idpServer.stop(0);
		System.clearProperty(OIDCLoginClient.REDIRECT_PORT_PROPERTY);
	}

	private void handleAuthorize(HttpExchange ex) throws IOException {
		Map<String, String> params = OIDCLoginClient.parseQuery(ex.getRequestURI().getRawQuery());
		authRequest = params;
		String location = params.get("redirect_uri") + "?state=" +
			URLEncoder.encode(params.get("state"), StandardCharsets.UTF_8);
		if (authorizeError != null) {
			location += "&error=" + authorizeError + "&error_description=User+said+no";
		}
		else {
			location += "&code=test-code-123";
		}
		ex.getResponseHeaders().set("Location", location);
		ex.sendResponseHeaders(302, -1);
		ex.close();
	}

	private void handleToken(HttpExchange ex) throws IOException {
		String body = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
		Map<String, String> form = OIDCLoginClient.parseQuery(body);
		tokenRequest = form;
		if (tokenError != null) {
			send(ex, 400, "application/json",
				"{\"error\":\"" + tokenError + "\",\"error_description\":\"bad grant\"}");
			return;
		}
		JsonObject claims = new JsonObject();
		claims.addProperty("iss", issuer);
		claims.addProperty("nonce", authRequest.get("nonce"));
		String idToken = b64("{\"alg\":\"RS256\"}") + "." + b64(claims.toString()) + ".c2ln";
		send(ex, 200, "application/json", "{\"access_token\":\"at\",\"token_type\":\"Bearer\"," +
			"\"id_token\":\"" + idToken + "\"}");
	}

	private static String b64(String s) {
		return Base64.getUrlEncoder()
				.withoutPadding()
				.encodeToString(s.getBytes(StandardCharsets.UTF_8));
	}

	private static void send(HttpExchange ex, int status, String type, String body)
			throws IOException {
		byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
		ex.getResponseHeaders().set("Content-Type", type);
		ex.sendResponseHeaders(status, bytes.length);
		try (OutputStream out = ex.getResponseBody()) {
			out.write(bytes);
		}
	}

	private OIDCCallback newCallback(String authParams, int redirectPort) {
		byte[] token = new byte[64];
		new Random(1).nextBytes(token);
		return new OIDCCallback(issuer, CLIENT_ID, "openid profile", authParams, redirectPort, 30,
			token);
	}

	/**
	 * Simulates a browser: requests the authorization URI and follows the redirect to the
	 * loopback listener.
	 */
	private HttpResponse<String> browse(URI uri) throws IOException {
		try {
			HttpResponse<String> resp = httpClient.send(HttpRequest.newBuilder(uri).build(),
				BodyHandlers.ofString());
			if (resp.statusCode() == 302) {
				String location = resp.headers().firstValue("Location").orElseThrow();
				return httpClient.send(HttpRequest.newBuilder(URI.create(location)).build(),
					BodyHandlers.ofString());
			}
			return resp;
		}
		catch (InterruptedException e) {
			throw new IOException(e);
		}
	}

	private java.util.concurrent.CompletableFuture<HttpResponse<String>> browseAsync(URI uri) {
		java.util.concurrent.CompletableFuture<HttpResponse<String>> result =
			new java.util.concurrent.CompletableFuture<>();
		Thread t = new Thread(() -> {
			try {
				result.complete(browse(uri));
			}
			catch (Throwable e) {
				result.completeExceptionally(e);
			}
		});
		t.setDaemon(true);
		t.start();
		return result;
	}

	@Test
	public void testSuccessfulLogin() throws Exception {
		OIDCCallback cb = newCallback("prompt=select_account&client_id=evil", 0);
		OIDCLoginClient client = new OIDCLoginClient(cb, httpClient);
		List<URI> opened = new ArrayList<>();
		List<java.util.concurrent.CompletableFuture<HttpResponse<String>>> browsers =
			new ArrayList<>();
		client.login((uri, port) -> {
			opened.add(uri);
			browsers.add(browseAsync(uri));
		}, null);

		assertNotNull(cb.getIdToken());
		assertEquals(1, opened.size());

		// browser must receive the completion page (listener must not close prematurely)
		HttpResponse<String> page =
			browsers.get(0).get(10, java.util.concurrent.TimeUnit.SECONDS);
		assertEquals(200, page.statusCode());
		assertTrue(page.body(), page.body().contains("sign-in complete"));

		// authorization request
		assertEquals("code", authRequest.get("response_type"));
		assertEquals(CLIENT_ID, authRequest.get("client_id")); // not overridden by authParams
		assertEquals("openid profile", authRequest.get("scope"));
		assertEquals(cb.getNonce(), authRequest.get("nonce"));
		assertEquals("S256", authRequest.get("code_challenge_method"));
		assertEquals("select_account", authRequest.get("prompt"));
		URI redirect = URI.create(authRequest.get("redirect_uri"));
		assertEquals("http", redirect.getScheme());
		assertEquals("127.0.0.1", redirect.getHost());
		assertEquals(OIDCLoginClient.CALLBACK_PATH, redirect.getPath());
		assertTrue(redirect.getPort() > 0);

		// token request with PKCE verifier
		assertEquals("authorization_code", tokenRequest.get("grant_type"));
		assertEquals("test-code-123", tokenRequest.get("code"));
		assertEquals(authRequest.get("redirect_uri"), tokenRequest.get("redirect_uri"));
		assertEquals(CLIENT_ID, tokenRequest.get("client_id"));
		assertNull(tokenRequest.get("client_secret"));
		String verifier = tokenRequest.get("code_verifier");
		assertNotNull(verifier);
		assertTrue(verifier.length() >= 43);
		assertEquals(authRequest.get("code_challenge"),
			OIDCLoginClient.computeCodeChallenge(verifier));
	}

	@Test
	public void testRfc7636CodeChallengeVector() {
		// RFC 7636 Appendix B
		assertEquals("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
			OIDCLoginClient.computeCodeChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"));
	}

	@Test
	public void testFixedRedirectPortProperty() throws Exception {
		int port;
		try (ServerSocket s = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))) {
			port = s.getLocalPort();
		}
		System.setProperty(OIDCLoginClient.REDIRECT_PORT_PROPERTY, Integer.toString(port));
		OIDCCallback cb = newCallback(null, 1); // property overrides server suggestion
		OIDCLoginClient client = new OIDCLoginClient(cb, httpClient);
		int[] reportedPort = new int[1];
		client.login((uri, p) -> {
			reportedPort[0] = p;
			browseAsync(uri);
		}, null);
		assertEquals(port, reportedPort[0]);
		assertEquals(port, URI.create(authRequest.get("redirect_uri")).getPort());
	}

	@Test
	public void testInvalidStateIgnored() throws Exception {
		OIDCCallback cb = newCallback(null, 0);
		OIDCLoginClient client = new OIDCLoginClient(cb, httpClient);
		client.login((uri, port) -> {
			// forged redirect with wrong state is rejected and login continues waiting
			HttpResponse<String> resp = browse(URI.create("http://127.0.0.1:" + port +
				OIDCLoginClient.CALLBACK_PATH + "?state=wrong&code=evil"));
			assertEquals(400, resp.statusCode());
			browseAsync(uri);
		}, null);
		assertEquals("test-code-123", tokenRequest.get("code"));
		assertNotNull(cb.getIdToken());
	}

	@Test
	public void testAuthorizationError() throws Exception {
		authorizeError = "access_denied";
		OIDCCallback cb = newCallback(null, 0);
		OIDCLoginClient client = new OIDCLoginClient(cb, httpClient);
		List<java.util.concurrent.CompletableFuture<HttpResponse<String>>> browsers =
			new ArrayList<>();
		try {
			client.login((uri, port) -> browsers.add(browseAsync(uri)), null);
			fail("Expected IOException");
		}
		catch (IOException e) {
			assertTrue(e.getMessage(), e.getMessage().contains("access_denied"));
			assertTrue(e.getMessage(), e.getMessage().contains("User said no"));
		}
		HttpResponse<String> page =
			browsers.get(0).get(10, java.util.concurrent.TimeUnit.SECONDS);
		assertTrue(page.body(), page.body().contains("sign-in failed"));
		assertNull(cb.getIdToken());
		assertNull(tokenRequest);
	}

	@Test
	public void testTokenError() throws Exception {
		tokenError = "invalid_grant";
		OIDCCallback cb = newCallback(null, 0);
		OIDCLoginClient client = new OIDCLoginClient(cb, httpClient);
		try {
			client.login((uri, port) -> browseAsync(uri), null);
			fail("Expected IOException");
		}
		catch (IOException e) {
			assertTrue(e.getMessage(), e.getMessage().contains("invalid_grant"));
		}
		assertNull(cb.getIdToken());
	}

	@Test
	public void testDiscoveryIssuerMismatch() throws Exception {
		discoveryIssuer = "http://127.0.0.1/evil";
		OIDCLoginClient client = new OIDCLoginClient(newCallback(null, 0), httpClient);
		try {
			client.login((uri, port) -> fail("should not open browser"), null);
			fail("Expected IOException");
		}
		catch (IOException e) {
			assertTrue(e.getMessage(), e.getMessage().contains("issuer mismatch"));
		}
	}

	@Test
	public void testInsecureIssuerRejected() throws Exception {
		OIDCCallback cb = new OIDCCallback("http://idp.example.com/realms/x", CLIENT_ID,
			"openid", null, 0, 30, new byte[64]);
		OIDCLoginClient client = new OIDCLoginClient(cb, httpClient);
		try {
			client.login((uri, port) -> fail("should not open browser"), null);
			fail("Expected IOException");
		}
		catch (IOException e) {
			assertTrue(e.getMessage(), e.getMessage().contains("https"));
		}
	}

	@Test
	public void testCancel() throws Exception {
		OIDCCallback cb = newCallback(null, 0);
		OIDCLoginClient client = new OIDCLoginClient(cb, httpClient);
		TaskMonitorAdapter monitor = new TaskMonitorAdapter(true);
		int[] listenPort = new int[1];
		long start = System.currentTimeMillis();
		try {
			client.login((uri, port) -> {
				listenPort[0] = port;
				new Thread(() -> {
					sleep(300);
					monitor.cancel();
				}).start();
			}, monitor);
			fail("Expected CancelledException");
		}
		catch (CancelledException e) {
			// expected
		}
		assertTrue(System.currentTimeMillis() - start < 10_000);
		// redirect listener must be closed
		try (Socket s = new Socket()) {
			s.connect(new InetSocketAddress("127.0.0.1", listenPort[0]), 1000);
			fail("Redirect listener still open");
		}
		catch (IOException e) {
			// expected
		}
	}

	@Test
	public void testNonceMismatchDetected() throws Exception {
		OIDCCallback cb = newCallback(null, 0);
		OIDCLoginClient client = new OIDCLoginClient(cb, httpClient);
		// Alter callback token after authorization request so ID token nonce will not match
		try {
			client.login((uri, port) -> {
				cb.getToken()[0] ^= 0x1;
				browseAsync(uri);
			}, null);
			fail("Expected IOException");
		}
		catch (IOException e) {
			assertTrue(e.getMessage(), e.getMessage().contains("nonce"));
		}
		assertNull(cb.getIdToken());
	}
}
