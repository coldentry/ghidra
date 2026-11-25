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

import java.io.IOException;
import java.io.OutputStream;
import java.net.*;
import java.net.http.*;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;

import com.google.gson.*;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import generic.random.SecureRandomFactory;
import ghidra.framework.remote.OIDCCallback;
import ghidra.net.HttpClients;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * <code>OIDCLoginClient</code> performs the client side of an OpenID Connect Authorization Code
 * flow with PKCE (RFC 7636) using a loopback redirect (RFC 8252) to satisfy an
 * {@link OIDCCallback} issued by a Ghidra Server.
 * <p>
 * The redirect listener is always bound to the IPv4 loopback address <code>127.0.0.1</code>.
 * The listen port is taken from the {@value #REDIRECT_PORT_PROPERTY} system property if set,
 * otherwise the port suggested by the server, otherwise an ephemeral port.  A fixed port
 * permits the login to be completed from a browser on a different machine by forwarding that
 * port (e.g., <code>ssh -L 8400:127.0.0.1:8400 host</code>).
 */
public class OIDCLoginClient {

	/**
	 * System property which may be used to force a specific loopback redirect port.
	 */
	public static final String REDIRECT_PORT_PROPERTY = "ghidra.oidc.redirect.port";

	/**
	 * Loopback redirect URI path.
	 */
	public static final String CALLBACK_PATH = "/oidc/callback";

	static final String LOOPBACK_ADDRESS = "127.0.0.1";

	private static final int DEFAULT_LOGIN_TIMEOUT_SECONDS = 300;
	private static final Duration HTTP_TIMEOUT = Duration.ofSeconds(30);
	private static final long POLL_INTERVAL_MS = 250;

	/**
	 * Handler responsible for presenting the authorization URI to the user (e.g., opening
	 * a web browser or displaying the URI).
	 */
	@FunctionalInterface
	public interface AuthorizationUriHandler {
		/**
		 * Present authorization URI to the user.
		 * @param authorizationUri identity provider authorization request URI
		 * @param redirectPort loopback port on which the redirect is being awaited
		 * @throws IOException if unable to present URI and login should be aborted
		 */
		void open(URI authorizationUri, int redirectPort) throws IOException;
	}

	private final OIDCCallback oidcCb;
	private final HttpClient httpClient;

	/**
	 * Construct OIDC login client.
	 * @param oidcCb server issued OIDC callback
	 * @throws IOException if HTTP client could not be initialized
	 */
	public OIDCLoginClient(OIDCCallback oidcCb) throws IOException {
		this(oidcCb, HttpClients.getHttpClient());
	}

	OIDCLoginClient(OIDCCallback oidcCb, HttpClient httpClient) {
		this.oidcCb = Objects.requireNonNull(oidcCb);
		this.httpClient = Objects.requireNonNull(httpClient);
	}

	/**
	 * Perform login and set the resulting ID token on the callback.
	 * @param uriHandler handler used to present the authorization URI to the user
	 * @param monitor task monitor used to cancel login (may be null)
	 * @throws IOException if login fails
	 * @throws CancelledException if login was cancelled
	 */
	public void login(AuthorizationUriHandler uriHandler, TaskMonitor monitor)
			throws IOException, CancelledException {
		monitor = TaskMonitor.dummyIfNull(monitor);

		String issuer = oidcCb.getIssuer();
		JsonObject metadata = fetchProviderMetadata(issuer);
		URI authEndpoint = getEndpoint(metadata, "authorization_endpoint");
		URI tokenEndpoint = getEndpoint(metadata, "token_endpoint");

		String codeVerifier = randomUrlSafeString(32);
		String codeChallenge = computeCodeChallenge(codeVerifier);
		String state = randomUrlSafeString(32);

		CompletableFuture<String> codeFuture = new CompletableFuture<>();
		HttpServer server = startRedirectListener(getRedirectPort(), state, codeFuture);
		try {
			int port = server.getAddress().getPort();
			String redirectUri = "http://" + LOOPBACK_ADDRESS + ":" + port + CALLBACK_PATH;

			URI authUri =
				buildAuthorizationUri(authEndpoint, redirectUri, state, codeChallenge);

			monitor.setMessage("Waiting for OpenID Connect sign-in using web browser...");
			uriHandler.open(authUri, port);

			String code = waitForCode(codeFuture, monitor);

			monitor.setMessage("Completing OpenID Connect sign-in...");
			String idToken = exchangeCode(tokenEndpoint, code, redirectUri, codeVerifier);
			checkNonce(idToken);
			oidcCb.setIdToken(idToken);
		}
		finally {
			server.stop(0);
		}
	}

	private int getRedirectPort() throws IOException {
		String portStr = System.getProperty(REDIRECT_PORT_PROPERTY);
		if (portStr != null && !portStr.isBlank()) {
			try {
				int port = Integer.parseInt(portStr.trim());
				if (port >= 0 && port <= 65535) {
					return port;
				}
			}
			catch (NumberFormatException e) {
				// fall through
			}
			throw new IOException("Invalid " + REDIRECT_PORT_PROPERTY + " value: " + portStr);
		}
		int port = oidcCb.getRedirectPort();
		return (port > 0 && port <= 65535) ? port : 0;
	}

	private JsonObject fetchProviderMetadata(String issuer) throws IOException {
		if (issuer == null || issuer.isBlank()) {
			throw new IOException("OIDC issuer not specified by server");
		}
		URI issuerUri = parseUri(issuer);
		checkSecureUri(issuerUri);
		String base = issuer.endsWith("/") ? issuer.substring(0, issuer.length() - 1) : issuer;
		URI discoveryUri = parseUri(base + "/.well-known/openid-configuration");

		HttpRequest request = HttpRequest.newBuilder(discoveryUri)
				.timeout(HTTP_TIMEOUT)
				.header("Accept", "application/json")
				.GET()
				.build();
		JsonObject metadata = sendForJson(request, "OIDC discovery");
		String reportedIssuer = getString(metadata, "issuer");
		if (!issuer.equals(reportedIssuer)) {
			throw new IOException("OIDC discovery issuer mismatch: expected " + issuer +
				" but provider reported " + reportedIssuer);
		}
		return metadata;
	}

	private URI getEndpoint(JsonObject metadata, String name) throws IOException {
		String value = getString(metadata, name);
		if (value == null) {
			throw new IOException("OIDC discovery document missing " + name);
		}
		URI uri = parseUri(value);
		checkSecureUri(uri);
		return uri;
	}

	private HttpServer startRedirectListener(int port, String expectedState,
			CompletableFuture<String> codeFuture) throws IOException {
		HttpServer server;
		try {
			server = HttpServer.create(
				new InetSocketAddress(InetAddress.getByName(LOOPBACK_ADDRESS), port), 0);
		}
		catch (BindException e) {
			throw new IOException("Unable to listen for OIDC redirect on " + LOOPBACK_ADDRESS +
				":" + port + " (port in use?)", e);
		}
		server.createContext(CALLBACK_PATH,
			exchange -> handleRedirect(exchange, expectedState, codeFuture));
		server.start();
		return server;
	}

	private static void handleRedirect(HttpExchange exchange, String expectedState,
			CompletableFuture<String> codeFuture) throws IOException {
		try {
			if (!"GET".equals(exchange.getRequestMethod())) {
				sendPage(exchange, 405, "Unsupported request method.");
				return;
			}
			Map<String, String> params = parseQuery(exchange.getRequestURI().getRawQuery());
			if (!MessageDigest.isEqual(
				expectedState.getBytes(StandardCharsets.US_ASCII),
				Objects.toString(params.get("state"), "").getBytes(StandardCharsets.US_ASCII))) {
				// Ignore unrelated/forged requests - keep waiting for the real redirect
				sendPage(exchange, 400, "Invalid or missing state parameter.");
				return;
			}
			// NOTE: The response must be fully sent before completing the future since
			// completion allows the login to proceed and stop this listener.
			String error = params.get("error");
			if (error != null) {
				String desc = params.get("error_description");
				sendPage(exchange, 200, "Ghidra Server sign-in failed: " + error +
					". You may close this window.");
				codeFuture.completeExceptionally(new IOException(
					"OIDC sign-in failed: " + error + (desc != null ? " - " + desc : "")));
				return;
			}
			String code = params.get("code");
			if (code == null || code.isEmpty()) {
				sendPage(exchange, 400, "Missing authorization code.");
				return;
			}
			sendPage(exchange, 200, codeFuture.isDone()
					? "Ghidra Server sign-in already completed. You may close this window."
					: "Ghidra Server sign-in complete. You may close this window.");
			codeFuture.complete(code);
		}
		finally {
			exchange.close();
		}
	}

	private static void sendPage(HttpExchange exchange, int status, String message)
			throws IOException {
		String html = "<!DOCTYPE html><html><head><meta charset=\"utf-8\">" +
			"<title>Ghidra Server Sign-In</title></head>" +
			"<body style=\"font-family: sans-serif; margin: 3em;\"><p>" + escapeHtml(message) +
			"</p></body></html>";
		byte[] bytes = html.getBytes(StandardCharsets.UTF_8);
		exchange.getResponseHeaders().set("Content-Type", "text/html; charset=utf-8");
		exchange.getResponseHeaders().set("Cache-Control", "no-store");
		exchange.sendResponseHeaders(status, bytes.length);
		try (OutputStream out = exchange.getResponseBody()) {
			out.write(bytes);
		}
	}

	private static String escapeHtml(String s) {
		return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
	}

	private URI buildAuthorizationUri(URI authEndpoint, String redirectUri, String state,
			String codeChallenge) throws IOException {
		String scope = oidcCb.getScope();
		if (scope == null || scope.isBlank()) {
			scope = "openid";
		}
		Map<String, String> params = new LinkedHashMap<>();
		params.put("response_type", "code");
		params.put("client_id", oidcCb.getClientId());
		params.put("redirect_uri", redirectUri);
		params.put("scope", scope);
		params.put("state", state);
		params.put("nonce", oidcCb.getNonce());
		params.put("code_challenge", codeChallenge);
		params.put("code_challenge_method", "S256");
		for (Map.Entry<String, String> e : parseQuery(oidcCb.getAuthParams()).entrySet()) {
			params.putIfAbsent(e.getKey(), e.getValue()); // never override protocol params
		}
		String base = authEndpoint.toString();
		String uri = base + (base.contains("?") ? "&" : "?") + formEncode(params);
		return parseUri(uri);
	}

	private String waitForCode(CompletableFuture<String> codeFuture, TaskMonitor monitor)
			throws IOException, CancelledException {
		int timeoutSeconds = oidcCb.getLoginTimeoutSeconds();
		if (timeoutSeconds <= 0) {
			timeoutSeconds = DEFAULT_LOGIN_TIMEOUT_SECONDS;
		}
		long deadline = System.currentTimeMillis() + timeoutSeconds * 1000L;
		while (true) {
			monitor.checkCancelled();
			try {
				return codeFuture.get(POLL_INTERVAL_MS, TimeUnit.MILLISECONDS);
			}
			catch (TimeoutException e) {
				if (System.currentTimeMillis() > deadline) {
					throw new IOException("Timed out waiting for OIDC sign-in");
				}
			}
			catch (ExecutionException e) {
				Throwable cause = e.getCause();
				if (cause instanceof IOException ioe) {
					throw ioe;
				}
				throw new IOException("OIDC sign-in failed", cause);
			}
			catch (InterruptedException e) {
				Thread.currentThread().interrupt();
				throw new CancelledException();
			}
		}
	}

	private String exchangeCode(URI tokenEndpoint, String code, String redirectUri,
			String codeVerifier) throws IOException {
		Map<String, String> form = new LinkedHashMap<>();
		form.put("grant_type", "authorization_code");
		form.put("code", code);
		form.put("redirect_uri", redirectUri);
		form.put("client_id", oidcCb.getClientId());
		form.put("code_verifier", codeVerifier);

		HttpRequest request = HttpRequest.newBuilder(tokenEndpoint)
				.timeout(HTTP_TIMEOUT)
				.header("Content-Type", "application/x-www-form-urlencoded")
				.header("Accept", "application/json")
				.POST(HttpRequest.BodyPublishers.ofString(formEncode(form)))
				.build();
		JsonObject response = sendForJson(request, "OIDC token request");
		String idToken = getString(response, "id_token");
		if (idToken == null) {
			throw new IOException(
				"OIDC token response did not include an id_token (is 'openid' scope requested?)");
		}
		return idToken;
	}

	/**
	 * Sanity check the ID token nonce before returning it to the server.  The server performs
	 * full signature and claim validation; this simply provides an earlier, clearer error.
	 */
	private void checkNonce(String idToken) throws IOException {
		String[] parts = idToken.split("\\.", -1);
		if (parts.length != 3) {
			throw new IOException("Malformed OIDC ID token");
		}
		try {
			String json =
				new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
			JsonObject claims = JsonParser.parseString(json).getAsJsonObject();
			if (!oidcCb.getNonce().equals(getString(claims, "nonce"))) {
				throw new IOException("OIDC ID token nonce mismatch");
			}
		}
		catch (IllegalArgumentException | JsonParseException | IllegalStateException e) {
			throw new IOException("Malformed OIDC ID token", e);
		}
	}

	private JsonObject sendForJson(HttpRequest request, String what) throws IOException {
		HttpResponse<String> response;
		try {
			response = httpClient.send(request, BodyHandlers.ofString(StandardCharsets.UTF_8));
		}
		catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			throw new IOException(what + " interrupted", e);
		}
		JsonObject json = null;
		try {
			JsonElement elem = JsonParser.parseString(response.body());
			if (elem.isJsonObject()) {
				json = elem.getAsJsonObject();
			}
		}
		catch (JsonParseException e) {
			// handled below
		}
		if (response.statusCode() != 200) {
			String detail = "";
			if (json != null && getString(json, "error") != null) {
				detail = ": " + getString(json, "error");
				String desc = getString(json, "error_description");
				if (desc != null) {
					detail += " - " + desc;
				}
			}
			throw new IOException(
				what + " failed (HTTP " + response.statusCode() + ")" + detail);
		}
		if (json == null) {
			throw new IOException(what + " returned invalid JSON");
		}
		return json;
	}

	static String getString(JsonObject obj, String name) {
		JsonElement e = obj.get(name);
		if (e == null || !e.isJsonPrimitive() || !e.getAsJsonPrimitive().isString()) {
			return null;
		}
		return e.getAsString();
	}

	static URI parseUri(String s) throws IOException {
		try {
			return new URI(s);
		}
		catch (URISyntaxException e) {
			throw new IOException("Invalid URI: " + s, e);
		}
	}

	/**
	 * Require https for identity provider endpoints, except for loopback hosts which may be
	 * used for local testing.
	 * @param uri endpoint URI
	 * @throws IOException if URI is not acceptable
	 */
	static void checkSecureUri(URI uri) throws IOException {
		String scheme = uri.getScheme();
		if ("https".equalsIgnoreCase(scheme)) {
			return;
		}
		if ("http".equalsIgnoreCase(scheme) && isLoopbackHost(uri.getHost())) {
			return;
		}
		throw new IOException("OIDC endpoint must use https: " + uri);
	}

	static boolean isLoopbackHost(String host) {
		if (host == null) {
			return false;
		}
		return host.equalsIgnoreCase("localhost") || host.equals("127.0.0.1") ||
			host.equals("[::1]") || host.equals("::1");
	}

	static Map<String, String> parseQuery(String rawQuery) {
		Map<String, String> params = new LinkedHashMap<>();
		if (rawQuery == null || rawQuery.isBlank()) {
			return params;
		}
		for (String pair : rawQuery.split("&")) {
			if (pair.isEmpty()) {
				continue;
			}
			int ix = pair.indexOf('=');
			String name = ix < 0 ? pair : pair.substring(0, ix);
			String value = ix < 0 ? "" : pair.substring(ix + 1);
			params.putIfAbsent(URLDecoder.decode(name, StandardCharsets.UTF_8),
				URLDecoder.decode(value, StandardCharsets.UTF_8));
		}
		return params;
	}

	static String formEncode(Map<String, String> params) {
		StringBuilder buf = new StringBuilder();
		for (Map.Entry<String, String> e : params.entrySet()) {
			if (buf.length() != 0) {
				buf.append('&');
			}
			buf.append(URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8));
			buf.append('=');
			buf.append(URLEncoder.encode(Objects.toString(e.getValue(), ""),
				StandardCharsets.UTF_8));
		}
		return buf.toString();
	}

	static String randomUrlSafeString(int numBytes) {
		byte[] bytes = new byte[numBytes];
		SecureRandomFactory.getSecureRandom().nextBytes(bytes);
		return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
	}

	static String computeCodeChallenge(String codeVerifier) {
		try {
			MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
			byte[] digest = sha256.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
			return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
		}
		catch (NoSuchAlgorithmException e) {
			throw new AssertionError("SHA-256 not available", e);
		}
	}

	/**
	 * Log a standard console message describing how to complete login.  Used by headless
	 * authenticators.
	 * @param serverName Ghidra Server name
	 * @param authorizationUri authorization URI
	 * @param redirectPort loopback redirect port
	 */
	static void printLoginInstructions(String serverName, URI authorizationUri,
			int redirectPort) {
		String msg = "\nGhidra Server " + serverName + " requires OpenID Connect sign-in.\n" +
			"Open the following URL in a web browser to sign in:\n\n  " + authorizationUri +
			"\n\nIf the browser is on a different machine, forward the redirect port first, " +
			"e.g.:\n  ssh -L " + redirectPort + ":" + LOOPBACK_ADDRESS + ":" + redirectPort +
			" <this-host>\n(use -D" + REDIRECT_PORT_PROPERTY +
			"=<port> to choose a fixed port)\n";
		Msg.info(OIDCLoginClient.class,
			"Waiting for OpenID Connect sign-in for " + serverName);
		System.err.println(msg);
		System.err.flush();
	}
}
