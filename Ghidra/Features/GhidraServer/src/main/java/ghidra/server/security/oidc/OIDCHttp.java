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
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.*;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

import com.google.gson.*;

/**
 * HTTP/JSON helper methods used for OIDC discovery and JWKS retrieval.
 */
class OIDCHttp {

	private static final Duration HTTP_TIMEOUT = Duration.ofSeconds(30);
	private static final int MAX_RESPONSE_CHARS = 1024 * 1024;

	private OIDCHttp() {
		// no construct
	}

	/**
	 * Determine if URI is acceptable for identity provider communication.  https is required
	 * except for loopback hosts (local testing).
	 * @param uri URI
	 * @return true if acceptable
	 */
	static boolean isSecureUri(URI uri) {
		String scheme = uri.getScheme();
		if ("https".equalsIgnoreCase(scheme)) {
			return true;
		}
		String host = uri.getHost();
		return "http".equalsIgnoreCase(scheme) && host != null &&
			(host.equalsIgnoreCase("localhost") || host.equals("127.0.0.1") ||
				host.equals("[::1]"));
	}

	static URI parseSecureUri(String s, String what) throws IOException {
		if (s == null) {
			throw new IOException(what + " not specified");
		}
		URI uri;
		try {
			uri = new URI(s);
		}
		catch (URISyntaxException e) {
			throw new IOException("Invalid " + what + ": " + s);
		}
		if (!isSecureUri(uri)) {
			throw new IOException(what + " must use https: " + s);
		}
		return uri;
	}

	static JsonObject getJson(HttpClient client, URI uri) throws IOException {
		HttpRequest request = HttpRequest.newBuilder(uri)
				.timeout(HTTP_TIMEOUT)
				.header("Accept", "application/json")
				.GET()
				.build();
		HttpResponse<String> response;
		try {
			response = client.send(request, BodyHandlers.ofString(StandardCharsets.UTF_8));
		}
		catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			throw new IOException("Request interrupted: " + uri, e);
		}
		if (response.statusCode() != 200) {
			throw new IOException("HTTP " + response.statusCode() + " from " + uri);
		}
		String body = response.body();
		if (body.length() > MAX_RESPONSE_CHARS) {
			throw new IOException("Response too large from " + uri);
		}
		try {
			JsonElement elem = JsonParser.parseString(body);
			if (!elem.isJsonObject()) {
				throw new IOException("Expected JSON object from " + uri);
			}
			return elem.getAsJsonObject();
		}
		catch (JsonParseException e) {
			throw new IOException("Invalid JSON from " + uri, e);
		}
	}

	/**
	 * Get a string member value.
	 * @param obj JSON object
	 * @param name member name
	 * @return string value or null if missing or not a string
	 */
	static String getString(JsonObject obj, String name) {
		JsonElement e = obj.get(name);
		if (e == null || !e.isJsonPrimitive() || !e.getAsJsonPrimitive().isString()) {
			return null;
		}
		return e.getAsString();
	}
}
