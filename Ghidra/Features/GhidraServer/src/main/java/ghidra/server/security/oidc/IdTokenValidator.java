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
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.time.Clock;
import java.util.*;

import javax.security.auth.login.FailedLoginException;

import com.google.gson.*;

/**
 * <code>IdTokenValidator</code> validates an OpenID Connect ID token (a JWS in compact
 * serialization) per OpenID Connect Core 1.0 section 3.1.3.7:
 * <ul>
 * <li>the signature must be valid using an asymmetric algorithm which has been allowed and a
 * key published by the identity provider (no keys are ever taken from the token itself),</li>
 * <li><code>iss</code> must exactly match the configured issuer,</li>
 * <li><code>aud</code> must contain the configured audience, and if multiple audiences are
 * present <code>azp</code> must be present; if present <code>azp</code> must equal the client
 * ID,</li>
 * <li><code>exp</code>, <code>iat</code> and (optional) <code>nbf</code> must be satisfied
 * subject to the allowed clock skew, and</li>
 * <li><code>nonce</code> must match the expected value.</li>
 * </ul>
 */
public class IdTokenValidator {

	/**
	 * Resolves identity provider signing keys
	 */
	@FunctionalInterface
	public interface KeyResolver {
		/**
		 * Find signing key
		 * @param kid key ID from JWS header (may be null)
		 * @param alg JWS algorithm
		 * @return key or null if not found
		 * @throws IOException if keys could not be obtained
		 */
		PublicKey getKey(String kid, JwsAlgorithm alg) throws IOException;
	}

	static final int MAX_TOKEN_LENGTH = 64 * 1024;

	private final OIDCConfiguration config;
	private final KeyResolver keyResolver;
	private final Clock clock;

	/**
	 * Construct ID token validator
	 * @param config OIDC configuration
	 * @param keyResolver signing key resolver
	 * @param clock clock used for time-based claim validation
	 */
	public IdTokenValidator(OIDCConfiguration config, KeyResolver keyResolver, Clock clock) {
		this.config = config;
		this.keyResolver = keyResolver;
		this.clock = clock;
	}

	/**
	 * Validate ID token.
	 * @param idToken compact serialized ID token
	 * @param expectedNonce expected <code>nonce</code> claim value
	 * @return validated token claims
	 * @throws FailedLoginException if token is invalid
	 * @throws IOException if signing keys could not be obtained
	 */
	public JsonObject validate(String idToken, String expectedNonce)
			throws FailedLoginException, IOException {
		if (idToken == null || idToken.isEmpty()) {
			throw new FailedLoginException("ID token missing");
		}
		if (idToken.length() > MAX_TOKEN_LENGTH) {
			throw new FailedLoginException("ID token too large");
		}
		String[] parts = idToken.split("\\.", -1);
		if (parts.length != 3) {
			throw new FailedLoginException("ID token is not a compact JWS");
		}

		JsonObject header = decodeJsonPart(parts[0], "header");
		JsonObject claims = decodeJsonPart(parts[1], "payload");
		byte[] signature = decodeBase64Url(parts[2], "signature");

		// --- Header / signature ---

		String algName = OIDCHttp.getString(header, "alg");
		JwsAlgorithm alg = JwsAlgorithm.forName(algName);
		if (alg == null || !config.getAllowedAlgorithms().contains(alg.name())) {
			throw new FailedLoginException("ID token algorithm not allowed: " + algName);
		}
		if (header.has("crit")) {
			throw new FailedLoginException("ID token contains unsupported critical header");
		}
		String kid = OIDCHttp.getString(header, "kid");
		PublicKey key = keyResolver.getKey(kid, alg);
		if (key == null) {
			throw new FailedLoginException("No identity provider signing key found for kid=" +
				kid + ", alg=" + alg);
		}
		byte[] signingInput = (parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII);
		boolean valid;
		try {
			valid = alg.verify(key, signingInput, signature);
		}
		catch (GeneralSecurityException e) {
			throw new FailedLoginException("ID token signature verification error: " + e);
		}
		if (!valid) {
			throw new FailedLoginException("ID token signature is invalid");
		}

		// --- Claims ---

		String iss = OIDCHttp.getString(claims, "iss");
		if (!config.getIssuer().equals(iss)) {
			throw new FailedLoginException("ID token issuer mismatch: " + iss);
		}

		String sub = OIDCHttp.getString(claims, "sub");
		if (sub == null || sub.isEmpty()) {
			throw new FailedLoginException("ID token subject missing");
		}

		List<String> aud = getAudience(claims);
		if (!aud.contains(config.getAudience())) {
			throw new FailedLoginException("ID token audience mismatch: " + aud);
		}
		String azp = OIDCHttp.getString(claims, "azp");
		if (aud.size() > 1 && azp == null) {
			throw new FailedLoginException("ID token with multiple audiences lacks azp");
		}
		if (azp != null && !config.getClientId().equals(azp)) {
			throw new FailedLoginException("ID token authorized party mismatch: " + azp);
		}

		long now = clock.millis() / 1000;
		long skew = config.getClockSkewSeconds();
		long exp = getRequiredTime(claims, "exp");
		if (now - skew >= exp) {
			throw new FailedLoginException("ID token has expired");
		}
		long iat = getRequiredTime(claims, "iat");
		if (iat > now + skew) {
			throw new FailedLoginException("ID token issued in the future");
		}
		if (claims.has("nbf")) {
			long nbf = getRequiredTime(claims, "nbf");
			if (nbf > now + skew) {
				throw new FailedLoginException("ID token not yet valid");
			}
		}

		String nonce = OIDCHttp.getString(claims, "nonce");
		if (expectedNonce == null || !expectedNonce.equals(nonce)) {
			throw new FailedLoginException("ID token nonce mismatch");
		}

		return claims;
	}

	private static JsonObject decodeJsonPart(String part, String what)
			throws FailedLoginException {
		byte[] bytes = decodeBase64Url(part, what);
		try {
			JsonElement elem = JsonParser.parseString(new String(bytes, StandardCharsets.UTF_8));
			if (elem.isJsonObject()) {
				return elem.getAsJsonObject();
			}
		}
		catch (JsonParseException e) {
			// fall through
		}
		throw new FailedLoginException("ID token " + what + " is not a JSON object");
	}

	private static byte[] decodeBase64Url(String part, String what) throws FailedLoginException {
		// JWS requires unpadded base64url
		if (part.isEmpty() || part.indexOf('=') >= 0) {
			throw new FailedLoginException("ID token " + what + " encoding is invalid");
		}
		try {
			return Base64.getUrlDecoder().decode(part);
		}
		catch (IllegalArgumentException e) {
			throw new FailedLoginException("ID token " + what + " encoding is invalid");
		}
	}

	private static List<String> getAudience(JsonObject claims) throws FailedLoginException {
		JsonElement e = claims.get("aud");
		List<String> list = new ArrayList<>();
		if (e != null && e.isJsonPrimitive() && e.getAsJsonPrimitive().isString()) {
			list.add(e.getAsString());
		}
		else if (e != null && e.isJsonArray()) {
			for (JsonElement a : e.getAsJsonArray()) {
				if (a.isJsonPrimitive() && a.getAsJsonPrimitive().isString()) {
					list.add(a.getAsString());
				}
			}
		}
		if (list.isEmpty()) {
			throw new FailedLoginException("ID token audience missing");
		}
		return list;
	}

	private static long getRequiredTime(JsonObject claims, String name)
			throws FailedLoginException {
		JsonElement e = claims.get(name);
		if (e == null || !e.isJsonPrimitive() || !e.getAsJsonPrimitive().isNumber()) {
			throw new FailedLoginException("ID token '" + name + "' claim missing or invalid");
		}
		try {
			return e.getAsBigDecimal().longValue();
		}
		catch (NumberFormatException | ArithmeticException ex) {
			throw new FailedLoginException("ID token '" + name + "' claim invalid");
		}
	}

	/**
	 * Resolve a claim value by name.  If no top-level claim with the exact name exists and the
	 * name contains '.', it is treated as a path into nested objects (e.g.,
	 * <code>realm_access.roles</code>).
	 * @param claims token claims
	 * @param name claim name or dotted path
	 * @return claim value or null if not found
	 */
	public static JsonElement getClaim(JsonObject claims, String name) {
		JsonElement e = claims.get(name);
		if (e != null || name.indexOf('.') < 0) {
			return e;
		}
		JsonElement cur = claims;
		for (String part : name.split("\\.")) {
			if (cur == null || !cur.isJsonObject()) {
				return null;
			}
			cur = cur.getAsJsonObject().get(part);
		}
		return cur;
	}

	/**
	 * Get string values of a claim, which may be a single string or an array of strings.
	 * @param claims token claims
	 * @param name claim name or dotted path
	 * @return list of string values (empty if not found)
	 */
	public static List<String> getClaimStrings(JsonObject claims, String name) {
		JsonElement e = getClaim(claims, name);
		List<String> list = new ArrayList<>();
		if (e == null) {
			return list;
		}
		if (e.isJsonPrimitive() && e.getAsJsonPrimitive().isString()) {
			list.add(e.getAsString());
		}
		else if (e.isJsonArray()) {
			for (JsonElement a : e.getAsJsonArray()) {
				if (a.isJsonPrimitive() && a.getAsJsonPrimitive().isString()) {
					list.add(a.getAsString());
				}
			}
		}
		return list;
	}
}
