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
import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.security.*;
import java.security.spec.*;
import java.time.Clock;
import java.util.*;

import com.google.gson.*;

import ghidra.util.Msg;

/**
 * <code>JwksKeyCache</code> retrieves and caches the signing keys published by an identity
 * provider as a JSON Web Key Set (RFC 7517).  Keys are refreshed periodically and on-demand
 * when an unknown key ID is encountered (key rotation), subject to a minimum refresh interval.
 */
public class JwksKeyCache {

	static final long CACHE_TTL_MS = 60 * 60 * 1000L; // 1 hour
	static final long MIN_REFRESH_INTERVAL_MS = 60 * 1000L; // 1 minute

	private final HttpClient httpClient;
	private final URI jwksUri;
	private final Clock clock;

	private List<Jwk> keys = List.of();
	private long lastFetchTime = Long.MIN_VALUE / 2;
	private long lastSuccessTime = Long.MIN_VALUE / 2;

	/**
	 * A parsed JSON Web Key
	 * @param kid key ID (may be null)
	 * @param alg intended algorithm (may be null)
	 * @param key public key
	 */
	record Jwk(String kid, String alg, PublicKey key) {
	}

	/**
	 * Construct JWKS key cache.
	 * @param httpClient HTTP client
	 * @param jwksUri JWKS URI
	 * @param clock clock
	 */
	public JwksKeyCache(HttpClient httpClient, URI jwksUri, Clock clock) {
		this.httpClient = httpClient;
		this.jwksUri = jwksUri;
		this.clock = clock;
	}

	/**
	 * Find the public key for the specified key ID and algorithm.
	 * @param kid key ID from JWS header (may be null)
	 * @param alg JWS algorithm
	 * @return public key or null if no suitable key was found
	 * @throws IOException if keys could not be retrieved
	 */
	public synchronized PublicKey getKey(String kid, JwsAlgorithm alg) throws IOException {
		long now = clock.millis();
		if (now - lastSuccessTime > CACHE_TTL_MS) {
			refresh(now, true);
		}
		PublicKey key = findKey(kid, alg);
		if (key == null && now - lastFetchTime >= MIN_REFRESH_INTERVAL_MS) {
			// possible key rotation
			refresh(now, false);
			key = findKey(kid, alg);
		}
		return key;
	}

	private void refresh(long now, boolean required) throws IOException {
		lastFetchTime = now;
		try {
			JsonObject jwks = OIDCHttp.getJson(httpClient, jwksUri);
			keys = parseJwks(jwks);
			lastSuccessTime = now;
			Msg.debug(this, "Loaded " + keys.size() + " OIDC signing keys from " + jwksUri);
		}
		catch (IOException e) {
			if (required && keys.isEmpty()) {
				throw new IOException("Failed to load OIDC signing keys: " + e.getMessage(), e);
			}
			Msg.warn(this, "Failed to refresh OIDC signing keys from " + jwksUri + ": " +
				e.getMessage());
		}
	}

	private PublicKey findKey(String kid, JwsAlgorithm alg) {
		List<Jwk> candidates = new ArrayList<>();
		for (Jwk jwk : keys) {
			if (kid != null && !kid.equals(jwk.kid())) {
				continue;
			}
			if (jwk.alg() != null && !jwk.alg().equals(alg.name())) {
				continue;
			}
			if (!alg.isCompatible(jwk.key())) {
				continue;
			}
			candidates.add(jwk);
		}
		// Without a key ID the choice must be unambiguous
		if (candidates.size() == 1 || (kid != null && !candidates.isEmpty())) {
			return candidates.get(0).key();
		}
		return null;
	}

	/**
	 * Parse a JWK Set, ignoring keys which are not public signature keys of a supported type.
	 * @param jwks JWK set JSON object
	 * @return list of keys
	 * @throws IOException if JWK set is malformed
	 */
	static List<Jwk> parseJwks(JsonObject jwks) throws IOException {
		JsonElement keysElem = jwks.get("keys");
		if (keysElem == null || !keysElem.isJsonArray()) {
			throw new IOException("JWK set missing 'keys' array");
		}
		List<Jwk> list = new ArrayList<>();
		for (JsonElement e : keysElem.getAsJsonArray()) {
			if (!e.isJsonObject()) {
				continue;
			}
			JsonObject jwk = e.getAsJsonObject();
			try {
				Jwk parsed = parseJwk(jwk);
				if (parsed != null) {
					list.add(parsed);
				}
			}
			catch (GeneralSecurityException | IllegalArgumentException ex) {
				Msg.warn(JwksKeyCache.class,
					"Ignoring invalid JWK (kid=" + OIDCHttp.getString(jwk, "kid") + "): " +
						ex.getMessage());
			}
		}
		return Collections.unmodifiableList(list);
	}

	private static Jwk parseJwk(JsonObject jwk) throws GeneralSecurityException {
		String use = OIDCHttp.getString(jwk, "use");
		if (use != null && !"sig".equals(use)) {
			return null;
		}
		String kty = OIDCHttp.getString(jwk, "kty");
		String kid = OIDCHttp.getString(jwk, "kid");
		String alg = OIDCHttp.getString(jwk, "alg");
		PublicKey key;
		if ("RSA".equals(kty)) {
			BigInteger n = decodeUnsigned(jwk, "n");
			BigInteger e = decodeUnsigned(jwk, "e");
			key = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(n, e));
		}
		else if ("EC".equals(kty)) {
			String crv = OIDCHttp.getString(jwk, "crv");
			String stdName = switch (Objects.toString(crv, "")) {
				case "P-256" -> "secp256r1";
				case "P-384" -> "secp384r1";
				case "P-521" -> "secp521r1";
				default -> null;
			};
			if (stdName == null) {
				return null; // unsupported curve
			}
			AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
			params.init(new ECGenParameterSpec(stdName));
			ECParameterSpec spec = params.getParameterSpec(ECParameterSpec.class);
			ECPoint point = new ECPoint(decodeUnsigned(jwk, "x"), decodeUnsigned(jwk, "y"));
			key = KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(point, spec));
		}
		else {
			return null; // unsupported key type (e.g., symmetric "oct")
		}
		return new Jwk(kid, alg, key);
	}

	private static BigInteger decodeUnsigned(JsonObject jwk, String name) {
		String value = OIDCHttp.getString(jwk, name);
		if (value == null) {
			throw new IllegalArgumentException("missing '" + name + "'");
		}
		return new BigInteger(1, Base64.getUrlDecoder().decode(value));
	}
}
