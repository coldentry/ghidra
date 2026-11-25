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
import java.net.http.HttpClient;
import java.security.PublicKey;
import java.time.Clock;

import com.google.gson.JsonObject;

import ghidra.util.Msg;

/**
 * <code>OIDCProvider</code> performs OpenID Connect discovery for the configured issuer and
 * provides access to its signing keys.  Discovery is performed lazily and retried on failure
 * (subject to a minimum retry interval) so that a temporarily unavailable identity provider
 * does not prevent server startup.
 */
public class OIDCProvider implements IdTokenValidator.KeyResolver {

	static final long DISCOVERY_RETRY_INTERVAL_MS = 10_000;

	private final String issuer;
	private final HttpClient httpClient;
	private final Clock clock;

	private JwksKeyCache keyCache;
	private long lastDiscoveryAttempt = Long.MIN_VALUE / 2;
	private String lastDiscoveryError;

	/**
	 * Construct OIDC provider
	 * @param issuer OIDC issuer identifier
	 * @param httpClient HTTP client
	 * @param clock clock
	 */
	public OIDCProvider(String issuer, HttpClient httpClient, Clock clock) {
		this.issuer = issuer;
		this.httpClient = httpClient;
		this.clock = clock;
	}

	/**
	 * Perform discovery if not yet completed.
	 * @throws IOException if discovery fails
	 */
	public synchronized void discover() throws IOException {
		if (keyCache != null) {
			return;
		}
		long now = clock.millis();
		if (now - lastDiscoveryAttempt < DISCOVERY_RETRY_INTERVAL_MS) {
			throw new IOException("OIDC discovery failed: " + lastDiscoveryError);
		}
		lastDiscoveryAttempt = now;
		try {
			String base =
				issuer.endsWith("/") ? issuer.substring(0, issuer.length() - 1) : issuer;
			URI discoveryUri = OIDCHttp.parseSecureUri(
				base + "/.well-known/openid-configuration", "OIDC discovery URI");
			JsonObject metadata = OIDCHttp.getJson(httpClient, discoveryUri);
			String reportedIssuer = OIDCHttp.getString(metadata, "issuer");
			if (!issuer.equals(reportedIssuer)) {
				throw new IOException("issuer mismatch: configured " + issuer +
					" but provider reported " + reportedIssuer);
			}
			URI jwksUri =
				OIDCHttp.parseSecureUri(OIDCHttp.getString(metadata, "jwks_uri"), "jwks_uri");
			keyCache = new JwksKeyCache(httpClient, jwksUri, clock);
			lastDiscoveryError = null;
			Msg.info(this, "OIDC discovery complete for " + issuer + " (jwks_uri=" + jwksUri +
				")");
		}
		catch (IOException e) {
			lastDiscoveryError = e.getMessage();
			throw new IOException("OIDC discovery failed: " + e.getMessage(), e);
		}
	}

	@Override
	public PublicKey getKey(String kid, JwsAlgorithm alg) throws IOException {
		JwksKeyCache cache;
		synchronized (this) {
			discover();
			cache = keyCache;
		}
		return cache.getKey(kid, alg);
	}
}
