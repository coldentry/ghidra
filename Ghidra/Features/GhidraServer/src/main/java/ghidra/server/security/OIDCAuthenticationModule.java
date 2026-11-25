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

import java.io.File;
import java.io.IOException;
import java.time.Clock;
import java.util.List;
import java.util.Locale;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;

import com.google.gson.JsonObject;

import ghidra.framework.remote.OIDCCallback;
import ghidra.net.HttpClients;
import ghidra.server.UserManager;
import ghidra.server.security.oidc.*;
import ghidra.util.Msg;

/**
 * <code>OIDCAuthenticationModule</code> authenticates users with an OpenID Connect identity
 * provider (e.g., Microsoft Entra ID, Keycloak).  The client performs an Authorization Code
 * flow with PKCE and returns the resulting ID token which is validated by this module.  The
 * OIDC nonce is derived from a single-use, time-limited token issued by the server, which
 * prevents replay of ID tokens.
 */
public class OIDCAuthenticationModule implements AuthenticationModule {

	private final OIDCConfiguration config;
	private final OIDCProvider provider;
	private final IdTokenValidator validator;

	/**
	 * Construct OIDC authentication module from configuration file.
	 * @param configFile OIDC configuration file
	 * @throws IOException if configuration could not be loaded or is invalid
	 */
	public OIDCAuthenticationModule(File configFile) throws IOException {
		this(OIDCConfiguration.load(configFile), null, Clock.systemUTC());
	}

	/**
	 * Construct OIDC authentication module.
	 * @param config OIDC configuration
	 * @param keyResolver signing key resolver, or null to use OIDC discovery for the
	 * configured issuer
	 * @param clock clock
	 * @throws IOException if HTTP client could not be initialized
	 */
	OIDCAuthenticationModule(OIDCConfiguration config, IdTokenValidator.KeyResolver keyResolver,
			Clock clock) throws IOException {
		this.config = config;
		if (keyResolver == null) {
			provider = new OIDCProvider(config.getIssuer(), HttpClients.getHttpClient(), clock);
			try {
				provider.discover();
			}
			catch (IOException e) {
				// Allow server to start - discovery will be retried on login
				Msg.warn(this, e.getMessage() + " (will retry on login)");
			}
			keyResolver = provider;
		}
		else {
			provider = null;
		}
		validator = new IdTokenValidator(config, keyResolver, clock);
	}

	/**
	 * {@return OIDC configuration}
	 */
	public OIDCConfiguration getConfiguration() {
		return config;
	}

	@Override
	public Callback[] getAuthenticationCallbacks() {
		byte[] token = TokenGenerator.getNewToken(config.getLoginTimeoutSeconds() * 1000L);
		return new Callback[] {
			new OIDCCallback(config.getIssuer(), config.getClientId(), config.getScopes(),
				config.getAuthParams(), config.getRedirectPort(),
				config.getLoginTimeoutSeconds(), token) };
	}

	@Override
	public boolean anonymousCallbacksAllowed() {
		return false;
	}

	@Override
	public boolean isNameCallbackAllowed() {
		return false;
	}

	@Override
	public String authenticate(UserManager userMgr, Subject subject, Callback[] callbacks)
			throws LoginException {
		OIDCCallback oidcCb =
			AuthenticationModule.getFirstCallbackOfType(OIDCCallback.class, callbacks);
		if (oidcCb == null) {
			throw new FailedLoginException("OIDC callback not found");
		}
		byte[] token = oidcCb.getToken();
		if (token == null) {
			throw new FailedLoginException("OIDC callback token missing");
		}

		JsonObject claims;
		try {
			claims = validator.validate(oidcCb.getIdToken(), OIDCCallback.getNonce(token));
		}
		catch (IOException e) {
			throw new LoginException("Unable to validate OIDC ID token: " + e.getMessage());
		}

		// Consume server issued token only after the ID token has been validated and bound
		// to it via the nonce claim
		if (!TokenGenerator.isValidToken(token)) {
			throw new FailedLoginException("Stale or reused OIDC login token");
		}

		checkRequiredClaim(claims);
		String username = mapUsername(claims);

		Msg.info(this, "OIDC authenticated " + config.getIssuer() + " subject " +
			getSubjectId(claims) + " as user '" + username + "'");
		return username;
	}

	private static String getSubjectId(JsonObject claims) {
		List<String> oid = IdTokenValidator.getClaimStrings(claims, "oid"); // Entra object ID
		List<String> sub = IdTokenValidator.getClaimStrings(claims, "sub");
		String id = sub.isEmpty() ? "?" : sub.get(0);
		if (!oid.isEmpty()) {
			id += " (oid " + oid.get(0) + ")";
		}
		return id;
	}

	private void checkRequiredClaim(JsonObject claims) throws FailedLoginException {
		String requiredClaim = config.getRequiredClaim();
		if (requiredClaim == null) {
			return;
		}
		for (String value : IdTokenValidator.getClaimStrings(claims, requiredClaim)) {
			if (config.getRequiredClaimValues().contains(value)) {
				return;
			}
		}
		throw new FailedLoginException(
			"OIDC user lacks required '" + requiredClaim + "' claim value");
	}

	/**
	 * Map validated ID token claims to a Ghidra user name.
	 * @param claims validated claims
	 * @return Ghidra user name
	 * @throws FailedLoginException if a valid user name could not be produced
	 */
	String mapUsername(JsonObject claims) throws FailedLoginException {
		String claimName = config.getUsernameClaim();
		List<String> values = IdTokenValidator.getClaimStrings(claims, claimName);
		if (values.size() != 1 || values.get(0).isBlank()) {
			throw new FailedLoginException("OIDC ID token lacks '" + claimName + "' claim");
		}
		String name = values.get(0).trim();

		String domain = null;
		int atIndex = name.lastIndexOf('@');
		if (atIndex >= 0) {
			domain = name.substring(atIndex + 1).toLowerCase(Locale.ROOT);
		}
		if (!config.getAllowedDomains().isEmpty() &&
			(domain == null || !config.getAllowedDomains().contains(domain))) {
			throw new FailedLoginException("OIDC user domain not allowed: " + name);
		}
		if (atIndex >= 0 && config.isStripDomain()) {
			name = name.substring(0, atIndex);
		}
		if (config.isLowercaseUsername()) {
			name = name.toLowerCase(Locale.ROOT);
		}
		if (!UserManager.isValidUserName(name)) {
			throw new FailedLoginException(
				"OIDC '" + claimName + "' claim is not a valid Ghidra user name: " + name);
		}
		return name;
	}
}
