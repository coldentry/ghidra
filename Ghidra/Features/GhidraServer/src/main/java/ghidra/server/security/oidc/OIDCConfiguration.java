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

import java.io.*;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * <code>OIDCConfiguration</code> holds the Ghidra Server OpenID Connect configuration which is
 * loaded from a Java properties file (see <code>server/oidc.conf</code>).
 */
public class OIDCConfiguration {

	public static final String ISSUER = "issuer";
	public static final String CLIENT_ID = "client_id";
	public static final String SCOPES = "scopes";
	public static final String AUDIENCE = "audience";
	public static final String USERNAME_CLAIM = "username_claim";
	public static final String STRIP_DOMAIN = "strip_domain";
	public static final String LOWERCASE_USERNAME = "lowercase_username";
	public static final String ALLOWED_DOMAINS = "allowed_domains";
	public static final String REQUIRED_CLAIM = "required_claim";
	public static final String REQUIRED_CLAIM_VALUES = "required_claim_values";
	public static final String REDIRECT_PORT = "redirect_port";
	public static final String AUTH_PARAMS = "auth_params";
	public static final String ALLOWED_ALGORITHMS = "allowed_algorithms";
	public static final String CLOCK_SKEW_SECONDS = "clock_skew_seconds";
	public static final String LOGIN_TIMEOUT_SECONDS = "login_timeout_seconds";

	private static final Set<String> KNOWN_PROPERTIES = Set.of(ISSUER, CLIENT_ID, SCOPES,
		AUDIENCE, USERNAME_CLAIM, STRIP_DOMAIN, LOWERCASE_USERNAME, ALLOWED_DOMAINS, REQUIRED_CLAIM,
		REQUIRED_CLAIM_VALUES, REDIRECT_PORT, AUTH_PARAMS, ALLOWED_ALGORITHMS,
		CLOCK_SKEW_SECONDS, LOGIN_TIMEOUT_SECONDS);

	static final String DEFAULT_SCOPES = "openid profile email";
	static final String DEFAULT_USERNAME_CLAIM = "preferred_username";
	static final int DEFAULT_CLOCK_SKEW_SECONDS = 120;
	static final int DEFAULT_LOGIN_TIMEOUT_SECONDS = 300;

	private final String issuer;
	private final String clientId;
	private final String scopes;
	private final String audience;
	private final String usernameClaim;
	private final boolean stripDomain;
	private final boolean lowercaseUsername;
	private final Set<String> allowedDomains;
	private final String requiredClaim;
	private final Set<String> requiredClaimValues;
	private final int redirectPort;
	private final String authParams;
	private final Set<String> allowedAlgorithms;
	private final int clockSkewSeconds;
	private final int loginTimeoutSeconds;

	/**
	 * Load configuration from a properties file.
	 * @param file configuration file
	 * @return configuration
	 * @throws IOException if file cannot be read or configuration is invalid
	 */
	public static OIDCConfiguration load(File file) throws IOException {
		Properties props = new Properties();
		try (Reader r = new InputStreamReader(new FileInputStream(file),
			StandardCharsets.UTF_8)) {
			props.load(r);
		}
		try {
			return new OIDCConfiguration(props);
		}
		catch (IllegalArgumentException e) {
			throw new IOException("Invalid OIDC configuration (" + file + "): " + e.getMessage(),
				e);
		}
	}

	/**
	 * Construct configuration from properties.
	 * @param props configuration properties
	 * @throws IllegalArgumentException if configuration is invalid
	 */
	public OIDCConfiguration(Properties props) {
		for (String name : props.stringPropertyNames()) {
			if (!KNOWN_PROPERTIES.contains(name)) {
				throw new IllegalArgumentException("unknown property: " + name);
			}
		}

		issuer = required(props, ISSUER);
		validateIssuer(issuer);
		clientId = required(props, CLIENT_ID);

		scopes = normalizeSpaces(get(props, SCOPES, DEFAULT_SCOPES));
		if (!Arrays.asList(scopes.split(" ")).contains("openid")) {
			throw new IllegalArgumentException(SCOPES + " must include 'openid'");
		}

		audience = get(props, AUDIENCE, clientId);
		usernameClaim = get(props, USERNAME_CLAIM, DEFAULT_USERNAME_CLAIM);
		stripDomain = getBoolean(props, STRIP_DOMAIN, true);
		lowercaseUsername = getBoolean(props, LOWERCASE_USERNAME, true);
		allowedDomains = Collections.unmodifiableSet(lowerCaseSet(getList(props, ALLOWED_DOMAINS)));

		requiredClaim = get(props, REQUIRED_CLAIM, null);
		requiredClaimValues =
			Collections.unmodifiableSet(new LinkedHashSet<>(getList(props, REQUIRED_CLAIM_VALUES)));
		if (requiredClaim != null && requiredClaimValues.isEmpty()) {
			throw new IllegalArgumentException(
				REQUIRED_CLAIM_VALUES + " must be specified when " + REQUIRED_CLAIM + " is set");
		}
		if (requiredClaim == null && !requiredClaimValues.isEmpty()) {
			throw new IllegalArgumentException(
				REQUIRED_CLAIM + " must be specified when " + REQUIRED_CLAIM_VALUES + " is set");
		}

		redirectPort = getInt(props, REDIRECT_PORT, 0, 0, 65535);
		authParams = get(props, AUTH_PARAMS, null);

		List<String> algs = getList(props, ALLOWED_ALGORITHMS);
		if (algs.isEmpty()) {
			allowedAlgorithms = JwsAlgorithm.getSupportedNames();
		}
		else {
			Set<String> set = new LinkedHashSet<>();
			for (String alg : algs) {
				if (JwsAlgorithm.forName(alg) == null) {
					throw new IllegalArgumentException("unsupported algorithm: " + alg);
				}
				set.add(alg);
			}
			allowedAlgorithms = Collections.unmodifiableSet(set);
		}

		clockSkewSeconds =
			getInt(props, CLOCK_SKEW_SECONDS, DEFAULT_CLOCK_SKEW_SECONDS, 0, 3600);
		loginTimeoutSeconds =
			getInt(props, LOGIN_TIMEOUT_SECONDS, DEFAULT_LOGIN_TIMEOUT_SECONDS, 30, 3600);
	}

	private static void validateIssuer(String issuer) {
		URI uri;
		try {
			uri = new URI(issuer);
		}
		catch (URISyntaxException e) {
			throw new IllegalArgumentException("invalid " + ISSUER + ": " + issuer);
		}
		if (uri.getHost() == null || uri.getRawQuery() != null || uri.getRawFragment() != null) {
			throw new IllegalArgumentException("invalid " + ISSUER + ": " + issuer);
		}
		if (!OIDCHttp.isSecureUri(uri)) {
			throw new IllegalArgumentException(ISSUER + " must use https: " + issuer);
		}
		String host = uri.getHost().toLowerCase(Locale.ROOT);
		String path = Objects.toString(uri.getPath(), "") + "/";
		boolean microsoft = host.equals("login.microsoftonline.com") ||
			host.equals("login.microsoftonline.us") || host.equals("login.partner.microsoftonline.cn");
		if (microsoft && (path.startsWith("/common/") || path.startsWith("/organizations/") ||
			path.startsWith("/consumers/") || issuer.contains("{tenantid}"))) {
			throw new IllegalArgumentException(
				"multi-tenant Microsoft issuers are not supported, use tenant-specific issuer: " +
					issuer);
		}
	}

	private static String get(Properties props, String name, String defaultValue) {
		String value = props.getProperty(name);
		if (value == null || value.isBlank()) {
			return defaultValue;
		}
		return value.trim();
	}

	private static String required(Properties props, String name) {
		String value = get(props, name, null);
		if (value == null) {
			throw new IllegalArgumentException("missing required property: " + name);
		}
		return value;
	}

	private static boolean getBoolean(Properties props, String name, boolean defaultValue) {
		String value = get(props, name, null);
		if (value == null) {
			return defaultValue;
		}
		if ("true".equalsIgnoreCase(value)) {
			return true;
		}
		if ("false".equalsIgnoreCase(value)) {
			return false;
		}
		throw new IllegalArgumentException(name + " must be true or false");
	}

	private static int getInt(Properties props, String name, int defaultValue, int min,
			int max) {
		String value = get(props, name, null);
		if (value == null) {
			return defaultValue;
		}
		try {
			int v = Integer.parseInt(value);
			if (v >= min && v <= max) {
				return v;
			}
		}
		catch (NumberFormatException e) {
			// fall through
		}
		throw new IllegalArgumentException(
			name + " must be an integer between " + min + " and " + max);
	}

	private static List<String> getList(Properties props, String name) {
		String value = get(props, name, null);
		List<String> list = new ArrayList<>();
		if (value != null) {
			for (String s : value.split("[,\\s]+")) {
				if (!s.isEmpty()) {
					list.add(s);
				}
			}
		}
		return list;
	}

	private static Set<String> lowerCaseSet(List<String> list) {
		Set<String> set = new LinkedHashSet<>();
		for (String s : list) {
			set.add(s.toLowerCase(Locale.ROOT));
		}
		return set;
	}

	private static String normalizeSpaces(String s) {
		return String.join(" ", s.trim().split("\\s+"));
	}

	/**
	 * {@return OIDC issuer identifier}
	 */
	public String getIssuer() {
		return issuer;
	}

	/**
	 * {@return OAuth client ID}
	 */
	public String getClientId() {
		return clientId;
	}

	/**
	 * {@return space-separated scopes}
	 */
	public String getScopes() {
		return scopes;
	}

	/**
	 * {@return required ID token audience (defaults to client ID)}
	 */
	public String getAudience() {
		return audience;
	}

	/**
	 * {@return name (or dotted path) of claim which provides the Ghidra user name}
	 */
	public String getUsernameClaim() {
		return usernameClaim;
	}

	/**
	 * {@return true if any <code>@domain</code> suffix should be removed from user name}
	 */
	public boolean isStripDomain() {
		return stripDomain;
	}

	/**
	 * {@return true if user name should be converted to lower-case}
	 */
	public boolean isLowercaseUsername() {
		return lowercaseUsername;
	}

	/**
	 * {@return set of allowed lower-case domains (empty if any domain is permitted)}
	 */
	public Set<String> getAllowedDomains() {
		return allowedDomains;
	}

	/**
	 * {@return name (or dotted path) of claim which must contain one of
	 * {@link #getRequiredClaimValues()}, or null if not required}
	 */
	public String getRequiredClaim() {
		return requiredClaim;
	}

	/**
	 * {@return set of acceptable required-claim values}
	 */
	public Set<String> getRequiredClaimValues() {
		return requiredClaimValues;
	}

	/**
	 * {@return preferred client loopback redirect port (0 = any)}
	 */
	public int getRedirectPort() {
		return redirectPort;
	}

	/**
	 * {@return additional authorization request parameters, or null}
	 */
	public String getAuthParams() {
		return authParams;
	}

	/**
	 * {@return set of allowed JWS algorithm names}
	 */
	public Set<String> getAllowedAlgorithms() {
		return allowedAlgorithms;
	}

	/**
	 * {@return allowed clock skew in seconds}
	 */
	public int getClockSkewSeconds() {
		return clockSkewSeconds;
	}

	/**
	 * {@return time allowed to complete login in seconds}
	 */
	public int getLoginTimeoutSeconds() {
		return loginTimeoutSeconds;
	}
}
