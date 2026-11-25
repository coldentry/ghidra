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
package ghidra.framework.remote;

import java.io.Serializable;
import java.util.Base64;

import javax.security.auth.callback.Callback;

/**
 * <code>OIDCCallback</code> provides a Callback implementation used to perform OpenID Connect
 * (OIDC) authentication.  This callback is instantiated by the server with the identity
 * provider details the client needs to perform an OIDC Authorization Code flow with PKCE,
 * along with a random single-use token from which the OIDC <code>nonce</code> is derived.
 * <p>
 * It is the responsibility of the callback handler to authenticate the user with the
 * identity provider, set the resulting ID token via {@link #setIdToken(String)} and return
 * this object in response to the callback.  The server validates the ID token signature and
 * claims, including the nonce, so the ID token must be obtained and returned within the
 * login timeout imposed by the server.
 */
public class OIDCCallback implements Callback, Serializable {

	public static final long serialVersionUID = 1L;

	private final String issuer;
	private final String clientId;
	private final String scope;
	private final String authParams;
	private final int redirectPort;
	private final int loginTimeoutSeconds;
	private final byte[] token;

	private String idToken;

	/**
	 * Construct an OIDC callback.
	 * @param issuer OIDC issuer identifier URL (discovery document is located relative to this)
	 * @param clientId OAuth client ID registered with the identity provider
	 * @param scope space-separated list of requested scopes (must include <code>openid</code>)
	 * @param authParams optional additional authorization request query parameters in
	 * <code>name=value&amp;name=value</code> form (may be null)
	 * @param redirectPort preferred loopback redirect port, or 0 if the client may choose
	 * @param loginTimeoutSeconds time allowed to complete the login
	 * @param token random single-use token issued by the server (basis for the OIDC nonce)
	 */
	public OIDCCallback(String issuer, String clientId, String scope, String authParams,
			int redirectPort, int loginTimeoutSeconds, byte[] token) {
		this.issuer = issuer;
		this.clientId = clientId;
		this.scope = scope;
		this.authParams = authParams;
		this.redirectPort = redirectPort;
		this.loginTimeoutSeconds = loginTimeoutSeconds;
		this.token = token;
	}

	/**
	 * {@return the OIDC issuer identifier URL}
	 */
	public String getIssuer() {
		return issuer;
	}

	/**
	 * {@return the OAuth client ID}
	 */
	public String getClientId() {
		return clientId;
	}

	/**
	 * {@return space-separated list of requested scopes}
	 */
	public String getScope() {
		return scope;
	}

	/**
	 * {@return additional authorization request parameters (<code>name=value&amp;...</code>)
	 * or null}
	 */
	public String getAuthParams() {
		return authParams;
	}

	/**
	 * {@return preferred loopback redirect port, or 0 if the client may choose any port}
	 */
	public int getRedirectPort() {
		return redirectPort;
	}

	/**
	 * {@return number of seconds allowed to complete the login}
	 */
	public int getLoginTimeoutSeconds() {
		return loginTimeoutSeconds;
	}

	/**
	 * {@return the server issued token}
	 */
	public byte[] getToken() {
		return token;
	}

	/**
	 * {@return the OIDC nonce which must be included in the authorization request and
	 * which will be present in the resulting ID token}
	 */
	public String getNonce() {
		return getNonce(token);
	}

	/**
	 * Compute the OIDC nonce corresponding to a server issued token.
	 * @param token server issued token
	 * @return base64url (unpadded) encoding of token
	 */
	public static String getNonce(byte[] token) {
		return Base64.getUrlEncoder().withoutPadding().encodeToString(token);
	}

	/**
	 * {@return the ID token set by the callback handler, or null if not set}
	 */
	public String getIdToken() {
		return idToken;
	}

	/**
	 * Set the ID token (compact JWS) obtained from the identity provider.
	 * @param idToken ID token
	 */
	public void setIdToken(String idToken) {
		this.idToken = idToken;
	}

}
