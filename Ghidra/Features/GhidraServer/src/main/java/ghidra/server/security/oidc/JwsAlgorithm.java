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

import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.*;

/**
 * <code>JwsAlgorithm</code> enumerates the asymmetric JWS signature algorithms (RFC 7518)
 * supported for OIDC ID token validation.  Symmetric (HMAC) algorithms and <code>none</code>
 * are intentionally not supported.
 */
public enum JwsAlgorithm {

	RS256("SHA256withRSA", null, "RSA", 0),
	RS384("SHA384withRSA", null, "RSA", 0),
	RS512("SHA512withRSA", null, "RSA", 0),
	PS256("RSASSA-PSS", pss("SHA-256", MGF1ParameterSpec.SHA256, 32), "RSA", 0),
	PS384("RSASSA-PSS", pss("SHA-384", MGF1ParameterSpec.SHA384, 48), "RSA", 0),
	PS512("RSASSA-PSS", pss("SHA-512", MGF1ParameterSpec.SHA512, 64), "RSA", 0),
	ES256("SHA256withECDSAinP1363Format", null, "EC", 256),
	ES384("SHA384withECDSAinP1363Format", null, "EC", 384),
	ES512("SHA512withECDSAinP1363Format", null, "EC", 521);

	/**
	 * Minimum accepted RSA modulus size in bits.
	 */
	public static final int MIN_RSA_KEY_BITS = 2048;

	private final String jcaName;
	private final PSSParameterSpec pssSpec;
	private final String keyType;
	private final int ecFieldBits;

	private JwsAlgorithm(String jcaName, PSSParameterSpec pssSpec, String keyType,
			int ecFieldBits) {
		this.jcaName = jcaName;
		this.pssSpec = pssSpec;
		this.keyType = keyType;
		this.ecFieldBits = ecFieldBits;
	}

	private static PSSParameterSpec pss(String digest, MGF1ParameterSpec mgf, int saltLen) {
		return new PSSParameterSpec(digest, "MGF1", mgf, saltLen, PSSParameterSpec.TRAILER_FIELD_BC);
	}

	/**
	 * {@return JWK key type (<code>kty</code>) required by this algorithm}
	 */
	public String getKeyType() {
		return keyType;
	}

	/**
	 * Find algorithm by its JWS name.
	 * @param name JWS <code>alg</code> name (case sensitive)
	 * @return algorithm or null if not supported
	 */
	public static JwsAlgorithm forName(String name) {
		if (name == null) {
			return null;
		}
		for (JwsAlgorithm alg : values()) {
			if (alg.name().equals(name)) {
				return alg;
			}
		}
		return null;
	}

	/**
	 * {@return set of all supported algorithm names}
	 */
	public static Set<String> getSupportedNames() {
		Set<String> set = new LinkedHashSet<>();
		for (JwsAlgorithm alg : values()) {
			set.add(alg.name());
		}
		return Collections.unmodifiableSet(set);
	}

	/**
	 * Determine if the specified public key is suitable for this algorithm.
	 * @param key public key
	 * @return true if suitable
	 */
	public boolean isCompatible(PublicKey key) {
		if ("RSA".equals(keyType)) {
			return key instanceof RSAPublicKey rsa &&
				rsa.getModulus().bitLength() >= MIN_RSA_KEY_BITS;
		}
		return key instanceof ECPublicKey ec &&
			ec.getParams().getCurve().getField().getFieldSize() == ecFieldBits;
	}

	/**
	 * Verify a JWS signature.
	 * @param key public key (must be {@link #isCompatible(PublicKey) compatible})
	 * @param signingInput JWS signing input (ASCII bytes of <code>header.payload</code>)
	 * @param signature decoded JWS signature bytes
	 * @return true if signature is valid
	 * @throws GeneralSecurityException if verification could not be performed
	 */
	public boolean verify(PublicKey key, byte[] signingInput, byte[] signature)
			throws GeneralSecurityException {
		if (!isCompatible(key)) {
			throw new InvalidKeyException("Key is not compatible with " + name());
		}
		if (ecFieldBits != 0) {
			// P1363 format: R || S, each the size of the curve order
			int len = 2 * ((ecFieldBits + 7) / 8);
			if (signature.length != len) {
				return false;
			}
		}
		Signature sig = Signature.getInstance(jcaName);
		if (pssSpec != null) {
			sig.setParameter(pssSpec);
		}
		sig.initVerify(key);
		sig.update(signingInput);
		return sig.verify(signature);
	}
}
