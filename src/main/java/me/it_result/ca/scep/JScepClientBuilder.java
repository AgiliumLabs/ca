/**
 * Copyright 2010 Roman Kisilenko
 *
 * This program is free software: you can redistribute it and/or modify it 
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your 
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT 
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or 
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License 
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package me.it_result.ca.scep;

import java.io.IOException;
import java.net.URL;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.jscep.CertificateVerificationCallback;
import org.jscep.client.Client;

/**
 * @author roman
 *
 */
public class JScepClientBuilder {

	private String caIdentifier;
	private X509Certificate client;
	private PrivateKey privateKey;
	private URL url;
	private CallbackHandler callbackHandler;
	
	public JScepClientBuilder caIdentifier(String caIdentifier) {
		this.caIdentifier = caIdentifier;
		return this;
	}
	
	public void identity(X509Certificate client, PrivateKey privateKey) {
		this.client = client;
		this.privateKey = privateKey;
	}
	
	public JScepClientBuilder url(URL url) {
		this.url = url;
		return this;
	}
	
	public Client build() {
		return new Client(url, client, privateKey, callbackHandler, caIdentifier);
	}

	public JScepClientBuilder caFingerprint(CertificateFingerprint caCertificateFingerprint) {
		this.callbackHandler = new CaFingerprintCallbackHandler(caCertificateFingerprint);
		return this;
	}
	
	public static class CaFingerprintCallbackHandler implements CallbackHandler {

		private CertificateFingerprint fingerprint;
		
		public CaFingerprintCallbackHandler(CertificateFingerprint fingerprint) {
			this.fingerprint = fingerprint;
		}

		@Override
		public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
			for (int i = 0; i < callbacks.length; i++) {
				if (callbacks[i] instanceof CertificateVerificationCallback) {
					final CertificateVerificationCallback callback = (CertificateVerificationCallback) callbacks[i];
					try {
						CertificateFingerprint actualFingerprint = CertificateFingerprint.calculate(callback.getCertificate());
						callback.setVerified(fingerprint.equals(actualFingerprint));
					} catch (Exception e) {
						throw new IOException(e);
					}
				}
			}
		}		
		
	}
	
}
