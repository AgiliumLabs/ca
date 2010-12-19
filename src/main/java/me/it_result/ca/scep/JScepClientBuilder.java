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

import java.net.URL;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javax.security.auth.callback.CallbackHandler;

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
	
	public JScepClientBuilder identity(X509Certificate client, PrivateKey privateKey) {
		this.client = client;
		this.privateKey = privateKey;
		return this;
	}
	
	public JScepClientBuilder url(URL url) {
		this.url = url;
		return this;
	}
	
	public Client build() {
		return new Client(url, client, privateKey, callbackHandler, caIdentifier);
	}

	public JScepClientBuilder caFingerprint(CertificateFingerprint caCertificateFingerprint) {
		if (callbackHandler instanceof CaFingerprintCallbackHandler) {
			CaFingerprintCallbackHandler fingerprintCallbackHandler = (CaFingerprintCallbackHandler) callbackHandler;
			fingerprintCallbackHandler.addFingerprint(caCertificateFingerprint);
		} else 
			this.callbackHandler = new CaFingerprintCallbackHandler(caCertificateFingerprint);
		return this;
	}
	
	public JScepClientBuilder callbackHandler(CallbackHandler callbackHandler) {
		this.callbackHandler = callbackHandler;
		return this;
	}
	
}
