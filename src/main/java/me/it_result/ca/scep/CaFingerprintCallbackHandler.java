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
import java.util.HashSet;
import java.util.Set;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.jscep.CertificateVerificationCallback;

/**
 * @author roman
 *
 */
public class CaFingerprintCallbackHandler implements CallbackHandler {

	private Set<CertificateFingerprint> fingerprints = new HashSet<CertificateFingerprint>();
	
	public CaFingerprintCallbackHandler(CertificateFingerprint fingerprint) {
		this.fingerprints.add(fingerprint);
	}
	
	public CaFingerprintCallbackHandler(Set<CertificateFingerprint> fingerprints) {
		this.fingerprints.addAll(fingerprints);
	}
	
	public void addFingerprint(CertificateFingerprint fingerprint) {
		fingerprints.add(fingerprint);
	}

	@Override
	public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
		for (int i = 0; i < callbacks.length; i++) {
			if (callbacks[i] instanceof CertificateVerificationCallback) {
				final CertificateVerificationCallback callback = (CertificateVerificationCallback) callbacks[i];
				callback.setVerified(false);
				for (CertificateFingerprint fingerprint: fingerprints) {
					try {
						CertificateFingerprint actualFingerprint = CertificateFingerprint.calculate(callback.getCertificate());
						if (fingerprint.equals(actualFingerprint)) {
							callback.setVerified(true);
							break;
						}
					} catch (Exception e) {
						throw new IOException(e);
					}
				}
			}
		}
	}		
	
}
