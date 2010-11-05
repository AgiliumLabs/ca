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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

/**
 * 
 * @author roman
 *
 */
public class CertificateFingerprint {

	private byte[] fingerprint;
	private String digestAlgorithm;
	
	/**
	 * @param fingerprint
	 * @param digestAlgorithm
	 */
	public CertificateFingerprint(byte[] fingerprint, String digestAlgorithm) {
		super();
		this.fingerprint = fingerprint;
		this.digestAlgorithm = digestAlgorithm;
	}

	public static CertificateFingerprint calculate(X509Certificate certificate) throws CertificateEncodingException, NoSuchAlgorithmException {
		byte[] encoded = certificate.getEncoded();
		MessageDigest digest = MessageDigest.getInstance("SHA-512");
		byte[] sha512 = digest.digest(encoded);
		return new CertificateFingerprint(sha512, "SHA-512");
	}

	/**
	 * @return the fingerprint
	 */
	public byte[] getFingerprint() {
		return fingerprint;
	}
	
	/**
	 * @param fingerprint the fingerprint to set
	 */
	public void setFingerprint(byte[] fingerprint) {
		this.fingerprint = fingerprint;
	}
	
	/**
	 * @return the digestAlgorithm
	 */
	public String getDigestAlgorithm() {
		return digestAlgorithm;
	}
	
	/**
	 * @param digestAlgorithm the digestAlgorithm to set
	 */
	public void setDigestAlgorithm(String digestAlgorithm) {
		this.digestAlgorithm = digestAlgorithm;
	}

	/* (non-Javadoc)
	 * @see java.lang.Object#hashCode()
	 */
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result
				+ ((digestAlgorithm == null) ? 0 : digestAlgorithm.hashCode());
		result = prime * result + Arrays.hashCode(fingerprint);
		return result;
	}

	/* (non-Javadoc)
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		CertificateFingerprint other = (CertificateFingerprint) obj;
		if (digestAlgorithm == null) {
			if (other.digestAlgorithm != null)
				return false;
		} else if (!digestAlgorithm.equals(other.digestAlgorithm))
			return false;
		if (!Arrays.equals(fingerprint, other.fingerprint))
			return false;
		return true;
	}
	
}
