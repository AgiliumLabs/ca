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
package me.it_result.ca.bouncycastle;

import java.io.IOException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.sql.SQLException;

import me.it_result.ca.Authorization;
import me.it_result.ca.AuthorizationOutcome;
import me.it_result.ca.db.Database;

import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.util.encoders.Hex;

/**
 * @author roman
 *
 */
public class ChallengePasswordAuthorization implements Authorization {
	
	private static final String PASSWORD_PROPERTY = ChallengePasswordAuthorization.class.getName() + ".password";
	
	private Database database;
	
	public ChallengePasswordAuthorization(Database database) {
		this.database = database;
	}
	
	/* (non-Javadoc)
	 * @see me.it_result.ca.scep.Authorization#isAuthorized(org.bouncycastle.asn1.pkcs.CertificationRequest)
	 */
	@Override
	public AuthorizationOutcome isAuthorized(CertificationRequest certificationRequest) throws Exception {
		CertificationRequestInfo requestInfo = certificationRequest.getCertificationRequestInfo();
		X509Name subject = requestInfo.getSubject();
		String alias = Utils.generateAlias(subject);
		String expectedPassword = readPassword(alias);
		String actualPassword = Utils.extractChallengePassword(requestInfo.getAttributes()); 
		if (actualPassword != null && expectedPassword != null && actualPassword.equals(expectedPassword))
			return AuthorizationOutcome.ACCEPT;
		else
			return AuthorizationOutcome.REJECT;
	}
	
	@Override
	public void certificateEnrolled(X509Certificate certificate) throws Exception {
		String alias = Utils.generateAlias(certificate.getSubjectX500Principal());
		clearPassword(alias);
	}
	
	public void clearPassword(String alias) throws Exception {
		storePassword(alias, null);
	}

	public String generatePassword(String alias, int passwordBytes) throws Exception {
		SecureRandom rnd = new SecureRandom();
		byte[] password = new byte[passwordBytes];
		rnd.nextBytes(password);
		byte[] hexPassword = Hex.encode(password);
		String result = new String(hexPassword);
		storePassword(alias, result);
		return result;
	}
	
	public void storePassword(String alias, String password) throws Exception {
		try {
			if (password != null)
				database.writeString(alias, PASSWORD_PROPERTY, password);
			else
				database.removeProperty(alias, PASSWORD_PROPERTY);
		} catch (SQLException e) {
			throw new IOException(e);
		}
	}
	
	private String readPassword(String alias) throws Exception {
		try {
			String password = database.readString(alias, PASSWORD_PROPERTY);
			return password;
		} catch (SQLException e) {
			throw new IOException(e);
		}
	}
	
}