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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.channels.FileLock;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Properties;

import me.it_result.ca.Authorization;
import me.it_result.ca.AuthorizationOutcome;

import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.util.encoders.Hex;

/**
 * @author roman
 *
 */
public class ChallengePasswordAuthorization implements Authorization {
	
	private String databaseFileName;
	private FileLock dbLock;
	
	public ChallengePasswordAuthorization(String databaseFileName) {
		this.databaseFileName = databaseFileName;
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
	
	public void clearPassword(String alias) throws IOException {
		storePassword(alias, null);
	}

	public String generatePassword(String alias, int passwordBytes) throws IOException {
		SecureRandom rnd = new SecureRandom();
		byte[] password = new byte[passwordBytes];
		rnd.nextBytes(password);
		byte[] hexPassword = Hex.encode(password);
		String result = new String(hexPassword);
		storePassword(alias, result);
		return result;
	}
	
	public void storePassword(String alias, String password) throws IOException {
		try {
			lockDatabase();
			Properties db = readDatabase();
			if (password != null)
				db.setProperty(alias, password);
			else
				db.remove(alias);
			writeDatabase(db);
		} finally {
			unlockDatabase();
		}
	}
	
	private void unlockDatabase() {
		if (dbLock != null) {
			try { dbLock.release(); } catch (Exception e) {}
			try { dbLock.channel().close(); } catch (Exception e) {}
			dbLock = null;
		}
	}

	private void lockDatabase() throws IOException {
		File databaseFile = new File(databaseFileName);
		if (databaseFile.exists()) {
			dbLock = new RandomAccessFile(databaseFileName, "rw").
				getChannel().
				lock();
		}
	}

	private String readPassword(String alias) throws IOException {
		try {
			lockDatabase();
			Properties db = readDatabase();
			String password = db.getProperty(alias);
			return password;
		} finally {
			unlockDatabase();
		}
	}
	
	private Properties readDatabase() throws IOException {
		File databaseFile = new File(databaseFileName);
		if (databaseFile.exists()) {
			FileInputStream fis = null;
			try {
				fis = new FileInputStream(databaseFile);
				Properties db = new Properties();
				db.load(fis);
				return db;
			} finally {
				if (fis != null)
					try { fis.close(); } catch (Exception e) {}
			}
		}
		else 
			return new Properties();
	}
	
	private void writeDatabase(Properties db) throws IOException {
		FileOutputStream fos = null;
		try {
			fos = new FileOutputStream(databaseFileName);
			db.store(fos, null);
		} finally {
			if (fos != null)
				try { fos.close(); } catch (Exception e) {}
		}
	}

}