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

import static org.testng.AssertJUnit.assertEquals;
import static org.testng.AssertJUnit.assertNotNull;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import me.it_result.ca.AuthorizationOutcome;
import me.it_result.ca.db.Database;
import me.it_result.ca.db.FileDatabase;

import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.util.encoders.Base64;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

/**
 * @author roman
 *
 */
public class ChallengePasswordAuthorizationTest {

	private static final String PASSWORD_DB = "target/test.passwords.db";
	private static final String SUBJECT = "CN=client";

	private ChallengePasswordAuthorization authz;
	
	private X509Certificate signedCertificate;
	private PKCS10CertificationRequest csr;

	@BeforeMethod
	public void setUp() throws Exception {
		authz = new ChallengePasswordAuthorization(getDatabase());
		signedCertificate = readCertificate("MIICCzCCAXSgAwIBAgIBAjANBgkqhkiG9w0BAQ0FADANMQswCQYDVQQDDAJDQTAgFw0xMDExMjgxNDUwMDVaGA8yMTEwMTEwNDE0NTAwNVowETEPMA0GA1UEAwwGY2xpZW50MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCdfmXsFDt8ZtOmFlKnEa3SWkkijHqcLqLLjO6VKheTcsKYVelMO6Pn9IpS4BDVTjbLNQ9x614HUyAeQFeWJSTFeAuOiubGcVLxnjGErmvLqnuojovg46tnBjzerK6D05FfN64MeCc92FYhpQos4n+CEhGoRxecFIzuQACsGKJI/QIDAQABo3UwczAOBgNVHQ8BAf8EBAMCBaAwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQU8eCNRBSV6c2sFCokS5k09VVXGp0wHwYDVR0jBBgwFoAUdA2ASswyfseSnGAKIRK/+1Pe4jkwEwYDVR0lBAwwCgYIKwYBBQUHAwIwDQYJKoZIhvcNAQENBQADgYEAWHtgVYAX9TizU9MnNrQZwOpOqEeaB6Sb60kQRrso5XB/t5SYeKN0P3ciFuzPA56whwnSIIFHjXNT55YRCYK/sii37EfDWqCkcNgIo+s3jwIijLRtNK0y3HMzcjwfk1U+8Kjqcf3qYbjg0sBEqminm/WvUMYgLZlrJjuhwfmuHPM=");
		csr = readCsr("MIIBijCB9AIBADARMQ8wDQYDVQQDDAZjbGllbnQwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAJ1+ZewUO3xm06YWUqcRrdJaSSKMepwuosuM7pUqF5NywphV6Uw7o+f0ilLgENVONss1D3HrXgdTIB5AV5YlJMV4C46K5sZxUvGeMYSua8uqe6iOi+Djq2cGPN6sroPTkV83rgx4Jz3YViGlCizif4ISEahHF5wUjO5AAKwYokj9AgMBAAGgOjAWBgkqhkiG9w0BCQcxCRMHY29ycmVjdDAgBgkqhkiG9w0BCQMxExMRQ2xpZW50Q2VydGlmaWNhdGUwDQYJKoZIhvcNAQENBQADgYEAZf+j1YH6col9sp13psNe2kbyCqilJIk7aMH6NEjGUqtNd5jJFkQScU6eGKR3K2YF/niImN15BtnK8mXWNAnwnjQZP/vqoQSK0Vy+JJBO+xl/r74iqSKdQ8PP5rk1VVpqdjxYy3Se4elJusYFJUytG5rEVIs79FlpDVpCGZj3MCQ=");
	}
	
	private Database getDatabase() {
		return new FileDatabase(PASSWORD_DB);
	}

	@AfterMethod
	public void tearDown() throws Exception {
		getDatabase().destroy();
	}

	@Test
	public void testGeneratePassword() throws Exception {
		int lengthInBytes = 16;
		String password = authz.generatePassword(SUBJECT, lengthInBytes);
		assertNotNull(password);
		assertEquals(lengthInBytes*2, password.length());
	}
	
	@Test
	public void testAuthorizationCorrectPassword() throws Exception {
		authz.storePassword(SUBJECT, "correct");
		// authorization should succeed
		assertEquals(AuthorizationOutcome.ACCEPT, authz.isAuthorized(csr));
		// password can be used only once
		authz.certificateEnrolled(signedCertificate);
		assertEquals(AuthorizationOutcome.REJECT, authz.isAuthorized(csr));
	}
	
	private X509Certificate readCertificate(String base64EncodedCertificate) throws CertificateException {
		byte[] derCert = Base64.decode(base64EncodedCertificate);
		X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(derCert));
		return cert;
	}

	private PKCS10CertificationRequest readCsr(String base64EncodedCsr) {
		byte[] csr = Base64.decode(base64EncodedCsr);
		return new PKCS10CertificationRequest(csr);
	}

	@Test
	public void testAuthorizationInvalidPassword() throws Exception {
		authz.storePassword(SUBJECT, "invalid");
		// authorization should fail
		assertEquals(AuthorizationOutcome.REJECT, authz.isAuthorized(csr));
	}
	
	@Test
	public void testAuthorizationPasswordNotSet() throws Exception {
		// authorization should fail if password is not set
		assertEquals(AuthorizationOutcome.REJECT, authz.isAuthorized(csr));
	}
	
	@Test
	public void testAuthorizationCSRPasswordNotSet() throws Exception {
		PKCS10CertificationRequest nullPasswordCsr = readCsr("MIIBcjCB3AIBADARMQ8wDQYDVQQDDAZjbGllbnQwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAJ1+ZewUO3xm06YWUqcRrdJaSSKMepwuosuM7pUqF5NywphV6Uw7o+f0ilLgENVONss1D3HrXgdTIB5AV5YlJMV4C46K5sZxUvGeMYSua8uqe6iOi+Djq2cGPN6sroPTkV83rgx4Jz3YViGlCizif4ISEahHF5wUjO5AAKwYokj9AgMBAAGgIjAgBgkqhkiG9w0BCQMxExMRQ2xpZW50Q2VydGlmaWNhdGUwDQYJKoZIhvcNAQENBQADgYEAAQ28YbeIQOOFq7OuyRMcoErb1QtXn4vevGPoAX3RZcXqtEuAxopyKJMsiri9yFokgdAoLj60MzevJTDuwX2YNKbSg2tiVkVMwfcmzeD/hdnm9t+dB+XVhyiAAm/bTletJ8gKfxVkafTQyYuldRKRPlIOm6NZp8PAygCOO2VMT8o=");
		// authorization should fail if password is not set
		assertEquals(AuthorizationOutcome.REJECT, authz.isAuthorized(nullPasswordCsr));
	}
	
}
