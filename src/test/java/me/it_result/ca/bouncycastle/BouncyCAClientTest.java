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
import static org.testng.AssertJUnit.assertNull;

import java.io.File;
import java.math.BigInteger;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

import me.it_result.ca.AlreadyInitializedException;
import me.it_result.ca.CA;
import me.it_result.ca.CAClient;
import me.it_result.ca.CAClientTest;
import me.it_result.ca.CAException;
import me.it_result.ca.X509Assertions;

import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.jce.X509Principal;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Optional;
import org.testng.annotations.Parameters;
import org.testng.annotations.Test;

/**
 * @author roman
 *
 */
public class BouncyCAClientTest extends CAClientTest {

	private static final String CA_KEYSTORE = "target/ca.keystore";
	private static final String KEYSTORE = "target/client.keystore";
	private static final String KEYSTORE_PASSWORD = "changeme";
	private static final int VALIDITY_DAYS = 365;

	private String jdkSignatureAlgorithm;
	
	private CA ca;
	private CAClient client;
	
	@BeforeMethod
	@Parameters({"keyAlgorithm", "keyBits", "bouncyCastleProviderSignatureAlgorithm", "jdkSignatureAlgorithm"})
	public void setUp(@Optional("RSA") String keyAlgorithm, @Optional("1024") int keyBits, @Optional("MD5WithRSA") String signatureAlgorithm, @Optional("MD5withRSA") String jdkSignatureAlgorithm) throws AlreadyInitializedException, CAException {
		this.jdkSignatureAlgorithm = jdkSignatureAlgorithm;
		ProfileRegistry profiles = ProfileRegistry.getDefaultInstance();
		ca = new BouncyCA(CA_KEYSTORE, keyAlgorithm, keyBits, VALIDITY_DAYS, KEYSTORE_PASSWORD, "CN=CA", jdkSignatureAlgorithm, profiles);
		client = new BouncyCAClient(KEYSTORE, keyAlgorithm, keyBits, VALIDITY_DAYS, KEYSTORE_PASSWORD, signatureAlgorithm, profiles);
		client.destroy();
		ca.destroy();
		ca.initialize();
	}
	
	@AfterMethod
	public void tearDown() {
		ca.destroy();
		client.destroy();
		new File(KEYSTORE).delete();
	}

	@Override
	protected CA ca() {
		return ca;
	}

	@Override
	protected CAClient client() {
		return client;
	}
	
	@Test
	public void testGenerateCSR() throws CertificateException, Exception {
		// Given CSR was never generated for 'CN=test,UID=test@test' subject name
		assertNull(client.getKeypair(SUBJECT_NAME));
		// When generateCSR('CN=test,UID=test@test') is invoked 
		Date minBeforeDate = new Date();
		byte[] csr = client.generateCSR(CERT_PARAMS);
		Date maxBeforeDate = new Date();
		// Then CSR is generated for the subject name
		PKCS10CertificationRequest parsedCsr = new PKCS10CertificationRequest(csr);
		assertEquals(new X509Principal(SUBJECT_NAME), parsedCsr.getCertificationRequestInfo().getSubject());
		// And a newly generated keypair is generated
		assertNotNull(client.getKeypair(SUBJECT_NAME));
		// And a self-signed certificate is generated
		X509Certificate selfSignedCert = client.getCertificate(SUBJECT_NAME);
		assertNotNull(selfSignedCert);
		new X509Assertions(selfSignedCert).
			caCertificate(false).
			issuedBy(selfSignedCert).
			serialNumber(new BigInteger("1")).
			signatureAlgrithm(jdkSignatureAlgorithm).
			subjectName(SUBJECT_NAME).
			type("X.509").
			version(3).
			validDuring(VALIDITY_DAYS, minBeforeDate, maxBeforeDate).
			keyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment).
			containsAKI().
			containsSKI().
			noMoreExtensions();
	}
	
}
