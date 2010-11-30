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

import static org.testng.AssertJUnit.assertEquals;
import static org.testng.AssertJUnit.fail;

import java.net.URL;
import java.security.cert.X509Certificate;
import java.util.Set;

import me.it_result.ca.CA;
import me.it_result.ca.CAClient;
import me.it_result.ca.CAException;
import me.it_result.ca.UserCertificateParameters;
import me.it_result.ca.bouncycastle.BouncyCA;
import me.it_result.ca.bouncycastle.BouncyCAClient;
import me.it_result.ca.bouncycastle.ChallengePasswordAuthorization;
import me.it_result.ca.bouncycastle.ProfileRegistry;
import me.it_result.ca.db.Database;
import me.it_result.ca.db.FileDatabase;

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
public class ScepCAClientIntegrationTest {

	private static final String CA_DB_LOCATION = "target/scep.ca.keystore";
	private static final String CLIENT_DB_LOCATION = "target/scep.client.keystore";
	private static final String KEYSTORE_PASSWORD = "changeme";
	private static final int VALIDITY_DAYS = 365;
	private static final String ISSUER = "CN=SCEP-CA";
	private static final String CA_PROFILE = "default";
	private static final int SCEP_PORT = 8080;
	private static final String SERVLET_PATH = "/pkiclient.exe";
	private static final String SCEP_URL = "http://localhost:" + SCEP_PORT + SERVLET_PATH;
	private static final String SUBJECT_DN = "CN=client";
	private static final String SCEP_PASSWORD = "password";
	
	private ScepServer server;
	private ScepCAClient scepClient;
	
	@BeforeMethod
	@Parameters({"keyAlgorithm", "keyBits", "bouncyCastleProviderSignatureAlgorithm", "jdkSignatureAlgorithm"})
	public void setUp(@Optional("RSA") String keyAlgorithm, @Optional("1024") int keyBits, @Optional("MD5WithRSA") String signatureAlgorithm, @Optional("MD5withRSA") String jdkSignatureAlgorithm) throws Exception {
		CA ca = new BouncyCA(getCaDatabase(), keyAlgorithm, keyBits, VALIDITY_DAYS, KEYSTORE_PASSWORD, ISSUER, signatureAlgorithm, ProfileRegistry.getDefaultInstance());
		ca.destroy();
		ca.initialize();
		ChallengePasswordAuthorization authorization = new ChallengePasswordAuthorization(getPasswordDatabase());
		authorization.storePassword(SUBJECT_DN, SCEP_PASSWORD);
		server = new ScepServer(ca, authorization, SCEP_PORT);
		server.start();
		scepClient = initializeScepClient(ca, keyAlgorithm, keyBits, signatureAlgorithm);
	}
	
	private Database getPasswordDatabase() {
		return new FileDatabase(CA_DB_LOCATION + ".passwords");
	}

	private Database getCaDatabase() {
		return new FileDatabase(CA_DB_LOCATION);
	}
	
	private Database getClientDatabase() {
		return new FileDatabase(CLIENT_DB_LOCATION);
	}

	private CA getCa() {
		return server.getCa();
	}
	
	public ScepCAClient initializeScepClient(CA ca, String keyAlgorithm, int keyBits, String signatureAlgorithm) throws Exception {
		CAClient caClient = new BouncyCAClient(getClientDatabase(), keyAlgorithm, keyBits, VALIDITY_DAYS, KEYSTORE_PASSWORD, signatureAlgorithm, ProfileRegistry.getDefaultInstance());
		URL scepUrl = new URL(SCEP_URL);
		X509Certificate caCertificate = ca.getCACertificate();
		CertificateFingerprint caFingerprint = CertificateFingerprint.calculate(caCertificate);
		caClient.destroy();
		return new ScepCAClient(caClient, scepUrl, caFingerprint, CA_PROFILE);
	}
	
	@AfterMethod
	public void tearDown() throws Exception {
		try {
			server.stop();
		} catch (Exception e) {}
		try {
			if (getCa() != null)
				getCa().destroy();
			scepClient.getCaClient().destroy();
		} catch (Exception e) {}
		getPasswordDatabase().destroy();
		scepClient = null;
		server = null;
	}
	
	@Test
	public void testEnrollment() throws Exception {
		// When enrollCertificate is invoked 
		UserCertificateParameters params = new UserCertificateParameters();
		params.setChallengePassword(SCEP_PASSWORD);
		params.setSubjectDN(SUBJECT_DN);
		scepClient.enrollCertificate(params);
		// The certificate should be enrolled by the server
		CA ca = getCa();
		Set<X509Certificate> certificates = ca.listCertificates();
		assertEquals(1, certificates.size());
		assertEquals(new X509Principal(SUBJECT_DN), new X509Principal(certificates.iterator().next().getSubjectX500Principal().getName()));
		// And scep client should store the certificate locally
		assertEquals(certificates.iterator().next(), scepClient.getCaClient().getCertificate(SUBJECT_DN));
	}
	
	@Test
	public void testEnollmentInvalidPassword() throws CAException {
		// When enrollCertificate is invoked with an invalid password
		UserCertificateParameters params = new UserCertificateParameters();
		params.setChallengePassword("invalid");
		params.setSubjectDN(SUBJECT_DN);
		// The server must return a failure instead of enrolling the certificate
		try {
			scepClient.enrollCertificate(params);
			fail("ScepFailureException expected");
		} catch (ScepFailureException e) {}
	}
	
}
