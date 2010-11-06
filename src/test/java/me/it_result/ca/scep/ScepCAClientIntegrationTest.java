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

import java.io.File;
import java.net.URL;
import java.security.cert.X509Certificate;
import java.util.Set;

import me.it_result.ca.BouncyCA;
import me.it_result.ca.BouncyCAClient;
import me.it_result.ca.CA;
import me.it_result.ca.CAClient;

import org.bouncycastle.jce.X509Principal;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.handler.ContextHandlerCollection;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Optional;
import org.testng.annotations.Parameters;
import org.testng.annotations.Test;

import static org.testng.AssertJUnit.*;

/**
 * TODO: split unit/IT tests
 * 
 * @author roman
 *
 */
public class ScepCAClientIntegrationTest {

	private static final String CA_KEYSTORE = "target/scep.ca.keystore";
	private static final String CLIENT_KEYSTORE = "target/scep.client.keystore";
	private static final String KEYSTORE_PASSWORD = "changeme";
	private static final int VALIDITY_DAYS = 365;
	private static final String ISSUER = "CN=SCEP-CA";
	private static final String CA_PROFILE = "default";
	private static final int SCEP_PORT = 8080;
	private static final String SERVLET_PATH = "/pkiclient.exe";
	private static final String SCEP_URL = "http://localhost:" + SCEP_PORT + SERVLET_PATH;
	private static final String SUBJECT_DN = "CN=client";
	private static final String SCEP_PASSWORD = "password";
	
	private Server scepServer;
	private ScepCAClient scepClient;
	
	@BeforeMethod
	@Parameters({"keyAlgorithm", "keyBits", "bouncyCastleProviderSignatureAlgorithm", "jdkSignatureAlgorithm"})
	public void setUp(@Optional("RSA") String keyAlgorithm, @Optional("1024") int keyBits, @Optional("MD5WithRSA") String signatureAlgorithm, @Optional("MD5withRSA") String jdkSignatureAlgorithm) throws Exception {
		destroyCa(jdkSignatureAlgorithm, keyBits, jdkSignatureAlgorithm);
		scepServer = startScepServer(keyAlgorithm, keyBits, signatureAlgorithm);
		CA ca = CARepository.getCA();
		scepClient = initializeScepClient(ca, keyAlgorithm, keyBits, signatureAlgorithm);
	}
	
	private Server startScepServer(String keyAlgorithm, int keyBits, String signatureAlgorithm) throws Exception {
		Server server = new Server(SCEP_PORT);
		ContextHandlerCollection contexts = new ContextHandlerCollection();
        server.setHandler(contexts);

        ServletContextHandler root = new ServletContextHandler(contexts, "/", ServletContextHandler.SESSIONS);
        root.addServlet(new ServletHolder(new ScepServlet()), SERVLET_PATH);
        root.addEventListener(new BouncyCAScepServletContextListener());
        root.setAttribute("keystore", CA_KEYSTORE);
        root.setAttribute("keyAlgorithm", keyAlgorithm);
        root.setAttribute("keyBits", keyBits);
        root.setAttribute("validityDays", VALIDITY_DAYS);
        root.setAttribute("keystorePassword", KEYSTORE_PASSWORD);
        root.setAttribute("issuer", ISSUER);
        root.setAttribute("signatureAlgorithm", signatureAlgorithm);

        server.start();
        return server;
	}

	private void destroyCa(String keyAlgorithm, int keyBits,
			String signatureAlgorithm) throws Exception {
		CA ca = new BouncyCA(CA_KEYSTORE, "RSA", keyBits, VALIDITY_DAYS, KEYSTORE_PASSWORD, "CN=CA", signatureAlgorithm);
		ca.destroy();
	}

	public ScepCAClient initializeScepClient(CA ca, String keyAlgorithm, int keyBits, String signatureAlgorithm) throws Exception {
		CAClient caClient = new BouncyCAClient(CLIENT_KEYSTORE, keyAlgorithm, keyBits, VALIDITY_DAYS, KEYSTORE_PASSWORD, signatureAlgorithm);
		URL scepUrl = new URL(SCEP_URL);
		X509Certificate caCertificate = ca.getCACertificate();
		CertificateFingerprint caFingerprint = CertificateFingerprint.calculate(caCertificate);
		caClient.destroy();
		return new ScepCAClient(caClient, scepUrl, caFingerprint, CA_PROFILE);
	}
	
	@AfterMethod
	public void tearDown() {
		try {
			scepServer.stop();
		} catch (Exception e) {}
		try {
			if (CARepository.getCA() != null)
				CARepository.getCA().destroy();
			scepClient.getCaClient().destroy();
		} catch (Exception e) {}
		new File(CA_KEYSTORE).delete();
		new File(CLIENT_KEYSTORE).delete();
		scepClient = null;
		scepServer = null;
	}
	
	@Test
	public void testEnrollment() throws Exception {
		// When enrollCertificate is invoked 
		scepClient.enrollCertificate(SUBJECT_DN, SCEP_PASSWORD.toCharArray(), 1000, 1000);
		// The certificate should be enrolled by the server
		CA ca = CARepository.getCA();
		Set<X509Certificate> certificates = ca.listCertificates();
		assertEquals(1, certificates.size());
		assertEquals(new X509Principal(SUBJECT_DN), new X509Principal(certificates.iterator().next().getSubjectX500Principal().getName()));
		// And scep client should store the certificate locally
		assertEquals(certificates.iterator().next(), scepClient.getCaClient().getCertificate(SUBJECT_DN));
	}
	
	@Test
	public void testEnollmentInvalidPassword() {
		// When enrollCertificate is invoked with an invalid password
		// The server must return a failure instead of enrolling the certificate
	}
	
}
