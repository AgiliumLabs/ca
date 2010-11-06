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

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.AssertJUnit.assertEquals;
import static org.testng.AssertJUnit.assertNull;
import static org.testng.AssertJUnit.assertTrue;
import static org.testng.AssertJUnit.fail;

import java.io.ByteArrayInputStream;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertStore;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Collections;

import me.it_result.ca.BouncyCA;
import me.it_result.ca.BouncyCAClient;
import me.it_result.ca.CAClient;
import me.it_result.ca.DuplicateSubjectException;

import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.util.encoders.Base64;
import org.jscep.client.Client;
import org.jscep.transaction.EnrolmentTransaction;
import org.jscep.transaction.FailInfo;
import org.jscep.transaction.Transaction.State;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

/**
 * @author roman
 *
 */
public class ScepCAClientTest {

	private static URL SCEP_URL;
	private static final String CA_PROFILE = "default";
	private static final String CLIENT_SUBJECT_DN = "CN=client";
	private static X509Certificate CA_CERTIFICATE;
	private static CertificateFingerprint CA_FINGERPRINT;
	private static X509Certificate SELF_SIGNED_CERTIFICATE;
	private static KeyPair KEYPAIR;
	private static char[] SCEP_PASSWORD;
	private static X509Certificate SIGNED_CERTIFICATE;
	private static PKCS10CertificationRequest CSR;
	private static X509CertSelector CERT_SELECTOR;
	
	static {
		String caCert = "MIIB9TCCAV6gAwIBAgIBATANBgkqhkiG9w0BAQ0FADANMQswCQYDVQQDDAJDQTAgFw0xMDEwMTkxOTU2NThaGA8yMTEwMDkyNTE5NTY1OFowDTELMAkGA1UEAwwCQ0EwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMDrxz72PybqNy/0SZXTR8eT4xwtp81kLk3vAElFSo6WP3FJTFFpPTJr62khMBqRdRDYZU3seYvG1qR1aoc1aE3Wj6/DhoO9A4Sm2r/XQJ9y3cBsInhD8KIeayernlidXoH7UkQJSYEm+K3JbJy1NDt9cO9QyBkJ/zhK3+jxlNV/AgMBAAGjYzBhMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRYrSEFo2br3g2kvhRwePtwC295GTAfBgNVHSMEGDAWgBRYrSEFo2br3g2kvhRwePtwC295GTANBgkqhkiG9w0BAQ0FAAOBgQBcXJ75Ie5bfVLvmRaomgTIga7cpTnNpF5o7tTqvRajaGxn6x+kWuNc9gml6uCqNFNW4TJuoTAarsEbt67tgIf/nzyZmgrK9+F4HwA7lp4ZsW27pLUUILJhJ6AEs270Sh/diju1oRNAXDCg7P7SjoeFXEb0ZDvnPgjJT+/T6WvxVw==";
		String csr = "MIIBTjCBuAIBADARMQ8wDQYDVQQDDAZjbGllbnQwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAJeJcS/K59i1WRVsLeKs+FLPI70AaULwJlxTBneBB5Gg4zNMmoIDKIoIgBQrwEU0swY0L3WC+LlO/JrIKHgMxNqowunRZzQ1sbuT35maw6kLGRFVBeF7V8MvNwbTJ9tnw416VIThTEz/BVGQdzEzIspV/jHSdsPettyhkKOGrasRAgMBAAEwDQYJKoZIhvcNAQENBQADgYEARpz4QvciTWpvOrvnUahMBNZ6B4ctJBGBtkR0XsNvdBsF8OzHgCY8U0RJUKtuGnoMe6PQTeTaeZDVih730fKFLzq07MPKrjjsSJkJhIsrTngs1Vp1OWYMjvXwMpmN7jt7UFH1H+E/BBj222D9/nDpBWU1Kodv//HDDC/nqJY1HZI=";
		String selfSignedCert = "MIIB+jCCAWOgAwIBAgIBATANBgkqhkiG9w0BAQ0FADARMQ8wDQYDVQQDDAZjbGllbnQwIBcNMTAxMDE5MTk1NjU4WhgPMjExMDA5MjUxOTU2NThaMBExDzANBgNVBAMMBmNsaWVudDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAl4lxL8rn2LVZFWwt4qz4Us8jvQBpQvAmXFMGd4EHkaDjM0yaggMoigiAFCvARTSzBjQvdYL4uU78msgoeAzE2qjC6dFnNDWxu5PfmZrDqQsZEVUF4XtXwy83BtMn22fDjXpUhOFMTP8FUZB3MTMiylX+MdJ2w9623KGQo4atqxECAwEAAaNgMF4wDgYDVR0PAQH/BAQDAgWgMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFPjtgggnIW5TfbGO7z0UBZErBa+OMB8GA1UdIwQYMBaAFPjtgggnIW5TfbGO7z0UBZErBa+OMA0GCSqGSIb3DQEBDQUAA4GBAFMuRZzETJ+ULmee+8M7DXwTUdtfUBPYKBsq8mFoS3SbF4fmZlwcKd/T0yQDGM2Qai91Kcfud2Tei81ZJiztqRmGTqZVzi6FZ9QHNWNEPnkCMRXpu64harCKP+Ri4sFCrKvC15TpsxWTtiZPuyLELzp0Syx2+uW9w5yzAE2RPIwH";
		String privateKey = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAJeJcS/K59i1WRVsLeKs+FLPI70AaULwJlxTBneBB5Gg4zNMmoIDKIoIgBQrwEU0swY0L3WC+LlO/JrIKHgMxNqowunRZzQ1sbuT35maw6kLGRFVBeF7V8MvNwbTJ9tnw416VIThTEz/BVGQdzEzIspV/jHSdsPettyhkKOGrasRAgMBAAECgYB+eE7mvElTK8b1ghupmwKE2ivRiY5QN21MkF5NTnqqp8P3BG/PIiOrT/zU2M7W82yWOOeDA5Ph1HIuG+7qgn2nV2bIA/D90ncfYLW+D1QqnDhIniNTUn2wea+UBXl705xEFKgkCxaMGhDel2fF8I5mbuKf7QlkdvWVaI+bFt7QAQJBAMmhgj6DYxPyOLetX26skbRau7uv3UZPeI8pbg8jB7w1PRD5++NsHfmYxiT7kwGZ6JvIUcGOdGHD8b825fNFq7ECQQDAZfdOU5O1ZsMJ7Y/bM8OAXe6/4ljgcXS25K6STkjYCcQk//TZzkCKsu9a1Ai33GwrBbD2xA7vJDW9+DiVka1hAkEAsmGM1LlwYikdPILJtyQ9E45iID4KSTXttto0YHfhVATVrbs7uYvhSPx78CQRfo0nWQr0KYVaOVQc/8oVzg+JQQJBAKAI8MG9MUMVnCw4540MrJStDXecnhLrLIspArB934eb8ARax18YeYUlO4VQk4PkHDFZBY7tHAL9GprOyrpWt2ECQD7Oj8EJDzwNHFaJan3KIto60u/uAVaY61ftLckZXrUK8/0aThamiQwrTHfS1XP6mXax2QeQ7EGJDDkc46dXGRA=";
		String publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCXiXEvyufYtVkVbC3irPhSzyO9AGlC8CZcUwZ3gQeRoOMzTJqCAyiKCIAUK8BFNLMGNC91gvi5TvyayCh4DMTaqMLp0Wc0NbG7k9+ZmsOpCxkRVQXhe1fDLzcG0yfbZ8ONelSE4UxM/wVRkHcxMyLKVf4x0nbD3rbcoZCjhq2rEQIDAQAB";
		String signedCertificate = "MIICCzCCAXSgAwIBAgIBAjANBgkqhkiG9w0BAQ0FADANMQswCQYDVQQDDAJDQTAgFw0xMDEwMTkxOTU2NTlaGA8yMTEwMDkyNTE5NTY1OVowETEPMA0GA1UEAwwGY2xpZW50MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCXiXEvyufYtVkVbC3irPhSzyO9AGlC8CZcUwZ3gQeRoOMzTJqCAyiKCIAUK8BFNLMGNC91gvi5TvyayCh4DMTaqMLp0Wc0NbG7k9+ZmsOpCxkRVQXhe1fDLzcG0yfbZ8ONelSE4UxM/wVRkHcxMyLKVf4x0nbD3rbcoZCjhq2rEQIDAQABo3UwczAOBgNVHQ8BAf8EBAMCBaAwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQU+O2CCCchblN9sY7vPRQFkSsFr44wHwYDVR0jBBgwFoAUWK0hBaNm694NpL4UcHj7cAtveRkwEwYDVR0lBAwwCgYIKwYBBQUHAwIwDQYJKoZIhvcNAQENBQADgYEARQxg8PkPVYlLZKXvelUSAUFDdspvx7Kf5V/AWxWQDkKdJaorfGwVBDFaceWcGYpI1BVzKgoPIjrLWICRraEYsiy1EZgzPjAztuk+lvlJFxLu2cT0beWsjdJqr0caVzPeTPNtmhHfQB6xv1WZ3RZt26bUnDbkLpx+gCiHuwmLJmI=";
		try {
			SCEP_URL = new URL("http://localhost/pkiclient.exe");
			CA_CERTIFICATE = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(Base64.decode(caCert.getBytes("UTF-8"))));
			CA_FINGERPRINT =  CertificateFingerprint.calculate(CA_CERTIFICATE);
			SELF_SIGNED_CERTIFICATE = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(Base64.decode(selfSignedCert.getBytes("UTF-8"))));
			KeySpec pubKeySpec = new X509EncodedKeySpec(Base64.decode(publicKey.getBytes("UTF-8")));
			PublicKey pubKey = KeyFactory.getInstance("RSA").generatePublic(pubKeySpec);
			KeySpec privKeySpec = new PKCS8EncodedKeySpec(Base64.decode(privateKey.getBytes("UTF-8")));
			PrivateKey privKey = KeyFactory.getInstance("RSA").generatePrivate(privKeySpec);
			KEYPAIR = new KeyPair(pubKey, privKey);
			SCEP_PASSWORD = "scepPassword".toCharArray();
			SIGNED_CERTIFICATE = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(Base64.decode(signedCertificate.getBytes("UTF-8"))));
			byte[] csrBytes = Base64.decode(csr.getBytes("UTF-8"));
			CSR = new PKCS10CertificationRequest(csrBytes);
			CERT_SELECTOR = new X509CertSelector();
			CERT_SELECTOR.setSubjectPublicKey(pubKey);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	private ScepCAClient scepCaClient;
	@Mock
	private JScepClientBuilder scepBuilder;
	@Mock
	private Client scepClient; 
	@Mock
	private CAClient caClient;
	@Mock
	private EnrolmentTransaction scepTransaction;
	private CertStore certStore;
	
	@BeforeMethod
	public void setUp() throws Exception {
		MockitoAnnotations.initMocks(this);
		ScepCAClient.BUILDER = scepBuilder;
		scepCaClient = new ScepCAClient(caClient, SCEP_URL, CA_FINGERPRINT, CA_PROFILE);
		certStore = CertStore.getInstance("Collection", new CollectionCertStoreParameters(Collections.singletonList(SIGNED_CERTIFICATE)));
	}
	
	@Test
	public void testEnrollment() throws Exception {
		// When enrollCertificate is invoked
		defineMockRulesForEnrollCertificate();
		// And certificate is enrolled automatically via scep
		when(scepTransaction.send()).thenReturn(State.CERT_ISSUED);
		when(scepTransaction.getCertStore()).thenReturn(certStore);
		X509Certificate enrolledCertificate = scepCaClient.enrollCertificate(CLIENT_SUBJECT_DN, SCEP_PASSWORD, 1000, 1000);
		// Then SCEP client should use a configuration from the ScepCAClient to connect to the server
		verify(scepBuilder).caFingerprint(CA_FINGERPRINT);
		verify(scepBuilder).caIdentifier(CA_PROFILE);
		verify(scepBuilder).identity(SELF_SIGNED_CERTIFICATE, KEYPAIR.getPrivate());
		verify(scepBuilder).url(SCEP_URL);
		// And client should store the CA certificate locally
		verify(caClient).initialize(CA_CERTIFICATE);
		// And client should receive a signed certificate and store it locally
		verify(caClient).storeCertificate(SIGNED_CERTIFICATE);
		assertEquals(SIGNED_CERTIFICATE, enrolledCertificate);
	}
	
	private void defineMockRulesForEnrollCertificate() throws Exception {
		when(caClient.generateCSR(CLIENT_SUBJECT_DN)).thenReturn(CSR.getEncoded());
		when(caClient.getCertificate(CLIENT_SUBJECT_DN)).thenReturn(SELF_SIGNED_CERTIFICATE);
		when(caClient.getKeypair(CLIENT_SUBJECT_DN)).thenReturn(KEYPAIR);
		when(scepBuilder.build()).thenReturn(scepClient);
		when(scepClient.getCaCertificate()).thenReturn(Collections.singletonList(CA_CERTIFICATE));
		when(scepClient.enrol(CSR)).thenReturn(scepTransaction);
	}

	@Test
	public void testEnrollmentOfEnrolledCertificate() throws Exception {
		// When enrollCertificate is invoked for an already enrolled certificate
		when(caClient.generateCSR(CLIENT_SUBJECT_DN)).thenReturn(CSR.getEncoded());
		when(caClient.getCertificate(CLIENT_SUBJECT_DN)).thenReturn(SIGNED_CERTIFICATE);
		// Then DuplicateSubjectException must be thrown
		try {
			scepCaClient.enrollCertificate(CLIENT_SUBJECT_DN, SCEP_PASSWORD, 1000, 1000);
			fail("DuplicateSubjectException expected");
		} catch (DuplicateSubjectException e) {}
	}
	
	@Test
	public void testPendingEnrollment() throws Exception {
		// When certificate is not automatically enrolled
		defineMockRulesForEnrollCertificate();
		when(scepTransaction.send()).thenReturn(State.CERT_REQ_PENDING);
		when(scepTransaction.poll()).thenReturn(State.CERT_ISSUED);
		when(scepTransaction.getCertStore()).thenReturn(certStore);
		long startTime = System.currentTimeMillis();
		X509Certificate enrolledCertificate = scepCaClient.enrollCertificate(CLIENT_SUBJECT_DN, SCEP_PASSWORD, 1000, 10000);
		// Then client should wait for a while and retry fetching the certificate
		long endTime = System.currentTimeMillis();
		assertTrue("" + (endTime - startTime), endTime - startTime >= 1000);
		assertTrue(endTime - startTime < 2000);
		// When certificate becomes available
		// Then the client should fetch the certificate and store it locally
		verify(caClient).storeCertificate(SIGNED_CERTIFICATE);
		assertEquals(SIGNED_CERTIFICATE, enrolledCertificate);
	}
	
	@Test 
	public void testPendingEnrollmentTimeout() throws Exception {
		// When certificate is not automatically enrolled within pendingTimeout
		defineMockRulesForEnrollCertificate();
		when(scepTransaction.send()).thenReturn(State.CERT_REQ_PENDING);
		when(scepTransaction.poll()).thenReturn(State.CERT_REQ_PENDING).thenReturn(State.CERT_REQ_PENDING);
		when(scepTransaction.getCertStore()).thenReturn(certStore);
		long startTime = System.currentTimeMillis();
		X509Certificate enrolledCertificate = scepCaClient.enrollCertificate(CLIENT_SUBJECT_DN, SCEP_PASSWORD, 1000, 2000);
		// Then client stops fetching the certificate
		long endTime = System.currentTimeMillis();
		assertTrue(endTime - startTime >= 2000);
		assertTrue(endTime - startTime < 3000);
		assertNull(enrolledCertificate);
		// When certificate is enrolled 
		// And client retries the request
		when(scepTransaction.send()).thenReturn(State.CERT_ISSUED);
		enrolledCertificate = scepCaClient.enrollCertificate(CLIENT_SUBJECT_DN, SCEP_PASSWORD, 1000, 2000);
		// The client should fetch the certificate and store it locally
		verify(caClient).storeCertificate(SIGNED_CERTIFICATE);
		assertEquals(SIGNED_CERTIFICATE, enrolledCertificate);
	}
	
	@Test 
	public void testEnrollmentFailure() throws Exception {
		// When certificate is being enrolled
		defineMockRulesForEnrollCertificate();
		// And server returns failure
		when(scepTransaction.send()).thenReturn(State.CERT_NON_EXISTANT);
		when(scepTransaction.getFailInfo()).thenReturn(FailInfo.badTime);
		// Then ScepFailureException must be thrown
		try {
			scepCaClient.enrollCertificate(CLIENT_SUBJECT_DN, SCEP_PASSWORD, 1000, 2000);
			fail("ScepFailureException expected");
		} catch (ScepFailureException e) {
			// And exception message should contain the failure reason
			assertTrue(e.getMessage().contains(FailInfo.badTime.toString()));
		}
	}
	
	public static void main(String[] args) {
		try {
			BouncyCA ca = new BouncyCA("target/scep.ca.keystore", "RSA", 1024, 36500, "changeit", "CN=CA", "SHA512withRSA");
			ca.initialize();
			printCertificate("CA certificate", ca.getCACertificate());
			BouncyCAClient caClient = new BouncyCAClient("target/scep.client.keystore", "RSA", 1024, 36500, "chengeit", "SHA512withRSA");
			byte[] csr = caClient.generateCSR(CLIENT_SUBJECT_DN);
			printBytes("CSR", csr);
			X509Certificate selfSignedCertificate = caClient.getCertificate(CLIENT_SUBJECT_DN);
			printCertificate("Self-signed certificate", selfSignedCertificate);
			KeyPair keyPair = caClient.getKeypair(CLIENT_SUBJECT_DN);
			printBytes("Private key", keyPair.getPrivate().getEncoded());
			printBytes("Public key", keyPair.getPublic().getEncoded());
			X509Certificate signedCertificate = ca.signCertificate(csr, false);
			printCertificate("Signed certificate", signedCertificate);
			ca.destroy();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	private static void printBytes(String label, byte[] data) throws UnsupportedEncodingException {
		byte[] dataBase64 = Base64.encode(data);
		System.out.println(label + ":\t" + new String(dataBase64, "UTF-8"));
	}
	
	private static void printCertificate(String label, X509Certificate certificate) throws CertificateEncodingException, UnsupportedEncodingException {
		byte[] cert = certificate.getEncoded();
		printBytes(label, cert);
	}
	
}