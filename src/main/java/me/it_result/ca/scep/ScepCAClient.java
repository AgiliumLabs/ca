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
import java.net.URL;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.Certificate;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import me.it_result.ca.CAClient;
import me.it_result.ca.CAException;
import me.it_result.ca.CANotInitializedException;
import me.it_result.ca.CertificateParameters;
import me.it_result.ca.DuplicateSubjectException;
import me.it_result.ca.InvalidCAException;
import me.it_result.ca.InvalidCertificateKeyException;

import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.jscep.client.Client;
import org.jscep.transaction.EnrolmentTransaction;
import org.jscep.transaction.FailInfo;
import org.jscep.transaction.Transaction.State;

/**
 * Makes it possible to enroll certificate via SCEP
 * 
 * @author roman
 */
public class ScepCAClient {

	protected static JScepClientBuilder BUILDER;
	
	private CAClient caClient;
	private URL scepUrl;
	private CertificateFingerprint caCertificateFingerprint;
	private String caProfile;
	private int pollIntervalInSeconds = 10;
	private int pollTimeoutInSeconds = 0;
	
	/**
	 * Instantiates a SCEP cleint
	 * 
	 * @param caClient CAClient instance used for generating CSR and storing certificates
	 * @param scepUrl SCEP server URL
	 * @param caCertificateFingerprint CA certificate fingerprint
	 * @param caProfile SCEP CA profile (identifier)
	 */
	public ScepCAClient(CAClient caClient, URL scepUrl,
			CertificateFingerprint caCertificateFingerprint, String caProfile) {
		super();
		this.caClient = caClient;
		this.scepUrl = scepUrl;
		this.caCertificateFingerprint = caCertificateFingerprint;
		this.caProfile = caProfile;
	}

	/**
	 * Instantiates a SCEP cleint
	 * 
	 * @param caClient CAClient instance used for generating CSR and storing certificates
	 * @param scepUrl SCEP server URL
	 * @param caCertificateFingerprint CA certificate fingerprint
	 * @param caProfile SCEP CA profile (identifier)
	 * @param pollIntervalInSeconds An interval between certificate retrieval 
	 * requests measured in seconds. 
	 * @param pollTimeoutInSeconds Defines a maximum time to wait for 
	 * certificate enrollment.
	 */
	public ScepCAClient(CAClient caClient, URL scepUrl,
			CertificateFingerprint caCertificateFingerprint, String caProfile, 
			int pollIntervalInSeconds, int pollTimeoutInSeconds) {
		super();
		this.caClient = caClient;
		this.scepUrl = scepUrl;
		this.caCertificateFingerprint = caCertificateFingerprint;
		this.caProfile = caProfile;
		this.pollIntervalInSeconds = pollIntervalInSeconds;
		this.pollTimeoutInSeconds = pollTimeoutInSeconds;
	}

	/**
	 * Enrolls a certificate via SCEP
	 * 
	 * @param certificateParameters certificate subject DN 
	 * 
	 * @return certificate enrolled
	 *  
	 * @throws DuplicateSubjectException In case certificate was enrolled 
	 * already
	 * @throws ScepFailureException In case enrollment resulted in SCEP failure
	 * status returned
	 * @throws CAException
	 */
	public X509Certificate enrollCertificate(CertificateParameters certificateParameters) throws CAException {
		try {
			String subject = certificateParameters.getSubjectDN();
			ensureCertificateNotSignedYet(subject);
			byte[] csr = caClient.generateCSR(certificateParameters);
			X509Certificate identity = caClient.getCertificate(subject);
			KeyPair keyPair = caClient.getKeypair(subject);
			Client scep = initializeScepClient(identity, keyPair);
			// TODO: take into account scepPassword value
			EnrolmentTransaction transaction = scep.enrol(new PKCS10CertificationRequest(csr));
			State state = executeScepTransaction(transaction);
			if (state == State.CERT_ISSUED) {
				X509Certificate certificate = extractCertificate(transaction.getCertStore(), keyPair.getPublic());
				return certificate;
			} else if (state == State.CERT_NON_EXISTANT) {
				FailInfo fail = transaction.getFailInfo();
				throw new ScepFailureException(fail.toString());
			} else if (state == State.CERT_REQ_PENDING) {
				return null;
			} else {
				throw new CAException("Unexpected transaction state: " + state);
			}
		} catch (DuplicateSubjectException e) {
			throw new DuplicateSubjectException(e);
		} catch (ScepFailureException e) {
			throw new ScepFailureException(e);
		} catch (Exception e) {
			throw new CAException(e);
		}
	}

	private State executeScepTransaction(EnrolmentTransaction transaction) throws IOException, InterruptedException, ExecutionException {
		State state = transaction.send();
		long startTime = System.currentTimeMillis();
		while (state == State.CERT_REQ_PENDING && (startTime + pollTimeoutInSeconds*1000L) > System.currentTimeMillis()) {
			Callable<State> task = new PollTask(transaction);
			state = Executors.newScheduledThreadPool(1).schedule(task, Math.max(Math.min(pollIntervalInSeconds*1000L, startTime + pollTimeoutInSeconds*1000L - System.currentTimeMillis()), 10), TimeUnit.MILLISECONDS).get();
		}
		return state;
	}

	private X509Certificate extractCertificate(CertStore certStore, PublicKey certificateKey) throws CertStoreException, CANotInitializedException, InvalidCertificateKeyException, InvalidCAException, CAException {
		X509CertSelector certSelector = new X509CertSelector();
		certSelector.setSubjectPublicKey(certificateKey);
		Collection<? extends Certificate> certificates = certStore.getCertificates(certSelector);
		for (Certificate cert : certificates) {
			if (cert instanceof X509Certificate) {
				X509Certificate certificate = (X509Certificate) cert;
				caClient.storeCertificate(certificate);
				return certificate;
			}
		}
		return null;
	}

	private void ensureCertificateNotSignedYet(String subject) throws CAException {
		X509Certificate certificate = caClient.getCertificate(subject);
		if (certificate != null && !certificate.getSubjectX500Principal().equals(certificate.getIssuerX500Principal()))
			throw new DuplicateSubjectException("Certificate for " + subject + " is signed already");
	}

	private static class PollTask implements Callable<State> {

		private EnrolmentTransaction transaction;
		
		public PollTask(EnrolmentTransaction transaction) {
			super();
			this.transaction = transaction;
		}

		@Override
		public State call() throws Exception {
			return transaction.poll();
		}
		
	}

	private Client initializeScepClient(X509Certificate identityCertificate, KeyPair keypair) throws IOException, CAException {
		JScepClientBuilder builder = BUILDER != null ? BUILDER : new JScepClientBuilder();
		builder.caFingerprint(caCertificateFingerprint);
		builder.caIdentifier(caProfile);
		builder.identity(identityCertificate, keypair.getPrivate());
		builder.url(scepUrl);
		Client scep = builder.build();
		if (!caClient.isInitialized()) {
			List<X509Certificate> caChain = scep.getCaCertificate();
			X509Certificate caCertificate;
			if (caChain.size() >= 2)
				caCertificate = caChain.get(1);
			else
				caCertificate = caChain.get(0);
			caClient.initialize(caCertificate);
		}
		return scep;
	}

	/**
	 * @return the scepUrl
	 */
	public URL getScepUrl() {
		return scepUrl;
	}

	/**
	 * @param scepUrl the scepUrl to set
	 */
	public void setScepUrl(URL scepUrl) {
		this.scepUrl = scepUrl;
	}

	/**
	 * @return the caCertificateFingerprint
	 */
	public CertificateFingerprint getCaCertificateFingerprint() {
		return caCertificateFingerprint;
	}

	/**
	 * @param caCertificateFingerprint the caCertificateFingerprint to set
	 */
	public void setCaCertificateFingerprint(
			CertificateFingerprint caCertificateFingerprint) {
		this.caCertificateFingerprint = caCertificateFingerprint;
	}

	/**
	 * @return the caProfile
	 */
	public String getCaProfile() {
		return caProfile;
	}

	/**
	 * @param caProfile the caProfile to set
	 */
	public void setCaProfile(String caProfile) {
		this.caProfile = caProfile;
	}

	/**
	 * @return the caClient
	 */
	public CAClient getCaClient() {
		return caClient;
	}

	/**
	 * @return the pollIntervalInSeconds
	 */
	public int getPollIntervalInSeconds() {
		return pollIntervalInSeconds;
	}

	/**
	 * @param pollIntervalInSeconds the pollIntervalInSeconds to set
	 */
	public void setPollIntervalInSeconds(int pollIntervalInSeconds) {
		this.pollIntervalInSeconds = pollIntervalInSeconds;
	}

	/**
	 * @return the pollTimeoutInSeconds
	 */
	public int getPollTimeoutInSeconds() {
		return pollTimeoutInSeconds;
	}

	/**
	 * @param pollTimeoutInSeconds the pollTimeoutInSeconds to set
	 */
	public void setPollTimeoutInSeconds(int pollTimeoutInSeconds) {
		this.pollTimeoutInSeconds = pollTimeoutInSeconds;
	}
	
}
