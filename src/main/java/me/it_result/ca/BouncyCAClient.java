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
package me.it_result.ca;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.PKCS10CertificationRequest;

/**
 * @author roman
 *
 */
public class BouncyCAClient extends BouncyCABase implements CAClient {

	private int selfSignedCertificateValidityDays;
	
	public BouncyCAClient(String keystore, String keyAlgorithm, int keyBits, 
			int selfSignedCertificateValidityDays, String keystorePassword, 
			String signatureAlgorithm) {
		super(keystore, keyAlgorithm, keyBits, keystorePassword, signatureAlgorithm);
		this.selfSignedCertificateValidityDays = selfSignedCertificateValidityDays;
	}
	/* (non-Javadoc)
	 * @see me.it_result.ca.CAClient#destroy()
	 */
	@Override
	public synchronized void destroy() {
		new File(keystore).delete();
	}

	/* (non-Javadoc)
	 * @see me.it_result.ca.CAClient#initialize(java.security.cert.X509Certificate)
	 */
	@Override
	public synchronized void initialize(X509Certificate caCertificate) throws CAException {
		ensureNotInitialized();
		try {
			KeyStore keyStore = loadKeystore();
			keyStore.setCertificateEntry(CA_ALIAS, caCertificate);
			saveKeystore(keyStore);
		} catch (Exception e) {
			throw new CAException(e);
		}
	}

	private void ensureNotInitialized() throws CAException {
		if (isInitialized())
			throw new AlreadyInitializedException("CA already initialized");
	}
	/* (non-Javadoc)
	 * @see me.it_result.ca.CAClient#isInitialized()
	 */
	@Override
	public synchronized boolean isInitialized() {
		InputStream is = null;
		try {
			is = new FileInputStream(keystore);
			KeyStore keyStore = KeyStore.getInstance("JKS");
			keyStore.load(is, keystorePassword.toCharArray());
			return keyStore.containsAlias(CA_ALIAS) && keyStore.isCertificateEntry(CA_ALIAS);
		} catch (Exception e) {
			return false;
		} finally {
			try { is.close(); } catch (Exception e) {}
		}
	}

	/* (non-Javadoc)
	 * @see me.it_result.ca.CA#generateCSR()
	 */
	@Override
	public synchronized byte[] generateCSR(String subjectDN) throws CAException {
		try {
			KeyPair keyPair;
			KeyStore keyStore = loadKeystore();
			String alias = BouncyCAUtils.generateAlias(subjectDN);
			if (!keyStore.containsAlias(alias)) 
				keyPair = generateKeyPair();
			else {
				keyPair = getKeypair(subjectDN);
				X509Certificate existingCertificate = (X509Certificate) keyStore.getCertificate(alias);
				if (!existingCertificate.getIssuerDN().equals(existingCertificate.getSubjectDN())) 
					throw new DuplicateSubjectException("Certificate for " + subjectDN + " is signed already");
			}
			X509Certificate cert = assembleCertificate(keyPair.getPublic(), keyPair.getPublic(), subjectDN, subjectDN, new BigInteger("1"), false, selfSignedCertificateValidityDays).generate(keyPair.getPrivate());
			PKCS10CertificationRequest csr = new PKCS10CertificationRequest(signatureAlgorithm, new X509Name(subjectDN), keyPair.getPublic(), null, keyPair.getPrivate());
			byte[] csrBytes = csr.getEncoded();
			keyStore.setKeyEntry(alias, keyPair.getPrivate(), keystorePassword.toCharArray(), new X509Certificate[] {cert});
			saveKeystore(keyStore);
			return csrBytes;
		} catch (DuplicateSubjectException e) {
			throw new DuplicateSubjectException(e);
		} catch (Exception e) {
			throw new CAException(e);
		} finally {
			certGen.reset();
		}
	}

	@Override
	public synchronized KeyPair getKeypair(String subjectDN) throws CAException {
		try {
			KeyStore keystore = loadKeystore();
			String alias = BouncyCAUtils.generateAlias(subjectDN);
			if (keystore.containsAlias(alias)) {
				PrivateKey privateKey = (PrivateKey) keystore.getKey(alias, keystorePassword.toCharArray());
				X509Certificate selfSignedCertificate = (X509Certificate) keystore.getCertificate(alias);
				KeyPair keyPair = new KeyPair(selfSignedCertificate.getPublicKey(), privateKey);
				return keyPair;
			}
		} catch (Exception e) {
			throw new CAException(e);
		}
		return null;
	}
	
	@Override
	public synchronized X509Certificate getCertificate(String subjectDN) throws CAException {
		try {
			KeyStore keystore = loadKeystore();
			String alias = BouncyCAUtils.generateAlias(subjectDN);
			if (keystore.containsAlias(alias)) {
				X509Certificate certificate = (X509Certificate) keystore.getCertificate(alias);
				return certificate;
			}
		} catch (Exception e) {
			throw new CAException(e);
		}
		return null;
	}
	
	/* (non-Javadoc)
	 * @see me.it_result.ca.CA#storeCertificate()
	 */
	@Override
	public synchronized void storeCertificate(X509Certificate certificate) throws CAException {
		ensureInitialized();
		try {
			KeyStore keyStore = loadKeystore();
			String alias = BouncyCAUtils.generateAlias(certificate.getSubjectX500Principal());
			X509Certificate existingCertificate = (X509Certificate) keyStore.getCertificate(alias);
			if (!existingCertificate.getPublicKey().equals(certificate.getPublicKey()))
				throw new InvalidCertificateKeyException("Signed certificate public key does not match expected");
			X509Certificate caCertificate = (X509Certificate) keyStore.getCertificate(CA_ALIAS);
			try {
				certificate.verify(caCertificate.getPublicKey());
			} catch (Exception e) {
				throw new InvalidCAException("The certificate was signed by a different CA", e);
			}
			PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, keystorePassword.toCharArray());
			keyStore.setKeyEntry(alias, privateKey, keystorePassword.toCharArray(), new Certificate[] {certificate});
			saveKeystore(keyStore);
		} catch (InvalidCertificateKeyException e) {
			throw new InvalidCertificateKeyException(e);
		} catch (InvalidCAException e) {
			throw new InvalidCAException(e);
		}
		catch (Exception e) {
			throw new CAException(e);
		}
	}

	private void ensureInitialized() throws CAException {
		if (!isInitialized())
			throw new CANotInitializedException("CA is not initialized yet.");
	}
	
	@Override
	public synchronized X509Certificate getCaCertificate() throws CAException,
			CAException {
		ensureInitialized();
		try {
			KeyStore keyStore = loadKeystore();
			return (X509Certificate) keyStore.getCertificate(CA_ALIAS);
		} catch (Exception e) {
			throw new CAException(e);
		}
	}

}
