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

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;

import me.it_result.ca.AlreadyInitializedException;
import me.it_result.ca.CA;
import me.it_result.ca.CAException;
import me.it_result.ca.NotInitializedException;
import me.it_result.ca.db.Database;

import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.PKCS10CertificationRequest;

/**
 * @author roman
 *
 */
public class BouncyCA extends BouncyCABase implements CA {

	static final String SERIAL_NUMBER_PROPERTY = BouncyCA.class.getName() + ".serialNumber";
	
	private String issuer;
	private int validityDays;

	public BouncyCA(Database database, String keyAlgorithm, int keyBits,
			int validityDays, String keystorePassword, String issuer, 
			String signatureAlgorithm, ProfileRegistry profiles) {
		super(database, keyAlgorithm, keyBits, keystorePassword,
				signatureAlgorithm, profiles);
		this.validityDays = validityDays;
		this.issuer = issuer;
	}

	/* (non-Javadoc)
	 * @see me.it_result.ca.CA#initializeCA()
	 */
	@Override
	public synchronized void initialize() throws CAException {
		ensureNotInitialized();
		try {
			KeyPair keyPair = generateKeyPair();
			BigInteger serialNumber = nextSerialNumber();
			X509Certificate cert = assembleCertificate(keyPair.getPublic(), keyPair.getPublic(), issuer, issuer, serialNumber, true, validityDays).
				generate(keyPair.getPrivate());
			KeyStore keyStore = loadKeystore();
			keyStore.setKeyEntry(CA_ALIAS, keyPair.getPrivate(), keystorePassword.toCharArray(), new X509Certificate[] {cert});
			saveKeystore(keyStore);
			incrementSerialNumber(serialNumber);
			// TODO: generateCRL();
		} catch (Exception e) {
			throw new CAException(e);
		}
		finally {
			certGen.reset();
		}
	}
	
	private void ensureNotInitialized() throws AlreadyInitializedException {
		if (isInitialized())
			throw new AlreadyInitializedException("CA already initialized");
	}

	/* (non-Javadoc)
	 * @see me.it_result.ca.CA#isInitialized()
	 */
	@Override
	public synchronized boolean isInitialized() {
		try {
			KeyStore keyStore = loadKeystore();
			return keyStore.containsAlias(CA_ALIAS) && keyStore.isKeyEntry(CA_ALIAS);
		} catch (Exception e) {
			return false;
		}
	}

	/* (non-Javadoc)
	 * @see me.it_result.ca.CA#listCertificates()
	 */
	@Override
	public synchronized Set<X509Certificate> listCertificates() throws CAException {
		ensureInitialized();
		try {
			Set<X509Certificate> certificates = new HashSet<X509Certificate>();
			KeyStore keyStore = loadKeystore();
			Enumeration<String> aliases = keyStore.aliases();
			while (aliases.hasMoreElements()) {
				String alias = aliases.nextElement();
				if (keyStore.isCertificateEntry(alias)) {
					Certificate certificate = keyStore.getCertificate(alias);
					if (certificate instanceof X509Certificate)
						certificates.add((X509Certificate)certificate);
				}
			}
			return certificates;
		} catch (Exception e) {
			throw new CAException(e);
		}
	}

	/* (non-Javadoc)
	 * @see me.it_result.ca.CA#signCertificate()
	 */
	@Override
	public synchronized X509Certificate signCertificate(byte[] csrBytes) throws CAException {
		ensureInitialized();
		try {
			PKCS10CertificationRequest csr = new PKCS10CertificationRequest(csrBytes);
			if (!csr.verify())
				throw new CAException("CSR verification failed!");
			X509Name sn = csr.getCertificationRequestInfo().getSubject();
			PublicKey publicKey = csr.getPublicKey();
			KeyStore keyStore = loadKeystore();
			PrivateKey caPrivateKey = (PrivateKey) keyStore.getKey(CA_ALIAS, keystorePassword.toCharArray());
			PublicKey caPublicKey = keyStore.getCertificate(CA_ALIAS).getPublicKey();
			BigInteger serialNumber = nextSerialNumber();
			assembleCertificate(publicKey, caPublicKey, sn.toString(), issuer, serialNumber, false, validityDays);
			ASN1Set csrAttributes = csr.getCertificationRequestInfo().getAttributes();
			Profile profile = selectProfile(csrAttributes);
			profile.generateCertificateExtensions(csrAttributes, certGen);
			X509Certificate cert = certGen.generate(caPrivateKey);
			String alias = Utils.generateAlias(sn);
			keyStore.setCertificateEntry(alias, cert);
			saveKeystore(keyStore);
			incrementSerialNumber(serialNumber);
			return cert;
		} catch (Exception e) {
			throw new CAException(e);
		} finally {
			certGen.reset();
		}
	}

	private Profile selectProfile(ASN1Set attributes) throws CAException {
		Profile profile = profiles.getProfile(attributes);
		if (profile == null)
			profile = profiles.getDefaultProfile();
		if (profile == null)
			throw new CAException("Profile capable processing this CSR is not registered and there is no default profile set");
		return profile;
	}

	private void ensureInitialized() throws CAException {
		if (!isInitialized())
			throw new CAException("CA is not initialized yet.");
	}

	@Override
	public synchronized X509Certificate getCACertificate() throws CAException {
		ensureInitialized();
		try {
			KeyStore keyStore = loadKeystore();
			X509Certificate caCertificate = (X509Certificate) keyStore.getCertificate(CA_ALIAS);
			return caCertificate;
		} catch (Exception e) {
			throw new CAException(e);
		}
	}
	
	private synchronized BigInteger nextSerialNumber() throws Exception {
		String serialNumberStr = database.readString(CA_ALIAS, SERIAL_NUMBER_PROPERTY);
		BigInteger nextSerialNumber = serialNumberStr == null ? BigInteger.ONE : new BigInteger(serialNumberStr);
		return nextSerialNumber;
	}

	private void incrementSerialNumber(BigInteger serialNumber) throws Exception {
		BigInteger nextSerialNumber = serialNumber.add(BigInteger.ONE);
		database.writeString(CA_ALIAS, SERIAL_NUMBER_PROPERTY, nextSerialNumber.toString());
	}

	@Override
	public KeyPair getCAKeypair() throws NotInitializedException, CAException {
		ensureInitialized();
		try {
			KeyStore keyStore = loadKeystore();
			PrivateKey caPrivateKey = (PrivateKey) keyStore.getKey(CA_ALIAS, keystorePassword.toCharArray());
			X509Certificate caCertificate = (X509Certificate) keyStore.getCertificate(CA_ALIAS);
			KeyPair keyPair = new KeyPair(caCertificate.getPublicKey(), caPrivateKey);
			return keyPair;
		} catch (Exception e) {
			throw new CAException(e);
		}
	}

}