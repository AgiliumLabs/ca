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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.util.Calendar;
import java.util.Date;

import me.it_result.ca.CAException;
import me.it_result.ca.db.Database;

import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;
import org.bouncycastle.x509.extension.SubjectKeyIdentifierStructure;

/**
 * @author roman
 *
 */
public abstract class BouncyCABase {

	static final String CA_ALIAS = "CA";
	static final String KEYSTORE_PROPERTY = BouncyCABase.class.getName() + ".keystore";
	
	protected Database database;
	protected String keyAlgorithm;
	protected int keyBits;
	protected String keystorePassword;
	protected String signatureAlgorithm;
	protected ProfileRegistry profiles;

	protected X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
	
	static {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	}
	
	public BouncyCABase(Database database, String keyAlgorithm, int keyBits,
			String keystorePassword, String signatureAlgorithm, 
			ProfileRegistry profiles) {
		super();
		this.database = database;
		this.keyAlgorithm = keyAlgorithm;
		this.keyBits = keyBits;
		this.keystorePassword = keystorePassword;
		this.signatureAlgorithm = signatureAlgorithm;
		this.profiles = profiles;
	}

	protected void saveKeystore(KeyStore keyStore) throws Exception {
		ByteArrayOutputStream os = new ByteArrayOutputStream();
		keyStore.store(os, keystorePassword.toCharArray());
		byte[] data = os.toByteArray();
		database.writeBytes(CA_ALIAS, KEYSTORE_PROPERTY, data);
	}

	protected KeyPair generateKeyPair() throws NoSuchAlgorithmException {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance(keyAlgorithm);
		keyGen.initialize(keyBits);
		return keyGen.generateKeyPair();
	}

	protected X509V3CertificateGenerator assembleCertificate(PublicKey publicKey, PublicKey caPublicKey, String subjectDN, String issuerDN, BigInteger serialNumber, boolean ca, int validityDays) throws CertificateParsingException, InvalidKeyException, CertificateEncodingException, IllegalStateException, NoSuchAlgorithmException, SignatureException, FileNotFoundException {
		certGen.setIssuerDN(new X509Principal(issuerDN));
		certGen.setNotBefore(new Date());
		Calendar cal = Calendar.getInstance();
		cal.setTimeInMillis(System.currentTimeMillis());
		cal.add(Calendar.DAY_OF_MONTH, validityDays);
		certGen.setNotAfter(cal.getTime());
		certGen.setPublicKey(publicKey);
		certGen.setSerialNumber(serialNumber);
		certGen.setSignatureAlgorithm(signatureAlgorithm);
		certGen.setSubjectDN(new X509Principal(subjectDN));
		X509KeyUsage keyUsage;
		if (ca)
			keyUsage = new X509KeyUsage(X509KeyUsage.cRLSign | X509KeyUsage.keyCertSign);
		else
			keyUsage = new X509KeyUsage(X509KeyUsage.keyEncipherment | X509KeyUsage.digitalSignature);
		certGen.addExtension(X509Extensions.KeyUsage, true, keyUsage.getDEREncoded());
		BasicConstraints basicConstraints = new BasicConstraints(ca);
		certGen.addExtension(X509Extensions.BasicConstraints, true, basicConstraints.getDEREncoded());
		SubjectKeyIdentifierStructure subjectKeyId = new SubjectKeyIdentifierStructure(publicKey);
		certGen.addExtension(X509Extensions.SubjectKeyIdentifier, false, subjectKeyId.getDEREncoded());
		AuthorityKeyIdentifierStructure authorityKeyId = new AuthorityKeyIdentifierStructure(caPublicKey);
		certGen.addExtension(X509Extensions.AuthorityKeyIdentifier, false, authorityKeyId.getDEREncoded());
		return certGen;
	}
	
	protected KeyStore loadKeystore() throws NoSuchAlgorithmException, CertificateException, IOException, KeyStoreException {
		KeyStore keyStore = KeyStore.getInstance("JKS");
		InputStream is = null;
		try {
			byte[] data = database.readBytes(CA_ALIAS, KEYSTORE_PROPERTY);
			if (data != null)
				is = new ByteArrayInputStream(data);
			keyStore.load(is, keystorePassword.toCharArray());
		} catch (Exception e) {
			keyStore.load(null, keystorePassword.toCharArray());			
		} finally {
			try { is.close(); } catch (Exception e) {}
		}
		return keyStore;
	}
	
	public synchronized void destroy() throws CAException {
		try {
			database.destroy();
		} catch (Exception e) {
			throw new CAException(e);
		}
	}

}