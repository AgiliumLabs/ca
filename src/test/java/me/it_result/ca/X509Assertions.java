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

import static org.testng.AssertJUnit.assertEquals;
import static org.testng.AssertJUnit.assertNotNull;
import static org.testng.AssertJUnit.assertTrue;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.X509Principal;

/**
 * @author roman
 *
 */
public class X509Assertions {

	private X509Certificate cert;
	
	private Set<String> criticalExtensions = new HashSet<String>();
	private Set<String> nonCriticalExtensions = new HashSet<String>();

	/**
	 * @param cert
	 * @throws CertificateException 
	 */
	public X509Assertions(X509Certificate cert) throws CertificateException {
		super();
		this.cert = toJdkCertificate(cert);
	}
	
	public static X509Certificate toJdkCertificate(X509Certificate cert) throws CertificateException {
		byte[] bytes = cert.getEncoded();
		return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(bytes));
	}

	public X509Assertions version(int version) {
		assertEquals(version, cert.getVersion());
		return this;
	}
	
	public X509Assertions issuedBy(X509Certificate caCertificate) throws Exception {
		cert.verify(caCertificate.getPublicKey());
		assertEquals(caCertificate.getSubjectX500Principal(), cert.getIssuerX500Principal());
		// TODO: SKI/AKI comparison (if present on the certificates)
		return this;
	}

	public X509Assertions type(String type) {
		assertEquals(type, cert.getType());
		return this;
	}

	public X509Assertions subjectName(String subjectName) {
		assertEquals(new X509Principal(subjectName), new X509Principal(cert.getSubjectX500Principal().getName()));
		return this;
	}

	public X509Assertions serialNumber(BigInteger serialNumber) {
		assertEquals(serialNumber, cert.getSerialNumber());
		return this;
	}

	public X509Assertions validDuring(int validityDays, Date minBeforeDate,
			Date maxBeforeDate) {
		Calendar cal = Calendar.getInstance();
		cal.setTime(minBeforeDate);
		cal.set(Calendar.MILLISECOND, 0);
		minBeforeDate = cal.getTime();
		cal.add(Calendar.DAY_OF_MONTH, validityDays);
		Date minAfterDate = cal.getTime(); 
		cal.setTime(maxBeforeDate);
		cal.add(Calendar.DAY_OF_MONTH, validityDays);
		Date maxAfterDate = cal.getTime(); 
		assertTrue(cert.getNotAfter() + "<" + minAfterDate, cert.getNotAfter().compareTo(minAfterDate) >= 0);
		assertTrue(cert.getNotAfter().compareTo(maxAfterDate) <= 0);
		assertTrue(cert.getNotBefore().compareTo(minBeforeDate) >= 0);
		assertTrue(cert.getNotBefore().compareTo(maxBeforeDate) <= 0);
		return this;
	}

	public X509Assertions caCertificate(boolean ca) throws Exception {
		extensionValue(X509Extensions.BasicConstraints, new BasicConstraints(ca));
		criticalExtension(X509Extensions.BasicConstraints);
		return this;
	}

	public X509Assertions extensionValue(DERObjectIdentifier id, ASN1Encodable value) throws Exception {
		ASN1InputStream asn1Parser = new ASN1InputStream(cert.getExtensionValue(id.getId()));
		DEROctetString actualExtension = (DEROctetString) asn1Parser.readObject();
		assertTrue(Arrays.equals(value.getDERObject().getDEREncoded(), actualExtension.getOctets()));
		return this;
	}
	
	public X509Assertions criticalExtension(DERObjectIdentifier extensionId) {
		criticalExtensions.add(extensionId.getId());
		return this;
	}

	public X509Assertions containsSKI() {
		assertNotNull(cert.getExtensionValue(X509Extensions.SubjectKeyIdentifier.getId()));
		nonCriticalExtension(X509Extensions.SubjectKeyIdentifier);
		return this;
	}

	public X509Assertions nonCriticalExtension(DERObjectIdentifier extensionId) {
		nonCriticalExtensions.add(extensionId.getId());
		return this;
	}

	public X509Assertions containsAKI() {
		assertNotNull(cert.getExtensionValue(X509Extensions.AuthorityKeyIdentifier.getId()));
		nonCriticalExtension(X509Extensions.AuthorityKeyIdentifier);
		return this;
	}

	public X509Assertions eku(KeyPurposeId[] keyPurposeIds) throws Exception {
		if (keyPurposeIds != null) {
			List<String> expectedEkus = new ArrayList<String>();
			for (int i = 0; i < keyPurposeIds.length; i++)
				expectedEkus.add(keyPurposeIds[i].getId());
			assertEquals(expectedEkus, cert.getExtendedKeyUsage());
			nonCriticalExtension(X509Extensions.ExtendedKeyUsage);
		}
		return this;
	}

	public X509Assertions keyUsage(int expectedKeyUsage) {
		int actualKeyUsage = 0;
		for (int i = 0; i < 8; i++) {
			int bit = cert.getKeyUsage()[i] ? 1 : 0;
			actualKeyUsage = (actualKeyUsage << 1) | bit;
		}
		assertEquals(expectedKeyUsage, actualKeyUsage);
		criticalExtension(X509Extensions.KeyUsage);
		return this;
	}

	public X509Assertions noMoreExtensions() {
		assertEquals("Critical extensions do not match expected", criticalExtensions, cert.getCriticalExtensionOIDs());
		assertEquals("Non-critical extensions do not match expected", nonCriticalExtensions, cert.getNonCriticalExtensionOIDs());
		return this;
	}

	public X509Assertions signatureAlgrithm(String jdkSignatureAlgorithm) {
		assertEquals(jdkSignatureAlgorithm, cert.getSigAlgName());
		return this;
	}
	
}
