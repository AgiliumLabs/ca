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

import java.security.KeyPair;
import java.util.Collection;
import java.util.Collections;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509ExtensionsGenerator;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.PKCS10CertificationRequest;

/**
 * @author roman
 *
 */
public class UserBouncyCAProfile implements BouncyCAProfile<UserCertificateParameters> {

	@Override
	public Collection<X509Extension> generateCertificateExtensions(
			ASN1Set csrAttributes) {
		// TODO: implement
		return Collections.emptyList();
	}

	@Override
	public PKCS10CertificationRequest generateCsr(KeyPair keyPair, UserCertificateParameters certificateParameters, String signatureAlgorithm) throws Exception {
		X509ExtensionsGenerator extGenerator = new X509ExtensionsGenerator();
		// EKU
		ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage(KeyPurposeId.anyExtendedKeyUsage);
		extGenerator.addExtension(X509Extensions.ExtendedKeyUsage, false, extendedKeyUsage);
		X509Extensions extensions = extGenerator.generate();
		Attribute extensionsAttribute = new Attribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, new DERSet(extensions));
		// TODO: implement challengePassword attribute
		DERSet attributes = new DERSet(new ASN1Encodable[] {extensionsAttribute/*, passwordAttribute*/}); 
		PKCS10CertificationRequest csr = new PKCS10CertificationRequest(signatureAlgorithm, new X509Name(certificateParameters.getSubjectDN()), keyPair.getPublic(), attributes, keyPair.getPrivate());
		return csr;
	}

}
