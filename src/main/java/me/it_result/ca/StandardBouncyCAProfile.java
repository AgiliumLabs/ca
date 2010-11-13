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
import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.x509.X509V3CertificateGenerator;

/**
 * @author roman
 *
 */
public class StandardBouncyCAProfile implements BouncyCAProfile {

	private static final String SERVER_PROFILE = "ServerCertificate";
	private static final String CLIENT_PROFILE = "ClientCertificate";
	
	/**
	 * TODO: Choose an appropriate attribute OID for profile ID
	 */
	private static final DERObjectIdentifier PROFILE_ID_ATTR = PKCSObjectIdentifiers.pkcs_9_at_contentType;

	@Override
	public void generateCertificateExtensions(
			ASN1Set csrAttributes, X509V3CertificateGenerator certificateGenerator) {
		// EKU
		ExtendedKeyUsage extendedKeyUsage;
		if (isServerProfile(csrAttributes))
			extendedKeyUsage = new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth);
		else
			extendedKeyUsage = new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth);
		certificateGenerator.addExtension(X509Extensions.ExtendedKeyUsage, false, extendedKeyUsage);
	}

	@Override
	public PKCS10CertificationRequest generateCsr(KeyPair keyPair, CertificateParameters certificateParameters, String signatureAlgorithm) throws Exception {
		if (!isCompatible(certificateParameters))
			throw new CAException("Certificate parameters are not compatible with profile");
		CertificateParametersBase params = (CertificateParametersBase) certificateParameters;
		ASN1EncodableVector attributeVector = new ASN1EncodableVector();
		// challengePassword
		if (params.getChallengePassword() != null) {
			ASN1EncodableVector passwordVector = new ASN1EncodableVector();
			passwordVector.add(new DERPrintableString(params.getChallengePassword()));
			Attribute passwordAttribute = new Attribute(PKCSObjectIdentifiers.pkcs_9_at_challengePassword, new DERSet(passwordVector));
			attributeVector.add(passwordAttribute);
		}
		String profileId = certificateParameters instanceof ServerCertificateParameters ? SERVER_PROFILE : CLIENT_PROFILE;
		Attribute profileIdAttribute = new Attribute(PROFILE_ID_ATTR, new DERSet(new ASN1Encodable[] {new DERPrintableString(profileId)}));
		attributeVector.add(profileIdAttribute);
		DERSet attributes = new DERSet(attributeVector); 
		PKCS10CertificationRequest csr = new PKCS10CertificationRequest(signatureAlgorithm, new X509Name(certificateParameters.getSubjectDN()), keyPair.getPublic(), attributes, keyPair.getPrivate());
		return csr;
	}

	@Override
	public boolean isCompatible(ASN1Set csrAttributes) {
		String profileId = extractProfileId(csrAttributes);
		return profileId != null && (profileId.equals(SERVER_PROFILE) || profileId.equals(CLIENT_PROFILE));
	}

	private String extractProfileId(ASN1Set csrAttributes) {
		String profileId = null;
		try {
			Enumeration<?> attrEnum = csrAttributes.getObjects();
			while (attrEnum.hasMoreElements()) {
				DERSequence attr = (DERSequence) attrEnum.nextElement();
				if (attr.getObjectAt(0).equals(PROFILE_ID_ATTR)) {
					ASN1Set profileIdSet = (ASN1Set) attr.getObjectAt(1);
					DERPrintableString profileIdValue = (DERPrintableString) profileIdSet.getObjectAt(0);
					profileId = ((DERPrintableString) profileIdValue).getString();
					break;
				}
			}
		} catch (Exception e) {}
		if (profileId == null)
			profileId = CLIENT_PROFILE;
		return profileId;
	}

	private boolean isServerProfile(ASN1Set csrAttributes) {
		String profileId = extractProfileId(csrAttributes);
		return profileId.equals(SERVER_PROFILE);
	}

	@Override
	public boolean isCompatible(CertificateParameters certificateParameters) {
		return certificateParameters instanceof UserCertificateParameters || certificateParameters instanceof ServerCertificateParameters;
	}

}
