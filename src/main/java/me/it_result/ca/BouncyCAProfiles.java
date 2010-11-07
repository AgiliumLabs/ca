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

import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Set;

/**
 * @author roman
 *
 */
public class BouncyCAProfiles {
	
	private Set<BouncyCAProfile> profiles = new HashSet<BouncyCAProfile>();
	private BouncyCAProfile defaultProfile;

	public void addProfile(BouncyCAProfile profile) {
		profiles.add(profile);
	}
	
	public void setDefaultProfile(BouncyCAProfile profile) {
		this.defaultProfile = profile;
	}
	
	public BouncyCAProfile getDefaultProfile() {
		return defaultProfile;
	}
	
	public BouncyCAProfile getProfile(CertificateParameters certificateParameters) {
		for (BouncyCAProfile profile : profiles)
			if (profile.isCompatible(certificateParameters))
				return profile;
		return null;
	}
	
	public BouncyCAProfile getProfile(ASN1Set csrAttributes) {
		for (BouncyCAProfile profile : profiles)
			if (profile.isCompatible(csrAttributes))
				return profile;
		return null;
	}
	
	public static BouncyCAProfiles getDefaultInstance() {
		BouncyCAProfiles profiles = new BouncyCAProfiles();
		StandardBouncyCAProfile userCertificateProfile = new StandardBouncyCAProfile();
		profiles.addProfile(userCertificateProfile);
		profiles.setDefaultProfile(userCertificateProfile);
		return profiles;
	}
	
}
