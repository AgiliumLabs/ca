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

import java.util.HashSet;
import java.util.Set;

import me.it_result.ca.CertificateParameters;

import org.bouncycastle.asn1.ASN1Set;

/**
 * @author roman
 *
 */
public class ProfileRegistry {
	
	private Set<Profile> profiles = new HashSet<Profile>();
	private Profile defaultProfile;

	public void addProfile(Profile profile) {
		profiles.add(profile);
	}
	
	public void setDefaultProfile(Profile profile) {
		this.defaultProfile = profile;
	}
	
	public Profile getDefaultProfile() {
		return defaultProfile;
	}
	
	public Profile getProfile(CertificateParameters certificateParameters) {
		for (Profile profile : profiles)
			if (profile.isCompatible(certificateParameters))
				return profile;
		return null;
	}
	
	public Profile getProfile(ASN1Set csrAttributes) {
		for (Profile profile : profiles)
			if (profile.isCompatible(csrAttributes))
				return profile;
		return null;
	}
	
	public static ProfileRegistry getDefaultInstance() {
		ProfileRegistry profiles = new ProfileRegistry();
		StandardProfile userCertificateProfile = new StandardProfile();
		profiles.addProfile(userCertificateProfile);
		profiles.setDefaultProfile(userCertificateProfile);
		return profiles;
	}
	
}
