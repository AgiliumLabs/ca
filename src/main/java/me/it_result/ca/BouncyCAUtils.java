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

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x509.X509Name;

/**
 * @author roman
 *
 */
public class BouncyCAUtils {

	private BouncyCAUtils() {}
	
	public static String generateAlias(X509Name name) {
		return name.toString(false, X509Name.DefaultSymbols);
	}
	
	public static String generateAlias(X500Principal name) {
		return new X509Name(name.getName()).toString(true, X509Name.DefaultSymbols);
	}
	
	public static String generateAlias(String name) {
		return generateAlias(new X509Name(name));
	}
	
}
