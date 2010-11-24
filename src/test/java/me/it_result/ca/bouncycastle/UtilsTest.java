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

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x509.X509Name;
import org.testng.annotations.Test;

import static org.testng.AssertJUnit.*;

/**
 * @author roman
 *
 */
public class UtilsTest {

	/**
	 * Test method for {@link me.it_result.ca.BouncyCAUtils#asAlias(org.bouncycastle.asn1.x509.X509Name)}.
	 */
	@Test
	public void testGenerateAlias() {
		String sn = "CN=test, UID=test@test";
		X500Principal x500sn = new X500Principal("UID=test@test, CN=test");
		X509Name x509sn = new X509Name(sn);
		String aliasX500 = Utils.generateAlias(x500sn);
		String aliasX509 = Utils.generateAlias(x509sn);
		String aliasStr = Utils.generateAlias(sn);
		assertEquals(aliasX509, aliasX500);
		assertEquals(aliasX500, aliasStr);
	}

}
