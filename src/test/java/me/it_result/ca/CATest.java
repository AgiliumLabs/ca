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

import static org.testng.AssertJUnit.assertFalse;
import static org.testng.AssertJUnit.assertTrue;
import static org.testng.AssertJUnit.assertNotNull;
import static org.testng.AssertJUnit.fail;

import java.util.Date;

import org.testng.annotations.Test;

/**
 * @author roman
 *
 */
public abstract class CATest {

	@Test
	public void testDestroy() throws CAException {
		// Given an initialized CA
		ca().initialize();
		// When destroy is invoked
		ca().destroy();
		// Then CA certificate, client certificates and CRLs are destroyed
		assertFalse(ca().isInitialized());
	}
	
	@Test
	public void testInitialize() throws Exception {
		// Given an uninitialized CA 
		assertFalse(ca().isInitialized());
		// When CA is initialized
		Date minBeforeDate = new Date(System.currentTimeMillis() - 1000);
		ca().initialize();
		Date maxBeforeDate = new Date(System.currentTimeMillis() + 1000);
		// Then CA becomes initialized
		assertTrue(ca().isInitialized());
		// And CA keypairs and certificates are generated
		assertNotNull(ca().getCACertificate());
		verifyCACertificates(minBeforeDate, maxBeforeDate);
		assertNotNull(ca().getCAKeypair());
		// And an empty CRL is generated
		// TODO: CRL impl
	}
	
	@Test 
	public void testInitializeInitialized() throws Exception {
		// Given an uninitialized CA 
		assertFalse(ca().isInitialized());
		// When CA is initialized
		ca().initialize();
		// Then attempt to initialize it once more time should fail
		try {
			ca().initialize();
			fail("AlreadyInitializedException expected");
		} catch (AlreadyInitializedException e) {}
	}
	
	protected abstract void verifyCACertificates(Date minBeforeDate, Date maxBeforeDate) throws Exception;

	protected abstract CA ca();
		
}
