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
package me.it_result.ca.db;

import static org.testng.AssertJUnit.assertEquals;
import static org.testng.AssertJUnit.assertNull;
import static org.testng.AssertJUnit.assertTrue;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Random;
import java.util.Set;

import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

/**
 * @author roman
 *
 */
public abstract class DatabaseTest {

	private Database database;
	
	@BeforeMethod
	public void setUp() {
		database = createDatabase();
	}
	
	protected abstract Database createDatabase();

	@AfterMethod
	public void tearDown() throws Exception {
		database.destroy();
	}
	
	@Test
	public void testStoreBytesData() throws Exception {
		byte[] expectedData = generateRandomData(1024);
		database.writeBytes("alias", "property", expectedData);
		byte[] actualData = database.readBytes("alias", "property");
		assertTrue(Arrays.toString(actualData) + "!=" + Arrays.toString(expectedData), Arrays.equals(expectedData, actualData));
	}
	
	@Test
	public void testUpdateBytesData() throws Exception {
		byte[] initialData = generateRandomData(1024);
		database.writeBytes("alias", "property", initialData);
		byte[] expectedData = generateRandomData(1024);
		database.writeBytes("alias", "property", expectedData);
		byte[] actualData = database.readBytes("alias", "property");
		assertTrue(Arrays.toString(actualData) + "!=" + Arrays.toString(expectedData), Arrays.equals(expectedData, actualData));
	}
	
	private byte[] generateRandomData(int length) {
		byte[] data = new byte[length];
		new Random().nextBytes(data);
		return data;
	}

	@Test
	public void testStoreStringData() throws Exception {
		String expected = generateRandomString(1024);
		database.writeString("alias", "property", expected);
		String actual = database.readString("alias", "property");
		assertEquals(expected, actual);
	}
	
	private String generateRandomString(int length) {
		StringBuffer buffer = new StringBuffer();
		for (int i = 0; i < length; i++) {
			char chr = (char)(Math.random()*24 + 40);
			buffer.append(chr);
		}
		return buffer.toString();
	}

	@Test 
	public void testUpdateStringData() throws Exception {
		String initialValue = generateRandomString(1024);
		database.writeString("alias", "property", initialValue);
		String expected = generateRandomString(1024);
		database.writeString("alias", "property", expected);
		String actual = database.readString("alias", "property");
		assertEquals(expected, actual);
	}
	
	@Test
	public void testRemoveProperty() throws Exception {
		database.writeString("alias", "property", "data");
		database.removeProperty("alias", "property");
		assertNull(database.readString("alias", "property"));
	}
	
	@Test
	public void testDestroy() throws Exception {
		database.writeString("alias", "property", "data");
		database.destroy();
		assertDatabaseDestroyed();
	}
	
	@Test
	public void testListAliases() throws Exception {
		database.writeString("alias1", "property", "data");
		database.writeString("alias2", "property", "data");
		database.writeString("alias3", "property-next", "data");
		Set<String> actualAliases = database.listAliases("property");
		Set<String> expectedAliases = new HashSet<String>(Arrays.asList(new String[] {"alias1", "alias2"}));
		assertEquals(expectedAliases, actualAliases);
	}

	protected abstract void assertDatabaseDestroyed() throws Exception;
	
}
