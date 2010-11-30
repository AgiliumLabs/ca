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

import static org.testng.AssertJUnit.assertFalse;

import java.io.File;

import org.testng.annotations.Test;

/**
 * @author roman
 *
 */
public class FileDatabaseTest extends DatabaseTest {

	public static final String DB_LOCATION = "target/filedb.test/db";

	@Override
	protected Database createDatabase() {
		return new FileDatabase(DB_LOCATION);
	}

	@Test
	public void emptyTestNgMarker() {}
	
	@Override
	protected void assertDatabaseDestroyed() throws Exception {
		assertFalse(new File(DB_LOCATION).exists());
	}

}
