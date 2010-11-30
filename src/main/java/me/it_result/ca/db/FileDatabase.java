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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.security.NoSuchAlgorithmException;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;

import org.bouncycastle.util.encoders.Base64;

/**
 * @author roman
 *
 */
public class FileDatabase implements Database {

	private String databaseLocation;
	
	public FileDatabase(String databaseLocation) {
		super();
		this.databaseLocation = databaseLocation;
	}

	/* (non-Javadoc)
	 * @see me.it_result.ca.db.Database#destroy()
	 */
	@Override
	public void destroy() {
		File dbDir = new File(databaseLocation);
		File[] dataFiles = dbDir.listFiles(); 
		if (dataFiles != null) 
			for (int i = 0; i < dataFiles.length; i++)
				dataFiles[i].delete();
		dbDir.delete();
	}

	/* (non-Javadoc)
	 * @see me.it_result.ca.db.Database#readBytes(java.lang.String, java.lang.String)
	 */
	@Override
	public byte[] readBytes(String alias, String property)
			throws Exception {
		String value = executeDataCommand(new ReadCommand(alias, property));
		byte[] data = value != null ? Base64.decode(value) : null;
		return data;
	}
	
	private <T> T executeDataCommand(DataCommand<T> command) throws IOException, NoSuchAlgorithmException {
		File dataFile = getDataFile();
		FileLock lock = null;
		try {
			lock = lockFile(dataFile);
			T value = executeDataCommand(command, dataFile);
			return value;
		} finally {
			unlockFile(lock);
		}
	}

	private <T> T executeDataCommand(DataCommand<T> command, File dataFile) throws IOException {
		InputStream is = new FileInputStream(dataFile);
		Properties data = new Properties();
		try {
			data.load(is);
		} finally {
			try { is.close(); } catch (Exception e) {}
		}
		return command.execute(data, dataFile);
	}

	private void unlockFile(FileLock lock) {
		// data is not being written via this channel
		// try { lock.channel().force(true); } catch (Exception e) {}
		try { lock.release(); } catch (Exception e) {}
		try { lock.channel().close(); } catch (Exception e) {}
	}

	private FileLock lockFile(File dataFile) throws IOException {
		if (!dataFile.exists()) {
			dataFile.getParentFile().mkdirs();
			dataFile.createNewFile();
		}
		FileOutputStream is = new FileOutputStream(dataFile, true);
		FileChannel fc = is.getChannel();
		return fc.lock();
	}

	private File getDataFile() throws NoSuchAlgorithmException {
		return new File(databaseLocation);
	}

	/* (non-Javadoc)
	 * @see me.it_result.ca.db.Database#readString(java.lang.String, java.lang.String)
	 */
	@Override
	public String readString(String alias, String property) throws Exception {
		String value = executeDataCommand(new ReadCommand(alias, property));
		return value;
	}

	/* (non-Javadoc)
	 * @see me.it_result.ca.db.Database#removeProperty(java.lang.String, java.lang.String)
	 */
	@Override
	public void removeProperty(String alias, String property) throws Exception {
		executeDataCommand(new RemoveCommand(alias, property));
	}

	/* (non-Javadoc)
	 * @see me.it_result.ca.db.Database#writeBytes(java.lang.String, java.lang.String, java.io.InputStream)
	 */
	@Override
	public void writeBytes(String alias, String property, byte[] data)
			throws Exception {
		byte[] encoded = Base64.encode(data);
		executeDataCommand(new WriteCommand(new String(encoded), alias, property));
	}

	/* (non-Javadoc)
	 * @see me.it_result.ca.db.Database#writeString(java.lang.String, java.lang.String, java.lang.String)
	 */
	@Override
	public void writeString(String alias, String property, String data)
			throws Exception {
		executeDataCommand(new WriteCommand(data, alias, property));
	}
	
	@Override
	public Set<String> listAliases(String property) throws Exception {
		Set<String> aliases = executeDataCommand(new ListAliasesCommand(property));
		return aliases;
	}

	private interface DataCommand<T> {
		
		public T execute(Properties data, File dataFile) throws IOException;
		
	}
	
	private class ReadCommand implements DataCommand<String> {

		private String alias;
		private String property;
		
		public ReadCommand(String alias, String property) {
			super();
			this.alias = alias;
			this.property = property;
		}

		@Override
		public String execute(Properties data, File dataFile) {
			String result = null;
			int maxRecordIndex = Integer.parseInt(data.getProperty("record.max.index", "1"));
			for (int i = 1; i <= maxRecordIndex; i++) {
				String recordAlias = data.getProperty(i + ".alias");
				String recordProperty = data.getProperty(i + ".property");
				if (recordAlias != null && recordAlias.equals(alias) && recordProperty.equals(property)) {  
					result = data.getProperty(i + ".value");
					break;
				}
			}
			return result;
		}

	}
	
	private class RemoveCommand implements DataCommand<Object> {

		private String alias;
		private String property;
		
		public RemoveCommand(String alias, String property) {
			super();
			this.alias = alias;
			this.property = property;
		}

		@Override
		public Object execute(Properties data,
				File dataFile) throws IOException {
			int maxRecordIndex = Integer.parseInt(data.getProperty("record.max.index", "1"));
			for (int i = 1; i <= maxRecordIndex; i++) {
				String recordAlias = data.getProperty(i + ".alias");
				String recordProperty = data.getProperty(i + ".property");
				if (recordAlias != null && recordAlias.equals(alias) && recordProperty.equals(property)) {
					data.remove(i + ".alias");
					data.remove(i + ".property");
					data.remove(i + ".value");
				}
			}
			OutputStream os = new FileOutputStream(dataFile);
			try {
				data.store(os, null);
				os.flush();
			} finally {
				try { os.close(); } catch (Exception e) {}
			}
			return null;
		}
		
	}

	private class WriteCommand implements DataCommand<Object> {

		private String value;
		private String alias;
		private String property;
		
		public WriteCommand(String value, String alias, String property) {
			super();
			this.value = value;
			this.alias = alias;
			this.property = property;
		}
		
		@Override
		public Object execute(Properties data, File dataFile) throws IOException {
			int maxRecordIndex = Integer.parseInt(data.getProperty("record.max.index", "0"));
			boolean updated = false;
			for (int i = 1; i <= maxRecordIndex; i++) {
				String recordAlias = data.getProperty(i + ".alias");
				String recordProperty = data.getProperty(i + ".property");
				if (recordAlias != null && recordAlias.equals(alias) && recordProperty.equals(property)) {
					data.setProperty(i + ".value", value);
					updated = true;
					break;
				}
			}
			if (!updated) {
				maxRecordIndex++;
				data.setProperty("record.max.index", Integer.toString(maxRecordIndex));
				data.setProperty(maxRecordIndex + ".alias", alias);
				data.setProperty(maxRecordIndex + ".property", property);
				data.setProperty(maxRecordIndex + ".value", value);
			}
			OutputStream os = new FileOutputStream(dataFile);
			try {
				data.store(os, null);
				os.flush();
			} finally {
				try { os.close(); } catch (Exception e) {}
			}
			return null;
		}

	}
	
	private class ListAliasesCommand implements DataCommand<Set<String>> {

		private String property;
		
		public ListAliasesCommand(String property) {
			super();
			this.property = property;
		}

		@Override
		public Set<String> execute(Properties data, File dataFile) throws IOException {
			Set<String> result = new HashSet<String>();
			int maxRecordIndex = Integer.parseInt(data.getProperty("record.max.index", "0"));
			for (int i = 1; i <= maxRecordIndex; i++) {
				String recordAlias = data.getProperty(i + ".alias");
				String recordProperty = data.getProperty(i + ".property");
				if (recordProperty != null && recordProperty.equals(property))
					result.add(recordAlias);
			}
			return result;
		}

	}

}
