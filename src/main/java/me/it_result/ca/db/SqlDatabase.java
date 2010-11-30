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

import java.io.ByteArrayInputStream;
import java.sql.Blob;
import java.sql.Clob;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashSet;
import java.util.Set;

/**
 * @author roman
 *
 */
public class SqlDatabase implements Database {
	
	private String driverClassName;
	private String jdbcUrl;
	private String username;
	private String password;
	
	public SqlDatabase(String driverClassName, String jdbcUrl, String username, String password) {
		super();
		this.driverClassName = driverClassName;
		this.jdbcUrl = jdbcUrl;
		this.username = username;
		this.password = password;
	}

	public void destroy() throws SQLException {
		Connection connection = getConnection();
		try {
			Statement stmt = connection.createStatement();
			stmt.execute("drop table property");
		} finally {
			connection.close();
		}
	}
	
	public Connection getConnection() throws SQLException {
		try {
			Class.forName(driverClassName);
		} catch (ClassNotFoundException e) {
			throw new SQLException(e);
		}
		Connection connection = DriverManager.getConnection(jdbcUrl, username, password);
		try {
			connection.setAutoCommit(false);
			connection.setTransactionIsolation(Connection.TRANSACTION_SERIALIZABLE);
			Statement stmt = connection.createStatement();
			if (!isSchemaInitialized(connection)) 
				stmt.executeUpdate("create table property(alias varchar(2048) not null, property varchar(2048) not null, bytesData longvarbinary null, stringData longvarchar null, primary key(alias, property));");
			return connection;
		} catch (SQLException e) {
			try { connection.close(); } catch (Exception ex) {}
			throw new SQLException(e);
		}
	}
	
	private boolean isSchemaInitialized(Connection connection) throws SQLException {
		DatabaseMetaData metadata = connection.getMetaData();
		ResultSet mrs = metadata.getTables(null, null, "PROPERTY", null);
		return mrs.next();
	}

	public void writeBytes(String alias, String property, byte[] data) throws SQLException {
		Connection connection = getConnection();
		try {
			PreparedStatement stmt;
			connection.setSavepoint();
			if (!isPropertySaved(connection, alias, property)) {
				stmt = connection.prepareStatement("insert into property(alias, property, bytesData) values(?, ?, ?)");
				stmt.setString(1, alias);
				stmt.setString(2, property);
				stmt.setBinaryStream(3, new ByteArrayInputStream(data));
			} else {
				stmt = connection.prepareStatement("update property set bytesData = ? where alias = ? and property = ?");
				stmt.setBinaryStream(1, new ByteArrayInputStream(data));
				stmt.setString(2, alias);
				stmt.setString(3, property);
			}
			stmt.execute();
			connection.commit();
		} finally {
			connection.close();
		}
	}
	
	private boolean isPropertySaved(Connection connection, String alias, String property) throws SQLException {
		PreparedStatement stmt = connection.prepareStatement("select count(*) from property where alias = ? and property = ?");
		stmt.setString(1, alias);
		stmt.setString(2, property);
		ResultSet rs = stmt.executeQuery();
		return rs.next() && rs.getLong(1) > 0;
	}

	public void writeString(String alias, String property, String data) throws SQLException {
		Connection connection = getConnection();
		try {
			PreparedStatement stmt;
			connection.setSavepoint();
			if (!isPropertySaved(connection, alias, property)) {
				stmt = connection.prepareStatement("insert into property(alias, property, stringData) values(?, ?, ?)");
				stmt.setString(1, alias);
				stmt.setString(2, property);
				// Causes infinite cycle in hsqldb
				// stmt.setCharacterStream(3, new StringReader(data));
				stmt.setString(3, data);
			} else {
				stmt = connection.prepareStatement("update property set stringData = ? where alias = ? and property = ?");
				stmt.setString(1, data);
				stmt.setString(2, alias);
				stmt.setString(3, property);
			}
			stmt.execute();
			connection.commit();
		} finally {
			connection.close();
		}
	}
	
	public void removeProperty(String alias, String property) throws SQLException {
		Connection connection = getConnection();
		try {
			PreparedStatement stmt = connection.prepareStatement("delete from property where alias = ? and property = ?");
			stmt.setString(1, alias);
			stmt.setString(2, property);
			stmt.execute();
			connection.commit();
		} finally {
			connection.close();
		}
	}
	
	public byte[] readBytes(String alias, String property) throws SQLException {
		Connection connection = getConnection();
		try {
			PreparedStatement stmt = connection.prepareStatement("select bytesData from property where alias = ? and property = ?");
			stmt.setString(1, alias);
			stmt.setString(2, property);
			ResultSet rs = stmt.executeQuery();
			byte[] result = null;
			if (rs.next()) {
				Blob blob = rs.getBlob(1);
				result = blob.getBytes(1, (int) blob.length());
			}
			return result;
		} finally {
			connection.close();
		}
	}
	
	public String readString(String alias, String property) throws SQLException {
		Connection connection = getConnection();
		try {
			PreparedStatement stmt = connection.prepareStatement("select stringData from property where alias = ? and property = ?");
			stmt.setString(1, alias);
			stmt.setString(2, property);
			ResultSet rs = stmt.executeQuery();
			String result = null;
			if (rs.next()) {
				Clob clob = rs.getClob(1);
				result = clob.getSubString(1, (int) clob.length());
			}
			return result;
		} finally {
			connection.close();
		}
	}

	@Override
	public Set<String> listAliases(String property) throws Exception {
		Connection connection = getConnection();
		try {
			PreparedStatement stmt = connection.prepareStatement("select alias from property where property = ?");
			stmt.setString(1, property);
			ResultSet rs = stmt.executeQuery();
			Set<String> result = new HashSet<String>();
			while (rs.next()) 
				result.add(rs.getString("alias"));
			return result;
		} finally {
			connection.close();
		}
	}
	
}
