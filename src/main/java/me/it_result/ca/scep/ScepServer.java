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
package me.it_result.ca.scep;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Set;

import me.it_result.ca.AuthorizationOutcome;
import me.it_result.ca.CAException;
import me.it_result.ca.bouncycastle.Utils;
import me.it_result.ca.db.Database;

import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.handler.ContextHandlerCollection;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;

/**
 * @author roman
 *
 */
public class ScepServer {

	private ScepServerContext context;
	private int port;
	private String hostname;
	
	private Server server;

	/**
	 * @param serverContext
	 * @param port
	 */
	public ScepServer(ScepServerContext context, int port) {
		this(context, port, null);
	}
	
	/**
	 * @param serverContext
	 * @param port
	 * @param hostname
	 */
	public ScepServer(ScepServerContext context, int port,
			String hostname) {
		super();
		this.context = context;
		this.port = port;
		this.hostname = hostname;
	}
	
	public void start() throws Exception {
		if (isStarted())
			throw new IllegalStateException("The server is started already");
		// construct the server
		if (hostname != null) {
			InetAddress host = InetAddress.getByName(hostname);
			InetSocketAddress address = new InetSocketAddress(host, port);
			server = new Server(address);
		}
		else
			server = new Server(port);
		// initialize contexts
		ContextHandlerCollection contexts = new ContextHandlerCollection();
        server.setHandler(contexts);
        ServletContextHandler root = new ServletContextHandler(contexts, "/", ServletContextHandler.SESSIONS);
        root.addServlet(new ServletHolder(new ScepServlet()), "/pkiclient.exe");
        // push scep server context
        root.setAttribute(ScepServerContext.CONTEXT_ATTRIBUTE, context);
        // start the server
        server.start();
	}
	
	public boolean isStarted() {
		return server != null && server.isStarted();
	}
	
	public void stop() throws Exception {
		if (server != null)
			server.stop();
		server = null;
	}

	/**
	 * @return the port
	 */
	public int getPort() {
		return port;
	}

	/**
	 * @return the hostname
	 */
	public String getHostname() {
		return hostname;
	}
	
	public ScepServerContext getContext() {
		return context;
	}

	public Collection<CertificationRequest> getManuallyAuthorizedCsrs() throws CAException {
		try {
			Database db = getContext().getDatabase();
			Set<String> aliases = db.listAliases(ScepServlet.MANUAL_AUTHORIZATION_CSR_PROPERTY);
			List<CertificationRequest> csrs = new ArrayList<CertificationRequest>();
			for (String alias : aliases) {
				byte[] csrBytes = db.readBytes(alias, ScepServlet.MANUAL_AUTHORIZATION_CSR_PROPERTY);
				CertificationRequest csr = new PKCS10CertificationRequest(csrBytes);
				csrs.add(csr);
			}
			return csrs;
		} catch (Exception e) {
			throw new CAException(e);
		}
	}
	
	public void authorizeManually(CertificationRequest csr, AuthorizationOutcome authorization) throws CAException {
		try {
			byte[] csrBytes = csr.getEncoded();
			String alias = Utils.sha1(csrBytes);
			Database db = getContext().getDatabase();
			Set<String> aliases = db.listAliases(ScepServlet.MANUAL_AUTHORIZATION_CSR_PROPERTY);
			if (!aliases.contains(alias)) 
				throw new CAException("The csr is not scheduled for manual authorization");
			if (authorization == AuthorizationOutcome.ACCEPT) 
				getContext().getCA().signCertificate(csrBytes);
			db.removeProperty(alias, ScepServlet.MANUAL_AUTHORIZATION_CSR_PROPERTY);
		} catch (Exception e) {
			throw new CAException(e);
		}
	}

}
