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

import me.it_result.ca.Authorization;
import me.it_result.ca.CA;

import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.handler.ContextHandlerCollection;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;

/**
 * @author roman
 *
 */
public class ScepServer {

	private CA ca;
	private Authorization authorization;
	private int port;
	private String hostname;
	
	private Server server;

	/**
	 * @param ca
	 * @param authorization
	 * @param port
	 */
	public ScepServer(CA ca, Authorization authorization, int port) {
		this(ca, authorization, port, null);
	}
	
	/**
	 * @param ca
	 * @param authorization
	 * @param port
	 * @param hostname
	 */
	public ScepServer(CA ca, Authorization authorization, int port,
			String hostname) {
		super();
		this.ca = ca;
		this.authorization = authorization;
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
        ScepServerContext ctx = new ScepServerContext(ca, authorization);
        root.setAttribute(ScepServerContext.CONTEXT_ATTRIBUTE, ctx);
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
	 * @return the ca
	 */
	public CA getCa() {
		return ca;
	}

	/**
	 * @return the authorization
	 */
	public Authorization getAuthorization() {
		return authorization;
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
	
}
