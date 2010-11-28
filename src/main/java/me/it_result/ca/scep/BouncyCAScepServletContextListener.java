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

import java.util.Collections;

import javax.servlet.ServletContext;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

import me.it_result.ca.Authorization;
import me.it_result.ca.CA;
import me.it_result.ca.bouncycastle.BouncyCA;
import me.it_result.ca.bouncycastle.ChallengePasswordAuthorization;
import me.it_result.ca.bouncycastle.ProfileRegistry;

/**
 * TODO: logging
 * 
 * @author roman
 *
 */
public class BouncyCAScepServletContextListener implements
		ServletContextListener {

	/* (non-Javadoc)
	 * @see javax.servlet.ServletContextListener#contextDestroyed(javax.servlet.ServletContextEvent)
	 */
	@Override
	public void contextDestroyed(ServletContextEvent event) {
		return;
	}

	/* (non-Javadoc)
	 * @see javax.servlet.ServletContextListener#contextInitialized(javax.servlet.ServletContextEvent)
	 */
	@Override
	public void contextInitialized(ServletContextEvent event) {
		try {
			ServletContext ctx = event.getServletContext();
			String keystore = readStringParameter(ctx, "keystore", "ca.keystore");
			String keyAlgorithm = readStringParameter(ctx, "keyAlgorithm", "RSA");
			int keyBits = readIntParameter(ctx, "keyBits", 2048); 
			int validityDays = readIntParameter(ctx, "validityDays", 365);
			String keystorePassword = readStringParameter(ctx, "keystorePassword", "changeit");
			String issuer = readStringParameter(ctx, "issuer", "CN=CA");
			String signatureAlgorithm = readStringParameter(ctx, "signatureAlgorithm", "SHA512WithRSA");
			BouncyCA ca = new BouncyCA(keystore, keyAlgorithm, keyBits, validityDays, keystorePassword, issuer, signatureAlgorithm, ProfileRegistry.getDefaultInstance());
			if (!ca.isInitialized())
				ca.initialize();
			Authorization authz = new ChallengePasswordAuthorization(keystore + ".passwords");
			ScepServer server = new ScepServer(Collections.singletonMap(ScepServlet.DEFAULT_CA_ID, (CA) ca), Collections.singletonMap(ScepServlet.DEFAULT_CA_ID, authz));
			ScepServer.SERVER = server;
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private int readIntParameter(ServletContext ctx, String name, int defaultValue) {
		int value = defaultValue;
		String valueStr = ctx.getInitParameter(name);
		try {
			value = valueStr != null ? Integer.parseInt(valueStr) : defaultValue;
		} catch (NumberFormatException e) {}
		return value;
	}

	private String readStringParameter(ServletContext ctx, String name, String defaultValue) {
		String value = ctx.getInitParameter(name);
		if (value == null)
			value = defaultValue;
		return value;
	}
	
}
