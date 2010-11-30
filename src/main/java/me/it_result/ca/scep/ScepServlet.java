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

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import me.it_result.ca.Authorization;
import me.it_result.ca.AuthorizationOutcome;
import me.it_result.ca.CA;
import me.it_result.ca.bouncycastle.Utils;
import me.it_result.ca.db.Database;

import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.X509Principal;
import org.jscep.response.Capability;
import org.jscep.transaction.FailInfo;
import org.jscep.transaction.OperationFailureException;

/**
 * @author roman
 *
 */
public class ScepServlet extends org.jscep.server.ScepServlet {

	/**
	 * 
	 */
	private static final long serialVersionUID = -1904719024430363584L;
	
	static final String MANUAL_AUTHORIZATION_CSR_PROPERTY = ScepServlet.class.getName() + ".csr";
	static final String REJECTED_CSR_PROPERTY = ScepServlet.class.getName() + ".csr.rejected";
	
	@Override
	protected Set<Capability> doCapabilities(String identifier) {
		Set<Capability> capabilities = new HashSet<Capability>();
		capabilities.add(Capability.POST_PKI_OPERATION);
		// TODO: query available algorithms instead
		capabilities.add(Capability.SHA_1);
		capabilities.add(Capability.SHA_256);
		capabilities.add(Capability.SHA_512);
		capabilities.add(Capability.TRIPLE_DES);
		return capabilities;
	}

	@Override
	protected List<X509Certificate> doEnroll(
			CertificationRequest certificationRequest)
			throws OperationFailureException {
		// Is csr signed already?
		try {
			for (X509Certificate cert : ca().listCertificates()) {
				String certAlias = Utils.generateAlias(cert.getSubjectX500Principal());
				String csrAlias = Utils.generateAlias(certificationRequest.getCertificationRequestInfo().getSubject());
				// TODO: compare keys, etc?
				if (certAlias.equals(csrAlias))
					return Collections.singletonList(cert);
			}
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
		// Was csr manually rejected?
		boolean rejected;
		try {
			Database db = getDatabase();
			byte[] csrBytes = certificationRequest.getEncoded();
			String alias = Utils.sha1(csrBytes);
			rejected = db.readBytes(alias, REJECTED_CSR_PROPERTY) != null;
			db.removeProperty(alias, REJECTED_CSR_PROPERTY);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
		if (rejected)
			throw new OperationFailureException(FailInfo.badMessageCheck);
		// execute request
		AuthorizationOutcome outcome = authorize(certificationRequest);
		if (outcome == AuthorizationOutcome.REJECT) 
			throw new OperationFailureException(FailInfo.badMessageCheck);
		try {
			byte[] csrBytes = certificationRequest.getEncoded();
			if (outcome == AuthorizationOutcome.ACCEPT) {
				X509Certificate certificate = ca().signCertificate(csrBytes);
				return Collections.singletonList(certificate);
			} else {
				String alias = Utils.sha1(csrBytes);
				getDatabase().writeBytes(alias, MANUAL_AUTHORIZATION_CSR_PROPERTY, csrBytes);
				return Collections.emptyList();
			}
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	private AuthorizationOutcome authorize(CertificationRequest certificationRequest) throws OperationFailureException {
		Authorization authz = getAuthorization();
		AuthorizationOutcome outcome;
		try {
			outcome = authz.isAuthorized(certificationRequest);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
		return outcome;
	}

	@Override
	protected List<X509Certificate> doGetCaCertificate(String identifier) {
		try {
			X509Certificate caCertificate = ca().getCACertificate();
			return Collections.singletonList(caCertificate);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	protected List<X509Certificate> doGetCert(X509Name issuer, BigInteger serial)
			throws OperationFailureException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	protected List<X509Certificate> doGetCertInitial(X509Name issuer,
			X509Name subject) throws OperationFailureException {
		try {
			X509Principal issuerPrincipal = new X509Principal(issuer);
			X509Principal subjectPrincipal = new X509Principal(subject);
			for (X509Certificate signedCert: ca().listCertificates()) {
				X509Principal actualIssuer = new X509Principal(signedCert.getIssuerX500Principal().getName());
				X509Principal actualSubject = new X509Principal(signedCert.getSubjectX500Principal().getName());
				if (issuerPrincipal.equals(actualIssuer) && subjectPrincipal.equals(actualSubject))
					return Collections.singletonList(signedCert);
			}
			return null;
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	protected X509CRL doGetCrl(X509Name issuer, BigInteger serial)
			throws OperationFailureException {
		throw new RuntimeException("GetCRL is not implemented yet");
	}

	@Override
	protected List<X509Certificate> getNextCaCertificate(String identifier) {
		throw new RuntimeException("GetNextCaCertificate is not implemented yet");
	}

	@Override
	protected X509Certificate getSender() {
		try {
			return ca().getCACertificate();
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	/* (non-Javadoc)
	 * @see org.jscep.server.ScepServlet#getPrivate()
	 */
	@Override
	protected PrivateKey getPrivate() {
		try {
			return ca().getCAKeypair().getPrivate();
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	
	protected CA ca() {
		ScepServerContext ctx = getScepServerContext();
		return ctx.getCA();
	}

	protected ScepServerContext getScepServerContext() {
		ScepServerContext ctx = (ScepServerContext) getServletContext().getAttribute(ScepServerContext.CONTEXT_ATTRIBUTE);
		return ctx;
	}

	protected Authorization getAuthorization() {
		ScepServerContext ctx = getScepServerContext();
		return ctx.getAuthorization();
	}

	protected Database getDatabase() {
		ScepServerContext ctx = getScepServerContext();
		return ctx.getDatabase();
	}

}
