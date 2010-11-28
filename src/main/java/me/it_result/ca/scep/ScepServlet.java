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
import me.it_result.ca.CA;

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
	
	protected static final String DEFAULT_CA_ID = "default";

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
		checkAuthorization(certificationRequest);
		try {
			byte[] csrBytes = certificationRequest.getEncoded();
			X509Certificate certificate = ca().signCertificate(csrBytes);
			return Collections.singletonList(certificate);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	private void checkAuthorization(CertificationRequest certificationRequest) throws OperationFailureException {
		Authorization authz = getAuthorization();
		boolean authorized;
		try {
			authorized = authz.isAuthorized(certificationRequest);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
		if (!authorized) 
			throw new OperationFailureException(FailInfo.badMessageCheck);
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
		ScepServer scepServer = getScepServer();
		return scepServer.getCA(DEFAULT_CA_ID);
	}

	protected ScepServer getScepServer() {
		return ScepServer.SERVER;
	}

	protected Authorization getAuthorization() {
		ScepServer scepServer = getScepServer();
		return scepServer.getAuthorization(DEFAULT_CA_ID);
	}

}
