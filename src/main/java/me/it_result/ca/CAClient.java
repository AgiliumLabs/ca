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

import java.security.KeyPair;
import java.security.cert.X509Certificate;

/**
 * The CA client is intended to be used with a single CA. In order to enroll or
 * store certificates belonging to multiple CAs, create several instances of 
 * CAClient, one instance per CA.
 * 
 * The client is assumed to use an unique subject for every certificate. 
 * 
 * @author roman
 *
 */
public interface CAClient {
	
	/**
	 * Cleans up the certificate stores
	 * 
	 * @throws CAException
	 */
	public void destroy() throws CAException;
	
	/**
	 * Client is considered initialized in case CA certificate was assigned the
	 * client
	 * 
	 * @return initialization status
	 */
	public boolean isInitialized();
	
	/**
	 * Assigns a CA certificate to the client
	 * 
	 * @param caCertificate The CA certificate
	 * 
	 * @throws AlreadyInitializedException in case the CA is initialized already
	 * @throws CAException
	 */
	public void initialize(X509Certificate caCertificate) throws AlreadyInitializedException, CAException;
	
	/**
	 * @return CA certificate
	 * 
	 * @throws NotInitializedException in case the instance was not 
	 * initialized yet
	 * @throws CAException
	 */
	public X509Certificate getCaCertificate() throws NotInitializedException, CAException;

	/**
	 * Generates a CSR given a subject. If the keypair is already generated for
	 * the subject, the same keypair is used for generating CSR.
	 * 
	 * @param certificateParameters the certificate parameters
	 * 
	 * @return a DER-encoded PKCS#10 CSR
	 * 
	 * @throws CAException
	 */
	public byte[] generateCSR(CertificateParameters certificateParameters) throws CAException;
	
	/**
	 * Given subject name, returns a keypair generated in generateCSR method. In
	 * case the keypair for the given subject name was not created yet, null is 
	 * returned. 
	 *  
	 * @param subjectDN subject name
	 * 
	 * @return the keypair used for certificate with a given subject name.
	 * 
	 * @throws CAException
	 */
	public KeyPair getKeypair(String subjectDN) throws CAException;
	
	/**
	 * Given subject name, returns a certificate. In case signed certificate is 
	 * not stored yet, a self-signed certificate is returned. In case a keypair
	 * was not generated for this subject name yet, null is returned.
	 * 
	 * @param subjectDN subject name
	 * 
	 * @return a X509 certificate
	 * 
	 * @throws CAException
	 */
	public X509Certificate getCertificate(String subjectDN) throws CAException;
	
	/**
	 * Stores a signed certificate.
	 *  
	 * @param certificate the signed certificate
	 * 
	 * @throws NotInitializedException in case the CA certificate is not 
	 * assigned yet to this client
	 * @throws InvalidCertificateKeyException in case the signed certificate 
	 * public key does not matches the keypair used for the certificate subject
	 * name
	 * @throws InvalidCAException in case the certificate is issued by a CA 
	 * this client does not belong to
	 * @throws CAException
	 */
	public void storeCertificate(X509Certificate certificate) throws NotInitializedException, InvalidCertificateKeyException, InvalidCAException, CAException;
	
}
