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

import java.util.Map;

import me.it_result.ca.Authorization;
import me.it_result.ca.CA;

/**
 * @author roman
 *
 */
public class ScepServer {

	protected static ScepServer SERVER;
	
	private Map<String, CA> caMap;
	private Map<String, Authorization> authorizationMap;
	
	/**
	 * @param caMap
	 * @param authorizationMap
	 */
	public ScepServer(Map<String, CA> caMap,
			Map<String, Authorization> authorizationMap) {
		super();
		this.caMap = caMap;
		this.authorizationMap = authorizationMap;
	}
	
	public Authorization getAuthorization(String caIdentifier) {
		return authorizationMap.get(caIdentifier);
	}
	
	public CA getCA(String caIdentifier) {
		return caMap.get(caIdentifier);
	}
	
}
