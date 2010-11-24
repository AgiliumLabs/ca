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

/**
 * @author roman
 *
 */
public class NotInitializedException extends CAException {

	/**
	 * 
	 */
	private static final long serialVersionUID = 5344480213361731061L;

	/**
	 * 
	 */
	public NotInitializedException() {
		super();
	}

	/**
	 * @param message
	 * @param cause
	 */
	public NotInitializedException(String message, Throwable cause) {
		super(message, cause);
	}

	/**
	 * @param message
	 */
	public NotInitializedException(String message) {
		super(message);
	}

	/**
	 * @param cause
	 */
	public NotInitializedException(Throwable cause) {
		super(cause);
	}

}
