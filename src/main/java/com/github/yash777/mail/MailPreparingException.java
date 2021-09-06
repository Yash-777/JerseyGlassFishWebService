package com.github.yash777.mail;

/**
 * This exception will be thrown if searching XML documents for a mandatory node
 * has returned no result.
 * 
 * @author W7375
 * @created 25.05.2005
 * @version $Id: MandatoryNodeMissingException.java,v 1.3 2005/06/09 17:32:57
 *          xwagnert Exp $
 *          <p>
 */
public class MailPreparingException extends ApplicationException {

	/**
	 * for serialization purposes.
	 */
	private static final long serialVersionUID = 3258128059583510583L;

	/**
	 * Constructor with a single String message
	 * 
	 * @param identifier
	 *            Unique Identifier to trace back the Exception to a specific
	 *            issue.
	 * @param message
	 *            description of the Exception
	 */
	public MailPreparingException(String identifier, String message) {
		super(identifier, message);
	}

	public MailPreparingException(String identifier, Throwable cause) {
		super(identifier, cause);
	}

	/**
	 * Constructor with a String message and an embedded exception
	 * 
	 * @param message
	 *            the String message
	 * @param cause
	 *            the embedded Throwable
	 */
	public MailPreparingException(String identifier, String message,
			Throwable cause) {
		super(identifier, message, cause);
	}

	public MailPreparingException(String identifier, String message,
			String description, Throwable cause) {
		super(identifier, message, description, cause);
	}

	public MailPreparingException(String identifier, String message,
			String description) {
		super(identifier, message, description);
	}

}