package com.github.yash777.mail;

/**
 * Common exception base class for all Application relevant exceptions.
 * 
 */
public class ApplicationException extends Exception {

	/**
	 * Generated serial version UID.
	 */
	private static final long serialVersionUID = 3256445810970539568L;

	/**
	 * identifier for Exception. Used in ASN1-like syntax.
	 */
	private String identifier;

	/**
	 * optional description for Exception.
	 */
	private String description;

	/**
	 * tells, wether the exception is expected or unexpected (business or
	 * technical)
	 */
	private boolean expected;
	/** the I18n-Message to display to the user */
	private String expectedMessageKey;
	/** the I18n-Placeholders */
	private String[] expectedMessagePlaceholders;

	/**
	 * Constructor with a single String message
	 * 
	 * @param identifier
	 *            Unique Identifier to trace back the Exception to a specific
	 *            issue.
	 * @param message
	 *            description of the Exception
	 */
	public ApplicationException(String identifier, String message) {
		super(message);
		this.identifier = identifier;
	}

	/**
	 * creates an expected exception
	 */
	public ApplicationException(String identifier, String key, String[] placeholders) {
		this(identifier, key);
		setExpected(key, placeholders);
	}

	public ApplicationException(String identifier, Throwable cause) {
		super(cause);
		this.identifier = identifier;
	}

	/**
	 * Constructor with a String message and an embedded exception
	 * 
	 * @param message
	 *            the String message
	 * @param cause
	 *            the embedded Throwable
	 */
	public ApplicationException(String identifier, String message, Throwable cause) {
		super(message, cause);
		this.identifier = identifier;
	}

	public ApplicationException(String identifier, String message, String description,
			Throwable cause) {
		super(message, cause);
		this.identifier = identifier;
		this.description = description;
	}

	public ApplicationException(String identifier, String message, String description) {
		super(message);
		this.identifier = identifier;
		this.description = description;
	}

	/**
	 * @return Returns the description.
	 */
	public String getDescription() {
		return description;
	}

	/**
	 * @return Returns the identifier.
	 */
	public String getIdentifier() {
		return identifier;
	}

	public void setExpected(String key, String[] placeholders) {
		this.expected = true;
		this.expectedMessageKey = key;
		this.expectedMessagePlaceholders = placeholders;
	}

	public boolean isExpected() {
		return expected;
	}

	public String getExpectedMessageKey() {
		return expectedMessageKey;
	}

	public String[] getExpectedMessagePlaceholders() {
		return expectedMessagePlaceholders;
	}

}