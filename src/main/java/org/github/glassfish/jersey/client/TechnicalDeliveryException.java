package org.github.glassfish.jersey.client;

public class TechnicalDeliveryException extends Exception {
	private static final long serialVersionUID = 372683934322930080L;
	public TechnicalDeliveryException() {
		super();
	}
	public TechnicalDeliveryException(String message) {
		super(message);
	}
	public TechnicalDeliveryException(Throwable cause) {
		super(cause);
	}
	public TechnicalDeliveryException(String message, Throwable cause) {
		super(message, cause);
	}
}
