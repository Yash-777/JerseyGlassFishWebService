package com.github.yash777.mail;

import java.io.Closeable;
import java.io.IOException;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * A utility for handling resources like stream and connections.
 */
public class ResourceUtil {

	private final static Log log = LogFactory.getLog(ResourceUtil.class);
	
	private ResourceUtil() {
		
	}

	public static void close(Closeable resource) {
		if (resource != null) {
			try {
				resource.close();
			} catch (IOException e) {
				log.error(e,e);
			}
		}
	}
	
	public static void close(Statement statement) {
		if (statement != null) {
			try {
				statement.close();
			} catch (SQLException e) {
				log.error(e,e);
			}
		}
	}
	public static void close(ResultSet resultSet) {
		if (resultSet != null) {
			try {
				resultSet.close();
			} catch (SQLException e) {
				log.error(e,e);
			}
		}
	}
	public synchronized static void close(Connection connection) {
		if (connection != null) {
			try {
				connection.close();
			} catch (SQLException e) {
				log.error(e,e);
			}
		}
	}
}