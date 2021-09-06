package com.github.yash.database;

import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NameClassPair;
import javax.naming.NamingException;
import javax.sql.DataSource;

import oracle.jdbc.OracleConnection;
import oracle.jdbc.driver.OracleDriver;

public class DBConnection {
	static Map<String, String> connectionUrls = new HashMap<String, String>();
	static {
		// validationQuery="select 1 from dual", Host, Port, Sid (default=xe), userName, Password
		connectionUrls.put("CLOUD_DEV", "yash777.github.onmicrosoft.com~1521~DEVYASH~dev~dev@123");
		connectionUrls.put("CLOUD_INT", "yash777.github.onmicrosoft.com~1521~INTYASH~dev~dev@123");
	}
	
	public static OracleConnection getDelegatingConnection(Connection conn) throws SQLException {
		OracleConnection oracleConnection = null;
		
		// oracle.jdbc.driver.T4CConnection cannot be cast to org.apache.tomcat.dbcp.dbcp2.DelegatingConnection
		// org.apache.commons.dbcp.PoolingDataSource
		/*if (conn instanceof org.apache.commons.dbcp.DelegatingConnection) {
			oracleConnection = (OracleConnection) ((DelegatingConnection<?>) conn).getInnermostDelegate();
		} else if (conn instanceof org.apache.tomcat.dbcp.dbcp.DelegatingConnection) {
			org.apache.tomcat.dbcp.dbcp.DelegatingConnection del = new org.apache.tomcat.dbcp.dbcp.DelegatingConnection(conn.getConnection());
			OracleConnection con = (OracleConnection) del.getInnermostDelegate();
		}*/
		
		//oracleConnection = ( OracleConnection ) conn.getMetaData().getConnection();
		// oracle.sql.ArrayDescriptor desc = oracle.sql.ArrayDescriptor.createDescriptor("TABLE_VIEW", oracleConnection);
		
		oracleConnection = (OracleConnection) conn;
		return oracleConnection;
	}
	
	public DBConnection() {
	}
	String connectionName; 
	public DBConnection(String connectionName) {
		this.connectionName = connectionName; 
	}
	Connection conn = null;
	
	public static void main(String[] args) throws SQLException, IOException {
		DBConnection obj3 = new DBConnection("Conneciton 3");
		obj3.initialContextJNDI(); // WEB
		/*
		testMain(obj3);
		
		// Terminates the currently running Java Virtual Machine. 
		//System.exit(1);
		
		System.in.read();
		System.in.read();
		
		System.out.println("Call GC : Objects will GC when Object Creation Stack execution completes.");
		System.gc();*/
		
		/*System.in.read();
		System.in.read();*/
		
	}
	public static void testMain(DBConnection obj3) throws SQLException, IOException {
		DBConnection obj = new DBConnection("Conneciton 1");
		DBConnection obj2 = new DBConnection("Conneciton 2");
		try {
			obj.conn = DBConnection.getConnection("DEV");
			
		} finally {
			System.out.println("Release Resource in finally()");
			obj.conn.close();
		}
	}

	/**
	 * Obtains a new Connection to the Database. By default, DB internal connection is obtained via 
	 * "jdbc:default:connection", but a Test-Mode can be used by setting the System-property "run.mode"
	 * to "test" and the property "connection.url" to any valid JDBC URL.
	 */
	public static Connection getConnection(String envKey) throws SQLException {
		Connection connection = null;
		OracleDriver driverClassName = new oracle.jdbc.driver.OracleDriver();
		try {
			java.sql.DriverManager.registerDriver(driverClassName);
			
			if (connectionUrls.containsKey(envKey)) {
				String uralParams = connectionUrls.get(envKey);
				String[] split = uralParams.split("~");
				
				StringBuffer buffer = new StringBuffer();
				buffer.append("jdbc:oracle:thin:@(DESCRIPTION=(ENABLE=BROKEN)(ADDRESS=(PROTOCOL=tcp)(PORT="+split[1]);
				buffer.append(")(HOST="+split[0]);
				buffer.append("))(CONNECT_DATA=(SID="+split[2]+")))");
				
				String usernName = split[3], password = split[4];
				
				// jdbc:oracle:driver_type:[username/password]@[//]host_name[:port][:ORCL]
				String connectionUrl = buffer.toString();
				System.out.println("DB URL: "+connectionUrl);
				// connection = DriverManager.getConnection("jdbc:default:connection:");
				//connection = DriverManager.getConnection(connectionUrl, usernName, password);
				
				// https://docs.oracle.com/javase/tutorial/jdbc/basics/connecting.html
				Properties connectionProps = new Properties();
				connectionProps.put("charset", "UTF8");
				connectionProps.put("lc_ctype", "en_US.UTF-8");
				connectionProps.put("user", usernName);
				connectionProps.put("password", password);
				
				connection = DriverManager.getConnection(connectionUrl, connectionProps);
				System.out.println("Connection : "+ connection);
			}
			return connection;
		} catch (Exception e) {
			e.printStackTrace();
			throw new SQLException(e);
		} finally {
			DriverManager.deregisterDriver(driverClassName);
		}
	}
	// "super.finalize()" should be called at the end of "Object.finalize()" implementations - https://rules.sonarsource.com/java/RSPEC-1114
	@Override
	protected void finalize() throws Throwable {
		System.out.println("Overriding finalize method to check which object is garbage collected");
		System.out.println(this.connectionName + " successfully garbage collected");
		try {
			if (conn != null) {
				System.out.println("Object Release Resource from finalize()");
				conn.close();
			}
		} finally {
			super.finalize();
		}
	}
	
	// Web Application - Read the DB details form Contex.xml
	private static final String JNDI_SUBCONTEXT = "java:comp/env/";
	private static final String JNDI_SUBCONTEXT_LogicalName = "java:comp/env/jdbc/";
	private ArrayList<DataSource> dataSourcesList = new ArrayList<DataSource>();
	public void initialContextJNDI() {
		try {
			Context ctx = new InitialContext();
			/** To Get the list of NameClassPair registered with JNDI */
			javax.naming.NamingEnumeration<NameClassPair> list = ctx.list(JNDI_SUBCONTEXT_LogicalName);
			String datasourceName = "";
			while (list.hasMore()) {
				try {
					datasourceName = JNDI_SUBCONTEXT_LogicalName + "" + list.next().getName();
					DataSource dataSource = (DataSource) ctx.lookup(datasourceName);
					System.out.println("Initialized datasource " + datasourceName + " successfully.");
					dataSourcesList.add(dataSource);
				} catch (NamingException e) {
					System.out.println("Datasource with name " + datasourceName + " not found in jndi-tree."+e);
					break;
				}
			}
			System.out.println("DataSourece List : "+dataSourcesList.toString());
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	public Connection getDataSourceConnection(int dataSourceIndex) {
		try {
			for (int i = 0; i < dataSourcesList.size(); i++) {
				if (i == dataSourceIndex) {
					DataSource dataSource = dataSourcesList.get(dataSourceIndex);
					conn = dataSource.getConnection();
					
					/** get Meta Data for user */
					String dbUser = conn.getMetaData().getUserName();
					System.out.println("DataSourceConnection user name is " + dbUser);
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return conn;
	}
	
	public Connection getDataSourceConnectionByResourceName(String environmentName) {
		Connection conn = null;
		try {
			Context ctx = new InitialContext();
			// OracleDataSource odsconn = (OracleDataSource)ctx.lookup("jdbc/sampledb");
			String datasourceName = (String) ctx.lookup(JNDI_SUBCONTEXT + "" + environmentName);
			javax.sql.DataSource dataSource = (DataSource) ctx.lookup(JNDI_SUBCONTEXT + "" + datasourceName);
			conn = dataSource.getConnection();
			
			/** get Meta Data for user */
			String dbUser = conn.getMetaData().getUserName();
			System.out.println("DataSourceConnectionByResourceName user name is " + dbUser);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return conn;
	}
}

/*
https://stackoverflow.com/questions/2324937/code-to-list-all-the-entries-in-jndi-on-remote-machine
https://stackoverflow.com/questions/20033596/how-to-configure-jndi-connection-pooling-for-more-than-one-database

-- DB_Name/SERVICE NAME/instance_name [XE] [DEVYASH]
-- jdbc:oracle:thin:@<server_host>:1521:<instance_name>
select name from V$database;  -- DB Name
select instance_name from v$instance; --
select sys_context('userenv','instance_name') from dual; -- Current Instance DB Name
select sys_context('userenv','db_name') from dual;

select ora_database_name from dual;  -- Yash777.WORLD
select * from global_name; -- YASH777.WORLD

-- server_host
select sys_context('userenv', 'server_host') from dual;

-- User Instance
select user from dual;  -- User Name of Current User Instance

-- port
-- (ADDRESS=(PROTOCOL=TCP)(HOST=10.55.72.14)(PORT=1521))
select * from v$listener_network;

--
SELECT sys_context('USERENV', 'SID') FROM DUAL;

-- 
variable i number;
variable dbname varchar2(30);
begin
    :i:=dbms_utility.get_parameter_value('db_name',:i,:dbname);
  end;
-- PL/SQL procedure successfully completed.
print dbname;
--

-- jdbc/name(any name --this will use in project(jndi)
*/