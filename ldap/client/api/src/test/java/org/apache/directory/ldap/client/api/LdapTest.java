package org.apache.directory.ldap.client.api;

import org.apache.directory.api.ldap.codec.api.LdapApiServiceFactory;
import org.apache.directory.api.ldap.model.cursor.EntryCursor;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.api.ldap.model.name.Dn;
import org.junit.Ignore;
import org.junit.Test;

public class LdapTest
{
    @Test
    @Ignore
    public void test2() throws Exception
    {
        LdapConnectionConfig config = new LdapConnectionConfig();
        //config.setLdapHost("10.107.183.18");
        config.setLdapHost("10.71.6.75");
        config.setLdapPort(636);
        config.setUseSsl(true);
        config.setUseTls(false);
        //char[] password = "cassandra".toCharArray();
        //FileInputStream fis = new FileInputStream("/Users/elecharny/ldap_ssl_truststore");
        //KeyStore ks = KeyStore.getInstance("jks");
        //ks.load(fis, password);
        //TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        //tmf.init(ks);
        config.setTrustManagers(new NoVerificationTrustManager() );
        //config.setName("cn=test");
        config.setName("cn=Manager,dc=example,dc=com");
        //config.setCredentials("pass");
        config.setCredentials("secret");
        config.setLdapApiService( LdapApiServiceFactory.getSingleton());

        ValidatingPoolableLdapConnectionFactory factory = new ValidatingPoolableLdapConnectionFactory(config);
        LdapConnectionPool connectionPool = new LdapConnectionPool(factory);
        connectionPool.setMaxActive(2);
        connectionPool.setMaxIdle(1);
        connectionPool.setMaxWait(0L);
        connectionPool.setTestOnBorrow(false);
        connectionPool.setTestOnReturn(true);
        connectionPool.setTestWhileIdle(false);

        LdapConnection connection = getConnection(connectionPool);
        LdapNetworkConnection cnx = (LdapNetworkConnection)((MonitoringLdapConnection)(connection)).wrapped();

        System.out.println( "Conection connected : " + connection.isConnected() + ", secured : " + cnx.isSecured() );

        EntryCursor cursor = connection.search("ou=users,dc=example,dc=com", "(cn=titi)", SearchScope.SUBTREE);

        cursor.next();

        Dn userDn = cursor.get().getDn();

        connection.setTimeOut(0L);
        connectionPool.releaseConnection(connection);

        connection = connectionPool.getConnection();
        connection.setTimeOut(0L);

        connection.bind(userDn, "titi");

        connection.setTimeOut(0L);
        connectionPool.releaseConnection(connection);
        
        
        System.out.println( "Sleeping for 30 seconds" );

        for ( int i = 1; i <= 30; i++ )
        {
            Thread.sleep(  1000L );
            System.out.print( '.' );
        }

        System.out.println( "\nDone sleeping" );

        connection = connectionPool.getConnection();
        cnx = (LdapNetworkConnection)((MonitoringLdapConnection)(connection)).wrapped();
        
        System.out.println( "Conection connected : " + connection.isConnected() + ", secured : " + cnx.isSecured() );

        cursor = connection.search("ou=users,dc=example,dc=com", "(cn=titi)", SearchScope.SUBTREE);

        cursor.next();

        userDn = cursor.get().getDn();

        connection.setTimeOut(0L);
        connectionPool.releaseConnection(connection);

        connection = connectionPool.getConnection();
        connection.setTimeOut(LdapConnectionConfig.DEFAULT_TIMEOUT);

        connection.bind(userDn, "titi");

        connection.setTimeOut(LdapConnectionConfig.DEFAULT_TIMEOUT);
        connectionPool.releaseConnection(connection);
    }

    private LdapConnection getConnection(LdapConnectionPool pool) throws Exception
    {
        LdapConnection connection = null;

        for (int retry = 0; retry < 2; retry++)
        {
            try
            {
                connection = pool.getConnection();
                connection.setTimeOut(0L);

                connection.bind();

                return connection;
            }
            catch (Throwable ex)
            {
                ex.printStackTrace();
                if (connection != null)
                {
                    pool.invalidateObject(connection);
                }
            }
        }
        return null;
    }
}
