/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *    https://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */
package org.apache.directory.ldap.client.api;


import static org.apache.directory.api.ldap.model.message.ResultCodeEnum.processResponse;

import java.io.File;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.net.ConnectException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.channels.UnresolvedAddressException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PrivilegedExceptionAction;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.ReentrantLock;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.security.auth.Subject;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.util.Oid;
import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.codec.api.BinaryAttributeDetector;
import org.apache.directory.api.ldap.codec.api.DefaultConfigurableBinaryAttributeDetector;
import org.apache.directory.api.ldap.codec.api.ExtendedOperationFactory;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.codec.api.LdapApiServiceFactory;
import org.apache.directory.api.ldap.codec.api.LdapDecoder;
import org.apache.directory.api.ldap.codec.api.LdapMessageContainer;
import org.apache.directory.api.ldap.codec.api.MessageEncoderException;
import org.apache.directory.api.ldap.codec.api.SaslFilter;
import org.apache.directory.api.ldap.codec.api.SchemaBinaryAttributeDetector;
import org.apache.directory.api.ldap.extras.controls.ad.TreeDelete;
import org.apache.directory.api.ldap.extras.controls.ad.TreeDeleteImpl;
import org.apache.directory.api.ldap.extras.extended.startTls.StartTlsRequestImpl;
import org.apache.directory.api.ldap.model.constants.LdapConstants;
import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.directory.api.ldap.model.cursor.Cursor;
import org.apache.directory.api.ldap.model.cursor.CursorException;
import org.apache.directory.api.ldap.model.cursor.EntryCursor;
import org.apache.directory.api.ldap.model.cursor.SearchCursor;
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Modification;
import org.apache.directory.api.ldap.model.entry.ModificationOperation;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapAuthenticationException;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.exception.LdapNoPermissionException;
import org.apache.directory.api.ldap.model.exception.LdapNoSuchObjectException;
import org.apache.directory.api.ldap.model.exception.LdapOperationException;
import org.apache.directory.api.ldap.model.exception.LdapOtherException;
import org.apache.directory.api.ldap.model.exception.LdapTlsHandshakeException;
import org.apache.directory.api.ldap.model.message.AbandonRequest;
import org.apache.directory.api.ldap.model.message.AbandonRequestImpl;
import org.apache.directory.api.ldap.model.message.AddRequest;
import org.apache.directory.api.ldap.model.message.AddRequestImpl;
import org.apache.directory.api.ldap.model.message.AddResponse;
import org.apache.directory.api.ldap.model.message.AliasDerefMode;
import org.apache.directory.api.ldap.model.message.BindRequest;
import org.apache.directory.api.ldap.model.message.BindRequestImpl;
import org.apache.directory.api.ldap.model.message.BindResponse;
import org.apache.directory.api.ldap.model.message.CompareRequest;
import org.apache.directory.api.ldap.model.message.CompareRequestImpl;
import org.apache.directory.api.ldap.model.message.CompareResponse;
import org.apache.directory.api.ldap.model.message.Control;
import org.apache.directory.api.ldap.model.message.DeleteRequest;
import org.apache.directory.api.ldap.model.message.DeleteRequestImpl;
import org.apache.directory.api.ldap.model.message.DeleteResponse;
import org.apache.directory.api.ldap.model.message.ExtendedRequest;
import org.apache.directory.api.ldap.model.message.ExtendedResponse;
import org.apache.directory.api.ldap.model.message.IntermediateResponse;
import org.apache.directory.api.ldap.model.message.LdapResult;
import org.apache.directory.api.ldap.model.message.Message;
import org.apache.directory.api.ldap.model.message.ModifyDnRequest;
import org.apache.directory.api.ldap.model.message.ModifyDnRequestImpl;
import org.apache.directory.api.ldap.model.message.ModifyDnResponse;
import org.apache.directory.api.ldap.model.message.ModifyRequest;
import org.apache.directory.api.ldap.model.message.ModifyRequestImpl;
import org.apache.directory.api.ldap.model.message.ModifyResponse;
import org.apache.directory.api.ldap.model.message.OpaqueExtendedRequest;
import org.apache.directory.api.ldap.model.message.OpaqueExtendedResponse;
import org.apache.directory.api.ldap.model.message.Request;
import org.apache.directory.api.ldap.model.message.Response;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import org.apache.directory.api.ldap.model.message.SearchRequest;
import org.apache.directory.api.ldap.model.message.SearchRequestImpl;
import org.apache.directory.api.ldap.model.message.SearchResultDone;
import org.apache.directory.api.ldap.model.message.SearchResultEntry;
import org.apache.directory.api.ldap.model.message.SearchResultReference;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.api.ldap.model.message.UnbindRequest;
import org.apache.directory.api.ldap.model.message.UnbindRequestImpl;
import org.apache.directory.api.ldap.model.message.controls.ManageDsaITImpl;
import org.apache.directory.api.ldap.model.message.controls.OpaqueControl;
import org.apache.directory.api.ldap.model.message.extended.AddNoDResponse;
import org.apache.directory.api.ldap.model.message.extended.BindNoDResponse;
import org.apache.directory.api.ldap.model.message.extended.CompareNoDResponse;
import org.apache.directory.api.ldap.model.message.extended.DeleteNoDResponse;
import org.apache.directory.api.ldap.model.message.extended.ExtendedNoDResponse;
import org.apache.directory.api.ldap.model.message.extended.ModifyDnNoDResponse;
import org.apache.directory.api.ldap.model.message.extended.ModifyNoDResponse;
import org.apache.directory.api.ldap.model.message.extended.NoticeOfDisconnect;
import org.apache.directory.api.ldap.model.message.extended.SearchNoDResponse;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.name.Rdn;
import org.apache.directory.api.ldap.model.schema.AttributeType;
import org.apache.directory.api.ldap.model.schema.ObjectClass;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.api.ldap.model.schema.parsers.OpenLdapSchemaParser;
import org.apache.directory.api.ldap.model.schema.registries.Registries;
import org.apache.directory.api.ldap.model.schema.registries.SchemaLoader;
import org.apache.directory.api.ldap.schema.manager.impl.DefaultSchemaManager;
import org.apache.directory.api.util.Network;
import org.apache.directory.api.util.StringConstants;
import org.apache.directory.api.util.Strings;
import org.apache.directory.ldap.client.api.callback.SaslCallbackHandler;
import org.apache.directory.ldap.client.api.exception.InvalidConnectionException;
import org.apache.directory.ldap.client.api.exception.LdapConnectionTimeOutException;
import org.apache.directory.ldap.client.api.future.AddFuture;
import org.apache.directory.ldap.client.api.future.BindFuture;
import org.apache.directory.ldap.client.api.future.CompareFuture;
import org.apache.directory.ldap.client.api.future.DeleteFuture;
import org.apache.directory.ldap.client.api.future.ExtendedFuture;
import org.apache.directory.ldap.client.api.future.HandshakeFuture;
import org.apache.directory.ldap.client.api.future.ModifyDnFuture;
import org.apache.directory.ldap.client.api.future.ModifyFuture;
import org.apache.directory.ldap.client.api.future.ResponseFuture;
import org.apache.directory.ldap.client.api.future.SearchFuture;
import org.apache.mina.core.filterchain.IoFilter;
import org.apache.mina.core.filterchain.IoFilterChain;
import org.apache.mina.core.future.CloseFuture;
import org.apache.mina.core.future.ConnectFuture;
import org.apache.mina.core.future.WriteFuture;
import org.apache.mina.core.service.IoConnector;
import org.apache.mina.core.session.IoSession;
import org.apache.mina.filter.FilterEvent;
import org.apache.mina.filter.codec.ProtocolCodecFilter;
import org.apache.mina.filter.codec.ProtocolEncoderException;
import org.apache.mina.filter.ssl.SslEvent;
import org.apache.mina.filter.ssl.SslFilter;
import org.apache.mina.transport.socket.SocketSessionConfig;
import org.apache.mina.transport.socket.nio.NioSocketConnector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * This class is the base for every operations sent or received to and
 * from a LDAP server.
 *
 * A connection instance is necessary to send requests to the server. The connection
 * is valid until either the client closes it, the server closes it or the
 * client does an unbind.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class LdapNetworkConnection extends AbstractLdapConnection implements LdapAsyncConnection
{

    /** logger for reporting errors that might not be handled properly upstream */
    private static final Logger LOG = LoggerFactory.getLogger( LdapNetworkConnection.class );

    /** The timeout used for response we are waiting for */
    private long timeout = LdapConnectionConfig.DEFAULT_TIMEOUT;

    /** configuration object for the connection */
    private LdapConnectionConfig config;
    
    /** The Socket configuration */
    private SocketSessionConfig socketSessionConfig;

    /** The connector open with the remote server */
    private IoConnector connector;

    /** A mutex used to avoid a double close of the connector */
    private ReentrantLock connectorMutex = new ReentrantLock();

    /**
     * The created session, created when we open a connection with
     * the Ldap server.
     */
    private IoSession ioSession;

    /** a map to hold the ResponseFutures for all operations */
    private Map<Integer, ResponseFuture<? extends Response>> futureMap = new ConcurrentHashMap<>();

    /** list of controls supported by the server */
    private List<String> supportedControls;

    /** The ROOT DSE entry */
    private Entry rootDse;

    /** A flag indicating that the BindRequest has been issued and successfully authenticated the user */
    private AtomicBoolean authenticated = new AtomicBoolean( false );

    /** a list of listeners interested in getting notified when the
     *  connection's session gets closed cause of network issues
     */
    private List<ConnectionClosedEventListener> conCloseListeners;

    /** The LDAP codec protocol filter */
    private IoFilter ldapProtocolFilter = new ProtocolCodecFilter( codec.getProtocolCodecFactory() );

    /** The LDAP coded protocol filter key */
    private static final String LDAP_CODEC_FILTER_KEY = "ldapCodec";

    /** The SslFilter key */
    private static final String SSL_FILTER_KEY = "sslFilter";

    /** The SaslFilter key */
    private static final String SASL_FILTER_KEY = "saslFilter";

    /** The exception stored in the session if we've got one */
    private static final String EXCEPTION_KEY = "sessionException";

    /** The krb5 configuration property */
    private static final String KRB5_CONF = "java.security.krb5.conf";
    
    /** A future used to block any action until the handshake is completed */
    private HandshakeFuture handshakeFuture;
    
    /** A future used to wait for a connection to be closed */
    private CompletableFuture<Integer> connectionCloseFuture = new CompletableFuture<>(); 
    
    // ~~~~~~~~~~~~~~~~~ common error messages ~~~~~~~~~~~~~~~~~~~~~~~~~~
    static final String TIME_OUT_ERROR = I18n.err( I18n.ERR_04170_TIMEOUT_OCCURED );

    static final String NO_RESPONSE_ERROR = I18n.err( I18n.ERR_04169_RESPONSE_QUEUE_EMPTIED );
    
   //------------------------- The constructors --------------------------//
    /**
     * Create a new instance of a LdapConnection on localhost,
     * port 389.
     */
    public LdapNetworkConnection()
    {
        this( null, -1, false );
    }


    /**
     *
     * Creates a new instance of LdapConnection with the given connection configuration.
     *
     * @param config the configuration of the LdapConnection
     */
    public LdapNetworkConnection( LdapConnectionConfig config )
    {
        this( config, LdapApiServiceFactory.getSingleton() );
    }


    /**
     * Creates a new LdapNetworkConnection instance
     * 
     * @param config The configuration to use
     * @param ldapApiService The LDAP API Service to use
     */
    public LdapNetworkConnection( LdapConnectionConfig config, LdapApiService ldapApiService )
    {
        super( ldapApiService );
        this.config = config;

        if ( config.getBinaryAttributeDetector() == null )
        {
            config.setBinaryAttributeDetector( new DefaultConfigurableBinaryAttributeDetector() );
        }
        
        this.timeout = config.getTimeout();
    }


    /**
     * Create a new instance of a LdapConnection on localhost,
     * port 389 if the SSL flag is off, or 636 otherwise.
     *
     * @param useSsl A flag to tell if it's a SSL connection or not.
     */
    public LdapNetworkConnection( boolean useSsl )
    {
        this( null, -1, useSsl );
    }


    /**
     * Creates a new LdapNetworkConnection instance
     * 
     * @param useSsl If we are going to create a secure connection or not
     * @param ldapApiService The LDAP API Service to use
     */
    public LdapNetworkConnection( boolean useSsl, LdapApiService ldapApiService )
    {
        this( null, -1, useSsl, ldapApiService );
    }


    /**
     * Create a new instance of a LdapConnection on a given
     * server, using the default port (389).
     *
     * @param server The server we want to be connected to. If null or empty,
     * we will default to LocalHost.
     */
    public LdapNetworkConnection( String server )
    {
        this( server, -1, false );
    }


    /**
     * Creates a new LdapNetworkConnection instance
     * 
     * @param server The server we want to be connected to. If null or empty,
     * we will default to LocalHost.
     * @param ldapApiService The LDAP API Service to use
     */
    public LdapNetworkConnection( String server, LdapApiService ldapApiService )
    {
        this( server, -1, false, ldapApiService );
    }


    /**
     * Create a new instance of a LdapConnection on a given
     * server, using the default port (389) if the SSL flag
     * is off, or 636 otherwise.
     *
     * @param server The server we want to be connected to. If null or empty,
     * we will default to LocalHost.
     * @param useSsl A flag to tell if it's a SSL connection or not.
     */
    public LdapNetworkConnection( String server, boolean useSsl )
    {
        this( server, -1, useSsl );
    }


    /**
     * Creates a new LdapNetworkConnection instance
     * 
     * @param server The server we want to be connected to. If null or empty,
     * we will default to LocalHost.
     * @param useSsl A flag to tell if it's a SSL connection or not.
     * @param ldapApiService The LDAP API Service to use
     */
    public LdapNetworkConnection( String server, boolean useSsl, LdapApiService ldapApiService )
    {
        this( server, -1, useSsl, ldapApiService );
    }


    /**
     * Create a new instance of a LdapConnection on a
     * given server and a given port. We don't use ssl.
     *
     * @param server The server we want to be connected to
     * @param port The port the server is listening to
     */
    public LdapNetworkConnection( String server, int port )
    {
        this( server, port, false );
    }


    /**
     * Create a new instance of a LdapConnection on a
     * given server and a given port. We don't use ssl.
     *
     * @param server The server we want to be connected to. If null or empty,
     * we will default to LocalHost.
     * @param port The port the server is listening on
     * @param ldapApiService The LDAP API Service to use
     */
    public LdapNetworkConnection( String server, int port, LdapApiService ldapApiService )
    {
        this( server, port, false, ldapApiService );
    }


    /**
     * Create a new instance of a LdapConnection on a given
     * server, and a give port. We set the SSL flag accordingly
     * to the last parameter.
     *
     * @param server The server we want to be connected to. If null or empty,
     * we will default to LocalHost.
     * @param port The port the server is listening to
     * @param useSsl A flag to tell if it's a SSL connection or not.
     */
    public LdapNetworkConnection( String server, int port, boolean useSsl )
    {
        this( buildConfig( server, port, useSsl ) );
    }
    
    
    /**
     * Create a new instance of a LdapConnection on a given
     * server, and a give port. This SSL connection will use the provided
     * TrustManagers
     *
     * @param server The server we want to be connected to. If null or empty,
     * we will default to LocalHost.
     * @param port The port the server is listening to
     * @param trustManagers The TrustManager to use
     */
    public LdapNetworkConnection( String server, int port, TrustManager... trustManagers )
    {
        this( buildConfig( server, port, true ) );
        
        config.setTrustManagers( trustManagers );
    }


    /**
     * Create a new instance of a LdapConnection on a
     * given server and a given port. We don't use ssl.
     *
     * @param server The server we want to be connected to. If null or empty,
     * we will default to LocalHost.
     * @param port The port the server is listening on
     * @param useSsl A flag to tell if it's a SSL connection or not.
     * @param ldapApiService The LDAP API Service to use
     */
    public LdapNetworkConnection( String server, int port, boolean useSsl, LdapApiService ldapApiService )
    {
        this( buildConfig( server, port, useSsl ), ldapApiService );
    }


    private static LdapConnectionConfig buildConfig( String server, int port, boolean useSsl )
    {
        LdapConnectionConfig config = new LdapConnectionConfig();
        config.setUseSsl( useSsl );

        if ( port != -1 )
        {
            config.setLdapPort( port );
        }
        else
        {
            if ( useSsl )
            {
                config.setLdapPort( config.getDefaultLdapsPort() );
            }
            else
            {
                config.setLdapPort( config.getDefaultLdapPort() );
            }
        }

        // Default to localhost if null
        if ( Strings.isEmpty( server ) )
        {
            config.setLdapHost( Network.LOOPBACK_HOSTNAME );
            
        }
        else
        {
            config.setLdapHost( server );
        }

        config.setBinaryAttributeDetector( new DefaultConfigurableBinaryAttributeDetector() );

        return config;
    }


    /**
     * Create the connector
     * 
     * @throws LdapException If the connector can't be created
     */
    private void createConnector() throws LdapException
    {
        // Use only one thread inside the connector
        connector = new NioSocketConnector( 1 );
        
        if ( socketSessionConfig != null )
        {
            ( ( SocketSessionConfig ) connector.getSessionConfig() ).setAll( socketSessionConfig );
        }
        else
        {
            ( ( SocketSessionConfig ) connector.getSessionConfig() ).setReuseAddress( true );
        }

        // Add the codec to the chain
        connector.getFilterChain().addLast( LDAP_CODEC_FILTER_KEY, ldapProtocolFilter );

        // If we use SSL, we have to add the SslFilter to the chain
        if ( config.isUseSsl() )
        {
            addSslFilter();
        }

        // Inject the protocolHandler
        connector.setHandler( this );
    }


    //--------------------------- Helper methods ---------------------------//
    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isConnected()
    {
        return ( ioSession != null ) && ioSession.isConnected() && !ioSession.isClosing();
        
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isAuthenticated()
    {
        return isConnected() && authenticated.get();
    }


    /**
     * Tells if the connection is using a secured channel
     * 
     * @return <tt>true</tt> if the session is using a secured channel
     */
    public boolean isSecured()
    {
        return isConnected() && ioSession.isSecured();
    }

    
    /**
     * {@inheritDoc}
     */
    @Override
    public Throwable exceptionCaught()
    {
        return ( Throwable ) ioSession.getAttribute( EXCEPTION_KEY );
    }
    
    
    /**
     * Check that a session is valid, ie we can send requests to the
     * server
     *
     * @throws InvalidConnectionException If the session is not valid
     */
    private void checkSession() throws InvalidConnectionException
    {
        if ( ioSession == null )
        {
            throw new InvalidConnectionException( I18n.err( I18n.ERR_04104_NULL_CONNECTION_CANNOT_CONNECT ) );
        }

        if ( !isConnected() )
        {
            throw new InvalidConnectionException( I18n.err( I18n.ERR_04108_INVALID_CONNECTION ) );
        }
    }


    private void addToFutureMap( int messageId, ResponseFuture<? extends Response> future )
    {
        if ( LOG.isDebugEnabled() )
        {
            LOG.debug( I18n.msg( I18n.MSG_04106_ADDING, messageId, future.getClass().getName() ) );
        }
        
        futureMap.put( messageId, future );
    }


    private ResponseFuture<? extends Response> getFromFutureMap( int messageId )
    {
        ResponseFuture<? extends Response> future = futureMap.remove( messageId );

        if ( LOG.isDebugEnabled() && ( future != null ) )
        {
            LOG.debug( I18n.msg( I18n.MSG_04126_REMOVING, messageId, future.getClass().getName() ) );
        }

        return future;
    }


    private ResponseFuture<? extends Response> peekFromFutureMap( int messageId )
    {
        ResponseFuture<? extends Response> future = futureMap.get( messageId );

        // future can be null if there was a abandon operation on that messageId
        if ( LOG.isDebugEnabled() && ( future != null ) )
        {
            LOG.debug( I18n.msg( I18n.MSG_04119_GETTING, messageId, future.getClass().getName() ) );
        }

        return future;
    }


    /**
     * Get the largest timeout from the search time limit and the connection
     * timeout.
     * 
     * @param connectionTimoutInMS Connection timeout
     * @param searchTimeLimitInSeconds Search timeout
     * @return The largest timeout
     */
    public long getTimeout( long connectionTimoutInMS, int searchTimeLimitInSeconds )
    {
        if ( searchTimeLimitInSeconds < 0 )
        {
            return connectionTimoutInMS;
        }
        else if ( searchTimeLimitInSeconds == 0 )
        {
            if ( config.getTimeout() == 0 )
            {
                return Long.MAX_VALUE;
            }
            else
            {
                return config.getTimeout();
            }
        }
        else
        {
            long searchTimeLimitInMS = searchTimeLimitInSeconds * 1000L;
            return Math.max( searchTimeLimitInMS, connectionTimoutInMS );
        }
    }

    
    /**
     * Process the connect. 
     * 
     * @exception LdapException If we weren't able to connect
     * @return A Future that can be used to check the status of the connection
     */
    public ConnectFuture tryConnect() throws LdapException
    {
        // Build the connection address
        SocketAddress address = new InetSocketAddress( config.getLdapHost(), config.getLdapPort() );
        ConnectFuture connectionFuture = connector.connect( address );
        boolean result = false;

        // Wait until it's established
        try
        {
            result = connectionFuture.await( timeout );
        }
        catch ( InterruptedException e )
        {
            connector.dispose();
            connector = null;

            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.msg( I18n.MSG_04120_INTERRUPTED_WAITING_FOR_CONNECTION, 
                    config.getLdapHost(),
                    config.getLdapPort() ), e );
            }
            
            throw new LdapOtherException( e.getMessage(), e );
        }

        if ( !result )
        {
            // It may be an exception, or a timeout
            Throwable connectionException = connectionFuture.getException();

            if ( ( connector != null ) && !connector.isDisposing() && !connector.isDisposed() )
            { 
                connector.dispose();
            }

            connector = null;

            if ( connectionException == null )
            {
                // This was a timeout
                String message = I18n.msg( I18n.MSG_04177_CONNECTION_TIMEOUT, timeout );
                
                if ( LOG.isDebugEnabled() )
                {
                    LOG.debug( message );
                }
                
                throw new LdapConnectionTimeOutException( message );
            }
            else
            {
                if ( LOG.isDebugEnabled() )
                {
                    if ( ( connectionException instanceof ConnectException )
                        || ( connectionException instanceof UnresolvedAddressException ) )
                    {
                        // No need to wait
                        // We know that there was a permanent error such as "connection refused".
                        LOG.debug( I18n.msg( I18n.MSG_04144_CONNECTION_ERROR, connectionFuture.getException().getMessage() ) );
                    }
    
                    LOG.debug( I18n.msg( I18n.MSG_04120_INTERRUPTED_WAITING_FOR_CONNECTION, 
                        config.getLdapHost(),
                        config.getLdapPort() ), connectionException );
                }
                
                throw new LdapOtherException( connectionException.getMessage(), connectionException );
            }
        }
        
        return connectionFuture;
    }
    
    
    /**
     * Close the connection and generate the appropriate exception
     * 
     * @exception LdapException If we weren't able to close the connection
     */
    private void close( ConnectFuture connectionFuture ) throws LdapException
    {
        // disposing connector if not connected
        close();

        Throwable e = connectionFuture.getException();

        if ( e != null )
        {
            // Special case for UnresolvedAddressException
            // (most of the time no message is associated with this exception)
            if ( ( e instanceof UnresolvedAddressException ) && ( e.getMessage() == null ) )
            {
                throw new InvalidConnectionException( I18n.err( I18n.ERR_04121_CANNOT_RESOLVE_HOSTNAME, config.getLdapHost() ), e );
            }

            // Default case
            throw new InvalidConnectionException( I18n.err( I18n.ERR_04110_CANNOT_CONNECT_TO_SERVER, e.getMessage() ), e );
        }

        // We didn't received anything : this is an error
        if ( LOG.isErrorEnabled() )
        {
            LOG.error( I18n.err( I18n.ERR_04112_OP_FAILED_TIMEOUT, "Connect" ) );
        }

        throw new LdapException( TIME_OUT_ERROR );
    }
    
    
    /**
     * Verify that the connection has been secured, otherwise throw a meaningful exception
     * 
     * @exception LdapException If we weren't able to check that the connection is secured
     */
    private void checkSecured( ConnectFuture connectionFuture ) throws LdapException
    {
        try
        {
            boolean isSecured = handshakeFuture.get( timeout, TimeUnit.MILLISECONDS );

            if ( !isSecured )
            {
                // check for a specific cause
                Throwable cause = connectionFuture.getException();
                
                if ( cause == null && connectionFuture.getSession() != null )
                {
                    cause = ( Throwable ) connectionFuture.getSession().getAttribute( EXCEPTION_KEY );
                }
                
                // Cancel the latch
                connectionCloseFuture.complete( 0 );

                // if there is no cause assume timeout
                if ( cause == null )
                {
                    throw new LdapException( TIME_OUT_ERROR );
                }

                throw new LdapTlsHandshakeException( I18n.err( I18n.ERR_04120_TLS_HANDSHAKE_ERROR ), cause );
            }
        }
        catch ( Exception e )
        {
            if ( e instanceof LdapException )
            {
                throw ( LdapException ) e;
            }

            String msg = I18n.err( I18n.ERR_04122_SSL_CONTEXT_INIT_FAILURE );
            LOG.error( msg, e );
            throw new LdapException( msg, e );
        }
    }
    
    
    /**
     * Set a listener associated to the closeFuture
     * 
     * @param connectionFuture A Future for which we want to set a listener
     */
    private void setCloseListener( ConnectFuture connectionFuture )
    {
        // Get the close future for this session
        CloseFuture closeFuture = connectionFuture.getSession().getCloseFuture();
        
        closeFuture.addListener( future -> 
        {
            // Process all the waiting operations and cancel them
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.msg( I18n.MSG_04137_NOD_RECEIVED ) );
            }

            for ( ResponseFuture<?> responseFuture : futureMap.values() )
            {
                if ( LOG.isDebugEnabled() )
                {
                    LOG.debug( I18n.msg( I18n.MSG_04137_NOD_RECEIVED ) );
                }

                responseFuture.cancel();

                try
                {
                    if ( responseFuture instanceof AddFuture )
                    {
                        ( ( AddFuture ) responseFuture ).set( AddNoDResponse.PROTOCOLERROR );
                    }
                    else if ( responseFuture instanceof BindFuture )
                    {
                        ( ( BindFuture ) responseFuture ).set( BindNoDResponse.PROTOCOLERROR );
                    }
                    else if ( responseFuture instanceof CompareFuture )
                    {
                        ( ( CompareFuture ) responseFuture ).set( CompareNoDResponse.PROTOCOLERROR );
                    }
                    else if ( responseFuture instanceof DeleteFuture )
                    {
                        ( ( DeleteFuture ) responseFuture ).set( DeleteNoDResponse.PROTOCOLERROR );
                    }
                    else if ( responseFuture instanceof ExtendedFuture )
                    {
                        ( ( ExtendedFuture ) responseFuture ).set( ExtendedNoDResponse.PROTOCOLERROR );
                    }
                    else if ( responseFuture instanceof ModifyFuture )
                    {
                        ( ( ModifyFuture ) responseFuture ).set( ModifyNoDResponse.PROTOCOLERROR );
                    }
                    else if ( responseFuture instanceof ModifyDnFuture )
                    {
                        ( ( ModifyDnFuture ) responseFuture ).set( ModifyDnNoDResponse.PROTOCOLERROR );
                    }
                    else if ( responseFuture instanceof SearchFuture )
                    {
                        ( ( SearchFuture ) responseFuture ).set( SearchNoDResponse.PROTOCOLERROR );
                    }
                }
                catch ( InterruptedException e )
                {
                    LOG.error( I18n.err( I18n.ERR_04113_ERROR_PROCESSING_NOD, responseFuture ), e );
                }

                futureMap.remove( messageId.get() );
            }

            futureMap.clear();
        } );
    }
    
    
    /**
     * Set the BinaryDetector instance in the session
     */
    private void setBinaryDetector()
    {
        @SuppressWarnings("unchecked")
        LdapMessageContainer<? extends Message> container =
            ( LdapMessageContainer<? extends Message> ) ioSession
                .getAttribute( LdapDecoder.MESSAGE_CONTAINER_ATTR );

        if ( container != null )
        {
            if ( ( schemaManager != null ) && !( container.getBinaryAttributeDetector() instanceof SchemaBinaryAttributeDetector ) )
            {
                container.setBinaryAttributeDetector( new SchemaBinaryAttributeDetector( schemaManager ) );
            }
        }
        else
        {
            BinaryAttributeDetector atDetector = new DefaultConfigurableBinaryAttributeDetector();

            if ( schemaManager != null )
            {
                atDetector = new SchemaBinaryAttributeDetector( schemaManager );
            }

            ioSession.setAttribute( LdapDecoder.MESSAGE_CONTAINER_ATTR,
                new LdapMessageContainer<Message>( codec, atDetector ) );
        }
    }
    

    //-------------------------- The methods ---------------------------//
    /**
     * {@inheritDoc}
     */
    @Override
    public boolean connect() throws LdapException
    {
        if ( isConnected() )
        {
            // No need to connect if we already have a connected session
            return true;
        }
        
        try
        {
            // Create the connector if needed
            if ( connector == null )
            {
                createConnector();
            }
    
            // And create the connection future
            ConnectFuture connectionFuture = tryConnect();
    
            // Check if we are good to go
            if ( !connectionFuture.isConnected() )
            {
                // Release the latch
                connectionCloseFuture.cancel( true );
                
                close( connectionFuture );
            }
    
            // Check if we are secured if requested
            if ( config.isUseSsl() )
            {
                checkSecured( connectionFuture );
            }
    
            // Add a listener to close the session in the session.
            setCloseListener( connectionFuture );
    
            // Get back the session
            ioSession = connectionFuture.getSession();
    
            // Store the container into the session if we don't have one
            setBinaryDetector();
    
            // Initialize the MessageId
            messageId.set( 0 );
            
            connectionCloseFuture = new CompletableFuture<>();
    
            // And return
            return true;
        }
        catch ( Exception e )
        {
            if ( ( connector != null ) && !connector.isDisposing() && !connector.isDisposed() ) 
            {
                connector.dispose();
                connector = null;
            }

            throw e;
        }
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void close()
    {
        // Close the session
        if ( isConnected() )
        {
            ioSession.closeNow();
        }

        try
        {
            if ( ( ioSession != null ) && ioSession.isConnected() )
            { 
                connectionCloseFuture.get( timeout, TimeUnit.MILLISECONDS );
            }
        }
        catch ( TimeoutException | ExecutionException | InterruptedException e )
        {
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.msg( I18n.MSH_04178_CLOSE_LATCH_ABORTED ) );
            }
        }
    }


    //------------------------ The LDAP operations ------------------------//
    // Add operations                                                      //
    //---------------------------------------------------------------------//
    /**
     * {@inheritDoc}
     */
    @Override
    public void add( Entry entry ) throws LdapException
    {
        if ( entry == null )
        {
            String msg = I18n.err( I18n.ERR_04123_CANNOT_ADD_EMPTY_ENTRY );
            
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( msg );
            }
            
            throw new IllegalArgumentException( msg );
        }

        AddRequest addRequest = new AddRequestImpl();
        addRequest.setEntry( entry );

        AddResponse addResponse = add( addRequest );

        processResponse( addResponse );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public AddFuture addAsync( Entry entry ) throws LdapException
    {
        if ( entry == null )
        {
            String msg = I18n.err( I18n.ERR_04125_CANNOT_ADD_NULL_ENTRY );
            
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( msg );
            }
            
            throw new IllegalArgumentException( msg );
        }

        AddRequest addRequest = new AddRequestImpl();
        addRequest.setEntry( entry );

        return addAsync( addRequest );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public AddResponse add( AddRequest addRequest ) throws LdapException
    {
        if ( addRequest == null )
        {
            String msg = I18n.err( I18n.ERR_04124_CANNOT_PROCESS_NULL_ADD_REQUEST );

            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( msg );
            }
            
            throw new IllegalArgumentException( msg );
        }

        if ( addRequest.getEntry() == null )
        {
            String msg = I18n.err( I18n.ERR_04125_CANNOT_ADD_NULL_ENTRY );

            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( msg );
            }
            
            throw new IllegalArgumentException( msg );
        }

        AddFuture addFuture = addAsync( addRequest );

        // Get the result from the future
        try
        {
            // Read the response, waiting for it if not available immediately
            // Get the response, blocking
            AddResponse addResponse = addFuture.get( timeout, TimeUnit.MILLISECONDS );

            if ( addResponse == null )
            {
                // We didn't received anything : this is an error
                if ( LOG.isErrorEnabled() )
                {
                    LOG.error( I18n.err( I18n.ERR_04112_OP_FAILED_TIMEOUT, "Add" ) );
                }
                
                throw new LdapException( TIME_OUT_ERROR );
            }

            if ( addResponse.getLdapResult().getResultCode() == ResultCodeEnum.SUCCESS )
            {
                // Everything is fine, return the response
                if ( LOG.isDebugEnabled() )
                { 
                    LOG.debug( I18n.msg( I18n.MSG_04108_ADD_SUCCESSFUL, addResponse ) );
                }
            }
            else
            {
                // We have had an error
                if ( LOG.isDebugEnabled() )
                { 
                    LOG.debug( I18n.msg( I18n.MSG_04107_ADD_FAILED, addResponse ) );
                }
            }

            return addResponse;
        }
        catch ( Exception ie )
        {
            // Catch all other exceptions
            LOG.error( NO_RESPONSE_ERROR, ie );

            // Send an abandon request
            if ( !addFuture.isCancelled() )
            {
                abandon( addRequest.getMessageId() );
            }

            throw new LdapException( NO_RESPONSE_ERROR, ie );
        }
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public AddFuture addAsync( AddRequest addRequest ) throws LdapException
    {
        if ( addRequest == null )
        {
            String msg = I18n.err( I18n.ERR_04124_CANNOT_PROCESS_NULL_ADD_REQUEST );

            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( msg );
            }
            
            throw new IllegalArgumentException( msg );
        }

        if ( addRequest.getEntry() == null )
        {
            String msg = I18n.err( I18n.ERR_04125_CANNOT_ADD_NULL_ENTRY );

            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( msg );
            }
            
            throw new IllegalArgumentException( msg );
        }

        // try to connect, if we aren't already connected.
        connect();

        checkSession();

        int newId = messageId.incrementAndGet();

        addRequest.setMessageId( newId );
        AddFuture addFuture = new AddFuture( this, newId );
        addToFutureMap( newId, addFuture );

        // Send the request to the server
        writeRequest( addRequest );

        // Ok, done return the future
        return addFuture;
    }


    //------------------------ The LDAP operations ------------------------//

    /**
     * {@inheritDoc}
     */
    @Override
    public void abandon( int messageId )
    {
        if ( messageId < 0 )
        {
            String msg = I18n.err( I18n.ERR_04126_CANNOT_ABANDON_NEG_MSG_ID );

            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( msg );
            }
            
            throw new IllegalArgumentException( msg );
        }

        AbandonRequest abandonRequest = new AbandonRequestImpl();
        abandonRequest.setAbandoned( messageId );

        abandonInternal( abandonRequest );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void abandon( AbandonRequest abandonRequest )
    {
        if ( abandonRequest == null )
        {
            String msg = I18n.err( I18n.ERR_04127_CANNOT_PROCESS_NULL_ABANDON_REQ );

            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( msg );
            }
            
            throw new IllegalArgumentException( msg );
        }

        abandonInternal( abandonRequest );
    }


    /**
     * Internal AbandonRequest handling
     * 
     * @param abandonRequest The request to abandon
     */
    private void abandonInternal( AbandonRequest abandonRequest )
    {
        if ( LOG.isDebugEnabled() )
        {
            LOG.debug( I18n.msg( I18n.MSG_04104_SENDING_REQUEST, abandonRequest ) );
        }

        int newId = messageId.incrementAndGet();
        abandonRequest.setMessageId( newId );

        // Send the request to the server
        ioSession.write( abandonRequest );

        // remove the associated listener if any
        int abandonId = abandonRequest.getAbandoned();

        ResponseFuture<? extends Response> rf = getFromFutureMap( abandonId );

        // if the listener is not null, this is a async operation and no need to
        // send cancel signal on future, sending so will leave a dangling poision object in the corresponding queue
        // this is a sync operation send cancel signal to the corresponding ResponseFuture
        if ( rf != null )
        {
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.msg( I18n.MSG_04141_SENDING_CANCEL ) );
            }
            
            rf.cancel( true );
        }
        else
        {
            // this shouldn't happen
            if ( LOG.isWarnEnabled() )
            {
                LOG.warn( I18n.msg( I18n.MSG_04165_NO_FUTURE_ASSOCIATED_TO_MSG_ID_COMPLETED, abandonId ) );
            }
        }
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void bind() throws LdapException
    {
        if ( LOG.isDebugEnabled() )
        {
            LOG.debug( I18n.msg(  I18n.MSG_04112_BIND ) );
        }

        // Create the BindRequest
        BindRequest bindRequest = createBindRequest( config.getName(), Strings.getBytesUtf8( config.getCredentials() ) );

        BindResponse bindResponse = bind( bindRequest );

        processResponse( bindResponse );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void anonymousBind() throws LdapException
    {
        if ( LOG.isDebugEnabled() )
        { 
            LOG.debug( I18n.msg( I18n.MSG_04109_ANONYMOUS_BIND ) );
        }

        // Create the BindRequest
        BindRequest bindRequest = createBindRequest( StringConstants.EMPTY, Strings.EMPTY_BYTES );

        BindResponse bindResponse = bind( bindRequest );

        processResponse( bindResponse );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public BindFuture bindAsync() throws LdapException
    {
        if ( LOG.isDebugEnabled() )
        {
            LOG.debug( I18n.msg( I18n.MSG_04111_ASYNC_BIND ) );
        }

        // Create the BindRequest
        BindRequest bindRequest = createBindRequest( config.getName(), Strings.getBytesUtf8( config.getCredentials() ) );

        return bindAsync( bindRequest );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public BindFuture anonymousBindAsync() throws LdapException
    {
        if ( LOG.isDebugEnabled() )
        { 
            LOG.debug( I18n.msg( I18n.MSG_04110_ANONYMOUS_ASYNC_BIND ) );
        }

        // Create the BindRequest
        BindRequest bindRequest = createBindRequest( StringConstants.EMPTY, Strings.EMPTY_BYTES );

        return bindAsync( bindRequest );
    }


    /**
     * Asynchronous unauthenticated authentication bind
     *
     * @param name The name we use to authenticate the user. It must be a
     * valid Dn
     * @return The BindResponse LdapResponse
     * @throws LdapException if some error occurred
     */
    public BindFuture bindAsync( String name ) throws LdapException
    {
        if ( LOG.isDebugEnabled() )
        {
            LOG.debug( I18n.msg( I18n.MSG_04102_BIND_REQUEST, name ) );
        }

        // Create the BindRequest
        BindRequest bindRequest = createBindRequest( name, Strings.EMPTY_BYTES );

        return bindAsync( bindRequest );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public BindFuture bindAsync( String name, String credentials ) throws LdapException
    {
        if ( LOG.isDebugEnabled() )
        {
            LOG.debug( I18n.msg( I18n.MSG_04102_BIND_REQUEST, name ) );
        }

        // The password must not be empty or null
        if ( Strings.isEmpty( credentials ) && Strings.isNotEmpty( name ) )
        {
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.msg( I18n.MSG_04105_MISSING_PASSWORD ) );
            }
            
            throw new LdapAuthenticationException( I18n.msg( I18n.MSG_04105_MISSING_PASSWORD ) );
        }

        // Create the BindRequest
        BindRequest bindRequest = createBindRequest( name, Strings.getBytesUtf8( credentials ) );

        return bindAsync( bindRequest );
    }


    /**
     * Asynchronous unauthenticated authentication Bind on a server.
     *
     * @param name The name we use to authenticate the user. It must be a
     * valid Dn
     * @return The BindResponse LdapResponse
     * @throws LdapException if some error occurred
     */
    public BindFuture bindAsync( Dn name ) throws LdapException
    {
        if ( LOG.isDebugEnabled() )
        {
            LOG.debug( I18n.msg( I18n.MSG_04102_BIND_REQUEST, name ) );
        }

        // Create the BindRequest
        BindRequest bindRequest = createBindRequest( name, Strings.EMPTY_BYTES );

        return bindAsync( bindRequest );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public BindFuture bindAsync( Dn name, String credentials ) throws LdapException
    {
        if ( LOG.isDebugEnabled() )
        {
            LOG.debug( I18n.msg( I18n.MSG_04102_BIND_REQUEST, name ) );
        }

        // The password must not be empty or null
        if ( Strings.isEmpty( credentials ) && ( !Dn.EMPTY_DN.equals( name ) ) )
        {
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.msg( I18n.MSG_04105_MISSING_PASSWORD ) );
            }
            
            throw new LdapAuthenticationException( I18n.msg( I18n.MSG_04105_MISSING_PASSWORD ) );
        }

        // Create the BindRequest
        BindRequest bindRequest = createBindRequest( name, Strings.getBytesUtf8( credentials ) );

        return bindAsync( bindRequest );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public BindResponse bind( BindRequest bindRequest ) throws LdapException
    {
        if ( bindRequest == null )
        {
            String msg = I18n.err( I18n.ERR_04128_CANNOT_PROCESS_NULL_BIND_REQ );

            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( msg );
            }
            
            throw new IllegalArgumentException( msg );
        }

        BindFuture bindFuture = bindAsync( bindRequest );

        // Get the result from the future
        try
        {
            // Read the response, waiting for it if not available immediately
            // Get the response, blocking
            BindResponse bindResponse = bindFuture.get( timeout, TimeUnit.MILLISECONDS );

            if ( bindResponse == null )
            {
                // We didn't received anything : this is an error
                if ( LOG.isErrorEnabled() )
                { 
                    LOG.error( I18n.err( I18n.ERR_04112_OP_FAILED_TIMEOUT, "Bind" ) );
                }
                
                throw new LdapException( TIME_OUT_ERROR );
            }

            if ( bindResponse.getLdapResult().getResultCode() == ResultCodeEnum.SUCCESS )
            {
                authenticated.set( true );

                // Everything is fine, return the response
                if ( LOG.isDebugEnabled() )
                { 
                    LOG.debug( I18n.msg( I18n.MSG_04101_BIND_SUCCESSFUL, bindResponse ) );
                }
            }
            else
            {
                // We have had an error
                if ( LOG.isDebugEnabled() )
                { 
                    LOG.debug( I18n.msg( I18n.MSG_04100_BIND_FAIL, bindResponse ) );
                }
            }

            return bindResponse;
        }
        catch ( Exception ie )
        {
            // Catch all other exceptions
            LOG.error( NO_RESPONSE_ERROR, ie );
            
            throw new LdapException( NO_RESPONSE_ERROR, ie );
        }
    }


    /**
     * Create a Simple BindRequest ready to be sent.
     * 
     * @param name The Bind name
     * @param credentials The Bind credentials
     * @return The created BindRequest instance
     */
    private BindRequest createBindRequest( String name, byte[] credentials )
    {
        return createBindRequest( name, credentials, null, ( Control[] ) null );
    }


    /**
     * Create a Simple BindRequest ready to be sent.
     * 
     * @param name The Bind name
     * @param credentials The Bind credentials
     * @return The created BindRequest instance
     */
    private BindRequest createBindRequest( Dn name, byte[] credentials )
    {
        return createBindRequest( name.getName(), credentials, null, ( Control[] ) null );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public BindFuture bindAsync( BindRequest bindRequest ) throws LdapException
    {
        if ( bindRequest == null )
        {
            String msg = I18n.err( I18n.ERR_04128_CANNOT_PROCESS_NULL_BIND_REQ );

            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( msg );
            }
            
            throw new IllegalArgumentException( msg );
        }

        // First switch to anonymous state
        authenticated.set( false );

        // try to connect, if we aren't already connected.
        connect();

        // establish TLS layer if TLS is enabled and SSL is NOT
        if ( config.isUseTls() && !config.isUseSsl() )
        {
            startTls();
        }

        // If the session has not been establish, or is closed, we get out immediately
        checkSession();

        // Update the messageId
        int newId = messageId.incrementAndGet();
        bindRequest.setMessageId( newId );

        if ( LOG.isDebugEnabled() )
        {
            LOG.debug( I18n.msg( I18n.MSG_04104_SENDING_REQUEST, bindRequest ) );
        }

        // Create a future for this Bind operation
        BindFuture bindFuture = new BindFuture( this, newId );

        addToFutureMap( newId, bindFuture );

        writeRequest( bindRequest );

        // Ok, done return the future
        return bindFuture;
    }


    /**
     * SASL PLAIN Bind on a server.
     *
     * @param authcid The Authentication identity
     * @param credentials The password. It can't be null
     * @return The BindResponse LdapResponse
     * @throws LdapException if some error occurred
     */
    public BindResponse bindSaslPlain( String authcid, String credentials ) throws LdapException
    {
        return bindSaslPlain( null, authcid, credentials );
    }


    /**
     * SASL PLAIN Bind on a server.
     *
     * @param authzid The Authorization identity
     * @param authcid The Authentication identity
     * @param credentials The password. It can't be null
     * @return The BindResponse LdapResponse
     * @throws LdapException if some error occurred
     */
    public BindResponse bindSaslPlain( String authzid, String authcid, String credentials ) throws LdapException
    {
        if ( LOG.isDebugEnabled() )
        {
            LOG.debug( I18n.msg( I18n.MSG_04127_SASL_PLAIN_BIND ) );
        }

        // Create the BindRequest
        SaslPlainRequest saslRequest = new SaslPlainRequest();
        saslRequest.setAuthorizationId( authzid );
        saslRequest.setUsername( authcid );
        saslRequest.setCredentials( credentials );

        BindFuture bindFuture = bindAsync( saslRequest );

        // Get the result from the future
        try
        {
            // Read the response, waiting for it if not available immediately
            // Get the response, blocking
            BindResponse bindResponse = bindFuture.get( timeout, TimeUnit.MILLISECONDS );

            if ( bindResponse == null )
            {
                // We didn't received anything : this is an error
                if ( LOG.isErrorEnabled() )
                { 
                    LOG.error( I18n.err( I18n.ERR_04112_OP_FAILED_TIMEOUT, "Bind" ) );
                }
                
                throw new LdapException( TIME_OUT_ERROR );
            }

            if ( bindResponse.getLdapResult().getResultCode() == ResultCodeEnum.SUCCESS )
            {
                authenticated.set( true );

                // Everything is fine, return the response
                if ( LOG.isDebugEnabled() )
                { 
                    LOG.debug( I18n.msg( I18n.MSG_04101_BIND_SUCCESSFUL, bindResponse ) );
                }
            }
            else
            {
                // We have had an error
                if ( LOG.isDebugEnabled() )
                { 
                    LOG.debug( I18n.msg( I18n.MSG_04100_BIND_FAIL, bindResponse ) );
                }
            }

            return bindResponse;
        }
        catch ( Exception ie )
        {
            // Catch all other exceptions
            LOG.error( NO_RESPONSE_ERROR, ie );

            throw new LdapException( NO_RESPONSE_ERROR, ie );
        }
    }


    /**
     * Bind to the server using a SaslRequest object.
     *
     * @param request The SaslRequest POJO containing all the needed parameters
     * @return A LdapResponse containing the result
     * @throws LdapException if some error occurred
     */
    public BindResponse bind( SaslRequest request ) throws LdapException
    {
        if ( request == null )
        {
            String msg = I18n.msg( I18n.MSG_04103_NULL_REQUEST );

            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( msg );
            }
            
            throw new IllegalArgumentException( msg );
        }

        BindFuture bindFuture = bindAsync( request );

        // Get the result from the future
        try
        {
            // Read the response, waiting for it if not available immediately
            // Get the response, blocking
            BindResponse bindResponse = bindFuture.get( timeout, TimeUnit.MILLISECONDS );

            if ( bindResponse == null )
            {
                // We didn't received anything : this is an error
                if ( LOG.isErrorEnabled() )
                { 
                    LOG.error( I18n.err( I18n.ERR_04112_OP_FAILED_TIMEOUT, "Bind" ) );
                }
                
                throw new LdapException( TIME_OUT_ERROR );
            }

            if ( bindResponse.getLdapResult().getResultCode() == ResultCodeEnum.SUCCESS )
            {
                authenticated.set( true );

                // Everything is fine, return the response
                if ( LOG.isDebugEnabled() )
                { 
                    LOG.debug( I18n.msg( I18n.MSG_04101_BIND_SUCCESSFUL, bindResponse ) );
                }
            }
            else
            {
                // We have had an error
                if ( LOG.isDebugEnabled() )
                { 
                    LOG.debug( I18n.msg( I18n.MSG_04100_BIND_FAIL, bindResponse ) );
                }
            }

            return bindResponse;
        }
        catch ( Exception ie )
        {
            // Catch all other exceptions
            LOG.error( NO_RESPONSE_ERROR, ie );

            throw new LdapException( NO_RESPONSE_ERROR, ie );
        }
    }


    /**
     * Bind to the server using the SASL CRAM-MD5 mechanism.
     *
     * @param userName The user name
     * @param credentials The user credentials
     * @return  A LdapResponse containing the result
     * @throws LdapException if some error occurred
     */
    public BindResponse bindSaslCramMd5( String userName, String credentials ) throws LdapException
    {
        SaslCramMd5Request request = new SaslCramMd5Request();
        request.setUsername( userName );
        request.setCredentials( "secret" );

        return bind( request );
    }


    /**
     * Bind to the server using the SASL DIGEST-MD5 mechanism.
     *
     * @param userName The user name
     * @param credentials The user credentials
     * @return  A LdapResponse containing the result
     * @throws LdapException if some error occurred
     */
    public BindResponse bindSaslDigestMd5( String userName, String credentials ) throws LdapException
    {
        SaslDigestMd5Request request = new SaslDigestMd5Request();
        request.setUsername( userName );
        request.setCredentials( "secret" );

        return bind( request );
    }


    /**
     * Bind to the server using a CramMd5Request object.
     *
     * @param request The CramMd5Request POJO containing all the needed parameters
     * @return A LdapResponse containing the result
     * @throws LdapException if some error occurred
     */
    public BindResponse bind( SaslCramMd5Request request ) throws LdapException
    {
        if ( request == null )
        {
            String msg = I18n.msg( I18n.MSG_04103_NULL_REQUEST );

            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( msg );
            }
            
            throw new IllegalArgumentException( msg );
        }

        BindFuture bindFuture = bindAsync( request );

        // Get the result from the future
        try
        {
            // Read the response, waiting for it if not available immediately
            // Get the response, blocking
            BindResponse bindResponse = bindFuture.get( timeout, TimeUnit.MILLISECONDS );

            if ( bindResponse == null )
            {
                // We didn't received anything : this is an error
                if ( LOG.isErrorEnabled() )
                { 
                    LOG.error( I18n.err( I18n.ERR_04112_OP_FAILED_TIMEOUT, "Bind" ) );
                }
                
                throw new LdapException( TIME_OUT_ERROR );
            }

            if ( bindResponse.getLdapResult().getResultCode() == ResultCodeEnum.SUCCESS )
            {
                authenticated.set( true );

                // Everything is fine, return the response
                if ( LOG.isDebugEnabled() )
                { 
                    LOG.debug( I18n.msg( I18n.MSG_04101_BIND_SUCCESSFUL, bindResponse ) );
                }
            }
            else
            {
                // We have had an error
                if ( LOG.isDebugEnabled() )
                { 
                    LOG.debug( I18n.msg( I18n.MSG_04100_BIND_FAIL, bindResponse ) );
                }
            }

            return bindResponse;
        }
        catch ( Exception ie )
        {
            // Catch all other exceptions
            LOG.error( NO_RESPONSE_ERROR, ie );

            throw new LdapException( NO_RESPONSE_ERROR, ie );
        }
    }


    /**
     * Do an asynchronous bind, based on a SaslPlainRequest.
     *
     * @param request The SaslPlainRequest POJO containing all the needed parameters
     * @return The bind operation's future
     * @throws LdapException if some error occurred
     */
    public BindFuture bindAsync( SaslRequest request )
        throws LdapException
    {
        return bindSasl( request );
    }


    /**
     * Bind to the server using a DigestMd5Request object.
     *
     * @param request The DigestMd5Request POJO containing all the needed parameters
     * @return A LdapResponse containing the result
     * @throws LdapException if some error occurred
     */
    public BindResponse bind( SaslDigestMd5Request request ) throws LdapException
    {
        if ( request == null )
        {
            String msg = I18n.msg( I18n.MSG_04103_NULL_REQUEST );

            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( msg );
            }
            
            throw new IllegalArgumentException( msg );
        }

        BindFuture bindFuture = bindAsync( request );

        // Get the result from the future
        try
        {
            // Read the response, waiting for it if not available immediately
            // Get the response, blocking
            BindResponse bindResponse = bindFuture.get( timeout, TimeUnit.MILLISECONDS );

            if ( bindResponse == null )
            {
                // We didn't received anything : this is an error
                if ( LOG.isErrorEnabled() )
                { 
                    LOG.error( I18n.err( I18n.ERR_04112_OP_FAILED_TIMEOUT, "Bind" ) );
                }
                
                throw new LdapException( TIME_OUT_ERROR );
            }

            if ( bindResponse.getLdapResult().getResultCode() == ResultCodeEnum.SUCCESS )
            {
                authenticated.set( true );

                // Everything is fine, return the response
                if ( LOG.isDebugEnabled() )
                { 
                    LOG.debug( I18n.msg( I18n.MSG_04101_BIND_SUCCESSFUL, bindResponse ) );
                }
            }
            else
            {
                // We have had an error
                if ( LOG.isDebugEnabled() )
                { 
                    LOG.debug( I18n.msg( I18n.MSG_04100_BIND_FAIL, bindResponse ) );
                }
            }

            return bindResponse;
        }
        catch ( Exception ie )
        {
            // Catch all other exceptions
            LOG.error( NO_RESPONSE_ERROR, ie );

            throw new LdapException( NO_RESPONSE_ERROR, ie );
        }
    }


    /**
     * Bind to the server using a GssApiRequest object.
     *
     * @param request The GssApiRequest POJO containing all the needed parameters
     * @return A LdapResponse containing the result
     * @throws LdapException if some error occurred
     */
    public BindResponse bind( SaslGssApiRequest request ) throws LdapException
    {
        if ( request == null )
        {
            String msg = I18n.msg( I18n.MSG_04103_NULL_REQUEST );

            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( msg );
            }
            
            throw new IllegalArgumentException( msg );
        }

        BindFuture bindFuture = bindAsync( request );

        // Get the result from the future
        try
        {
            // Read the response, waiting for it if not available immediately
            // Get the response, blocking
            BindResponse bindResponse = bindFuture.get( timeout, TimeUnit.MILLISECONDS );

            if ( bindResponse == null )
            {
                // We didn't received anything : this is an error
                if ( LOG.isErrorEnabled() )
                { 
                    LOG.error( I18n.err( I18n.ERR_04112_OP_FAILED_TIMEOUT, "Bind" ) );
                }
                
                throw new LdapException( TIME_OUT_ERROR );
            }

            if ( bindResponse.getLdapResult().getResultCode() == ResultCodeEnum.SUCCESS )
            {
                authenticated.set( true );

                // Everything is fine, return the response
                if ( LOG.isDebugEnabled() )
                { 
                    LOG.debug( I18n.msg( I18n.MSG_04101_BIND_SUCCESSFUL, bindResponse ) );
                }
            }
            else
            {
                // We have had an error
                if ( LOG.isDebugEnabled() )
                { 
                    LOG.debug( I18n.msg( I18n.MSG_04100_BIND_FAIL, bindResponse ) );
                }
            }

            return bindResponse;
        }
        catch ( Exception ie )
        {
            // Catch all other exceptions
            LOG.error( NO_RESPONSE_ERROR, ie );

            throw new LdapException( NO_RESPONSE_ERROR, ie );
        }
    }


    /**
     * Bind to the server using a SaslExternalRequest object.
     *
     * @param request The SaslExternalRequest POJO containing all the needed parameters
     * @return A LdapResponse containing the result
     * @throws LdapException if some error occurred
     */
    public BindResponse bind( SaslExternalRequest request ) throws LdapException
    {
        if ( request == null )
        {
            String msg = I18n.msg( I18n.MSG_04103_NULL_REQUEST );

            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( msg );
            }
            
            throw new IllegalArgumentException( msg );
        }

        BindFuture bindFuture = bindAsync( request );

        // Get the result from the future
        try
        {
            // Read the response, waiting for it if not available immediately
            // Get the response, blocking
            BindResponse bindResponse = bindFuture.get( timeout, TimeUnit.MILLISECONDS );

            if ( bindResponse == null )
            {
                // We didn't received anything : this is an error
                if ( LOG.isErrorEnabled() )
                { 
                    LOG.error( I18n.err( I18n.ERR_04112_OP_FAILED_TIMEOUT, "Bind" ) );
                }
                
                throw new LdapException( TIME_OUT_ERROR );
            }

            if ( bindResponse.getLdapResult().getResultCode() == ResultCodeEnum.SUCCESS )
            {
                authenticated.set( true );

                // Everything is fine, return the response
                if ( LOG.isDebugEnabled() )
                { 
                    LOG.debug( I18n.msg( I18n.MSG_04101_BIND_SUCCESSFUL, bindResponse ) );
                }
            }
            else
            {
                // We have had an error
                if ( LOG.isDebugEnabled() )
                { 
                    LOG.debug( I18n.msg( I18n.MSG_04100_BIND_FAIL, bindResponse ) );
                }
            }

            return bindResponse;
        }
        catch ( Exception ie )
        {
            // Catch all other exceptions
            LOG.error( NO_RESPONSE_ERROR, ie );

            throw new LdapException( NO_RESPONSE_ERROR, ie );
        }
    }


    /**
     * Do an asynchronous bind, based on a GssApiRequest.
     *
     * @param request The GssApiRequest POJO containing all the needed parameters
     * @return The bind operation's future
     * @throws LdapException if some error occurred
     */
    public BindFuture bindAsync( SaslGssApiRequest request )
        throws LdapException
    {
        // Krb5.conf file
        if ( request.getKrb5ConfFilePath() != null )
        {
            // Using the krb5.conf file provided by the user
            System.setProperty( KRB5_CONF, request.getKrb5ConfFilePath() );
        }
        else if ( ( request.getRealmName() != null ) && ( request.getKdcHost() != null )
            && ( request.getKdcPort() != 0 ) )
        {
            try
            {
                // Using a custom krb5.conf we create from the settings provided by the user
                String krb5ConfPath = createKrb5ConfFile( request.getRealmName(), request.getKdcHost(),
                    request.getKdcPort() );
                System.setProperty( KRB5_CONF, krb5ConfPath );
            }
            catch ( IOException ioe )
            {
                throw new LdapException( ioe );
            }
        }
        else
        {
            // Using the system Kerberos configuration
            System.clearProperty( KRB5_CONF );
        }

        // Login Module configuration
        if ( request.getLoginModuleConfiguration() != null )
        {
            // Using the configuration provided by the user
            Configuration.setConfiguration( request.getLoginModuleConfiguration() );
        }
        else
        {
            // Using the default configuration
            Configuration.setConfiguration( new Krb5LoginConfiguration() );
        }

        try
        {
            System.setProperty( "javax.security.auth.useSubjectCredsOnly", "true" );
            LoginContext loginContext = new LoginContext( request.getLoginContextName(),
                new SaslCallbackHandler( request ) );
            loginContext.login();

            final SaslGssApiRequest requetFinal = request;
            return ( BindFuture ) Subject.doAs( loginContext.getSubject(), new PrivilegedExceptionAction<Object>()
            {
                @Override
                public Object run() throws Exception
                {
                    return bindSasl( requetFinal );
                }
            } );
        }
        catch ( Exception e )
        {
            connectionCloseFuture.complete( 0 );
            throw new LdapException( e );
        }
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public EntryCursor search( Dn baseDn, String filter, SearchScope scope, String... attributes )
        throws LdapException
    {
        if ( baseDn == null )
        {
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.msg( I18n.MSG_04138_NULL_DN_SEARCH ) );
            }
            
            throw new IllegalArgumentException( I18n.err( I18n.ERR_04129_NULL_BASE_DN ) );
        }

        // Create a new SearchRequest object
        SearchRequest searchRequest = new SearchRequestImpl();

        searchRequest.setBase( baseDn );
        searchRequest.setFilter( filter );
        searchRequest.setScope( scope );
        searchRequest.addAttributes( attributes );
        searchRequest.setDerefAliases( AliasDerefMode.DEREF_ALWAYS );

        // Process the request in blocking mode
        return new EntryCursorImpl( search( searchRequest ) );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public EntryCursor search( String baseDn, String filter, SearchScope scope, String... attributes )
        throws LdapException
    {
        return search( new Dn( baseDn ), filter, scope, attributes );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public SearchFuture searchAsync( Dn baseDn, String filter, SearchScope scope, String... attributes )
        throws LdapException
    {
        // Create a new SearchRequest object
        SearchRequest searchRequest = new SearchRequestImpl();

        searchRequest.setBase( baseDn );
        searchRequest.setFilter( filter );
        searchRequest.setScope( scope );
        searchRequest.addAttributes( attributes );
        searchRequest.setDerefAliases( AliasDerefMode.DEREF_ALWAYS );

        // Process the request in blocking mode
        return searchAsync( searchRequest );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public SearchFuture searchAsync( String baseDn, String filter, SearchScope scope, String... attributes )
        throws LdapException
    {
        return searchAsync( new Dn( baseDn ), filter, scope, attributes );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public SearchFuture searchAsync( SearchRequest searchRequest ) throws LdapException
    {
        if ( searchRequest == null )
        {
            String msg = I18n.err( I18n.ERR_04130_CANNOT_PROCESS_NULL_SEARCH_REQ );

            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( msg );
            }
            
            throw new IllegalArgumentException( msg );
        }

        if ( searchRequest.getBase() == null )
        {
            String msg = I18n.err( I18n.ERR_04131_CANNOT_PROCESS_SEARCH_NULL_DN );

            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( msg );
            }
            
            throw new IllegalArgumentException( msg );
        }

        // try to connect, if we aren't already connected.
        connect();

        // If the session has not been establish, or is closed, we get out immediately
        checkSession();

        int newId = messageId.incrementAndGet();
        searchRequest.setMessageId( newId );

        if ( searchRequest.isIgnoreReferrals() )
        {
            // We want to ignore the referral, inject the ManageDSAIT control in the request
            searchRequest.addControl( new ManageDsaITImpl() );
        }

        if ( LOG.isDebugEnabled() )
        {
            LOG.debug( I18n.msg( I18n.MSG_04104_SENDING_REQUEST, searchRequest ) );
        }

        SearchFuture searchFuture = new SearchFuture( this, searchRequest.getMessageId() );
        addToFutureMap( searchRequest.getMessageId(), searchFuture );

        // Send the request to the server
        writeRequest( searchRequest );

        // Check that the future hasn't be canceled
        if ( searchFuture.isCancelled() )
        {
            // Throw an exception here
            throw new LdapException( searchFuture.getCause() );
        }

        // Ok, done return the future
        return searchFuture;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public SearchCursor search( SearchRequest searchRequest ) throws LdapException
    {
        if ( searchRequest == null )
        {
            String msg = I18n.err( I18n.ERR_04130_CANNOT_PROCESS_NULL_SEARCH_REQ );
            
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( msg );
            }
            
            throw new IllegalArgumentException( msg );
        }

        SearchFuture searchFuture = searchAsync( searchRequest );

        long searchTimeout = getTimeout( timeout, searchRequest.getTimeLimit() );

        return new SearchCursorImpl( searchFuture, searchTimeout, TimeUnit.MILLISECONDS );
    }


    //------------------------ The LDAP operations ------------------------//
    // Unbind operations                                                   //
    //---------------------------------------------------------------------//
    /**
     * {@inheritDoc}
     */
    @Override
    public void unBind() throws LdapException
    {
        // If the session has not been establish, or is closed, we get out immediately
        checkSession();

        // Creates the messageID and stores it into the
        // initial message and the transmitted message.
        int newId = messageId.incrementAndGet();

        // Create the UnbindRequest
        UnbindRequest unbindRequest = new UnbindRequestImpl();
        unbindRequest.setMessageId( newId );

        if ( LOG.isDebugEnabled() )
        {
            LOG.debug( I18n.msg( I18n.MSG_04132_SENDING_UNBIND, unbindRequest ) );
        }

        // Send the request to the server
        // Use this for logging instead: WriteFuture unbindFuture = ldapSession.write( unbindRequest )
        WriteFuture unbindFuture = ioSession.write( unbindRequest );

        unbindFuture.awaitUninterruptibly( timeout );

        try
        {
            connectionCloseFuture.get( timeout, TimeUnit.MILLISECONDS );
        }
        catch ( TimeoutException | ExecutionException | InterruptedException e )
        {
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.msg( I18n.MSH_04178_CLOSE_LATCH_ABORTED ) );
            }
        }

        // And get out
        if ( LOG.isDebugEnabled() )
        {
            LOG.debug( I18n.msg( I18n.MSG_04133_UNBINDSUCCESSFUL ) );
        }
    }


    /**
     * Set the connector to use.
     *
     * @param connector The connector to use
     */
    public void setConnector( IoConnector connector )
    {
        this.connector = connector;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setTimeOut( long timeout )
    {
        if ( timeout <= 0 )
        {
            // Set a date in the far future : 100 years
            this.timeout = 1000L * 60L * 60L * 24L * 365L * 100L;
        }
        else
        {
            this.timeout = timeout;
        }
    }


    /**
     * Handle the exception we got.
     *
     * @param session The session we got the exception on
     * @param cause The exception cause
     * @throws Exception If we have had another exception
     */
    @Override
    public void exceptionCaught( IoSession session, Throwable cause ) throws Exception
    {
        if ( LOG.isWarnEnabled() )
        {
            LOG.warn( cause.getMessage(), cause );
        }

        session.setAttribute( EXCEPTION_KEY, cause );

        if ( cause instanceof ProtocolEncoderException )
        {
            Throwable realCause = ( ( ProtocolEncoderException ) cause ).getCause();

            if ( realCause instanceof MessageEncoderException )
            {
                int messageId = ( ( MessageEncoderException ) realCause ).getMessageId();

                ResponseFuture<?> response = futureMap.get( messageId );
                response.cancel( true );
                response.setCause( realCause );
            }
        }

        session.closeNow();
    }


    /**
     * Check if the message is a NoticeOfDisconnect message
     * 
     * @param message The message to check
     * @return <tt>true</tt> if the message is a Notice of Disconnect
     */
    private boolean isNoticeOfDisconnect( Message message )
    {
        if ( message instanceof ExtendedResponse )
        {
            String responseName = ( ( ExtendedResponse ) message ).getResponseName();

            if ( NoticeOfDisconnect.EXTENSION_OID.equals( responseName ) )
            {
                return true;
            }
        }

        return false;
    }


    /**
     * Process the AddResponse received from the server
     * 
     * @param addResponse The AddResponse to process
     * @param addFuture The AddFuture to feed
     * @param responseId The associated request message ID
     * @throws InterruptedException If the Future is interrupted
     */
    private void addReceived( AddResponse addResponse, AddFuture addFuture, int responseId ) throws InterruptedException
    {
        // remove the listener from the listener map
        if ( LOG.isDebugEnabled() )
        {
            if ( addResponse.getLdapResult().getResultCode() == ResultCodeEnum.SUCCESS )
            {
                // Everything is fine, return the response
                LOG.debug( I18n.msg( I18n.MSG_04108_ADD_SUCCESSFUL, addResponse ) );
            }
            else
            {
                // We have had an error
                LOG.debug( I18n.msg( I18n.MSG_04107_ADD_FAILED, addResponse ) );
            }
        }

        // Store the response into the future
        addFuture.set( addResponse );

        // Remove the future from the map
        removeFromFutureMaps( responseId );
    }


    /**
     * Process the BindResponse received from the server
     * 
     * @param bindResponse The BindResponse to process
     * @param bindFuture The BindFuture to feed
     * @param responseId The associated request message ID
     * @throws InterruptedException If the Future is interrupted
     */
    private void bindReceived( BindResponse bindResponse, BindFuture bindFuture, int responseId ) 
        throws InterruptedException
    {
        // remove the listener from the listener map
        if ( bindResponse.getLdapResult().getResultCode() == ResultCodeEnum.SUCCESS )
        {
            authenticated.set( true );

            // Everything is fine, return the response
            if ( LOG.isDebugEnabled() )
            { 
                LOG.debug( I18n.msg( I18n.MSG_04101_BIND_SUCCESSFUL, bindResponse ) );
            }
        }
        else
        {
            // We have had an error
            if ( LOG.isDebugEnabled() )
            { 
                LOG.debug( I18n.msg( I18n.MSG_04100_BIND_FAIL, bindResponse ) );
            }
        }

        // Store the response into the future
        bindFuture.set( bindResponse );

        // Remove the future from the map
        removeFromFutureMaps( responseId );
    }


    /**
     * Process the CompareResponse received from the server
     * 
     * @param compareResponse The CompareResponse to process
     * @param compareFuture The CompareFuture to feed
     * @param responseId The associated request message ID
     * @throws InterruptedException If the Future is interrupted
     */
    private void compareReceived( CompareResponse compareResponse, CompareFuture compareFuture, int responseId ) 
       throws InterruptedException
    {
        // remove the listener from the listener map
        if ( LOG.isDebugEnabled() )
        {
            if ( compareResponse.getLdapResult().getResultCode() == ResultCodeEnum.SUCCESS )
            {
                // Everything is fine, return the response
                LOG.debug( I18n.msg( I18n.MSG_04114_COMPARE_SUCCESSFUL, compareResponse ) );
            }
            else
            {
                // We have had an error
                LOG.debug( I18n.msg( I18n.MSG_04113_COMPARE_FAILED, compareResponse ) );
            }
        }

        // Store the response into the future
        compareFuture.set( compareResponse );

        // Remove the future from the map
        removeFromFutureMaps( responseId );
    }


    /**
     * Process the DeleteResponse received from the server
     * 
     * @param deleteResponse The DeleteResponse to process
     * @param deleteFuture The DeleteFuture to feed
     * @param responseId The associated request message ID
     * @throws InterruptedException If the Future is interrupted
     */
    private void deleteReceived( DeleteResponse deleteResponse, DeleteFuture deleteFuture, int responseId ) 
        throws InterruptedException
    {
        if ( LOG.isDebugEnabled() )
        {
            if ( deleteResponse.getLdapResult().getResultCode() == ResultCodeEnum.SUCCESS )
            {
                // Everything is fine, return the response
                LOG.debug( I18n.msg( I18n.MSG_04116_DELETE_SUCCESSFUL, deleteResponse ) );
            }
            else
            {
                // We have had an error
                LOG.debug( I18n.msg( I18n.MSG_04115_DELETE_FAILED, deleteResponse ) );
            }
        }

        // Store the response into the future
        deleteFuture.set( deleteResponse );

        // Remove the future from the map
        removeFromFutureMaps( responseId );
    }


    /**
     * Process the ExtendedResponse received from the server
     * 
     * @param extendedResponse The ExtendedResponse to process
     * @param extendedFuture The ExtendedFuture to feed
     * @param responseId The associated request message ID
     * @throws InterruptedException If the Future is interrupted
     * @throws DecoderException If the response cannot be decoded
     */
    private void extendedReceived( ExtendedResponse extendedResponse, ExtendedFuture extendedFuture, int responseId ) 
        throws InterruptedException, DecoderException
    {
        if ( LOG.isDebugEnabled() )
        {
            if ( extendedResponse.getLdapResult().getResultCode() == ResultCodeEnum.SUCCESS )
            {
                // Everything is fine, return the response
                LOG.debug( I18n.msg( I18n.MSG_04118_EXTENDED_SUCCESSFUL, extendedResponse ) );
            }
            else
            {
                // We have had an error
                LOG.debug( I18n.msg( I18n.MSG_04117_EXTENDED_FAILED, extendedResponse ) );
            }
        }
        
        extendedResponse = handleOpaqueResponse( extendedResponse, extendedFuture );

        // Store the response into the future
        extendedFuture.set( extendedResponse );

        // Remove the future from the map
        removeFromFutureMaps( responseId );
    }


    /**
     * Process the IntermediateResponse received from the server
     * 
     * @param intermediateResponse The IntermediateResponse to process
     * @param responseFuture The ResponseFuture to feed
     * @throws InterruptedException If the Future is interrupted
     */
    private void intermediateReceived( IntermediateResponse intermediateResponse, ResponseFuture<? extends Response> responseFuture ) 
        throws InterruptedException
    {
        // Store the response into the future
        if ( responseFuture instanceof SearchFuture )
        {
            ( ( SearchFuture ) responseFuture ).set( intermediateResponse );
        }
        else if ( responseFuture instanceof ExtendedFuture )
        {
            ( ( ExtendedFuture ) responseFuture ).set( intermediateResponse );
        }
        else
        {
            // currently we only support IR for search and extended operations
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_04111_UNKNOWN_RESPONSE_FUTURE_TYPE,
                responseFuture.getClass().getName() ) );
        }

        // Do not remove the future from the map, that's done when receiving search result done
    }


    /**
     * Process the ModifyResponse received from the server
     * 
     * @param modifyResponse The ModifyResponse to process
     * @param modifyFuture The ModifyFuture to feed
     * @param responseId The associated request message ID
     * @throws InterruptedException If the Future is interrupted
     */
    private void modifyReceived( ModifyResponse modifyResponse, ModifyFuture modifyFuture, int responseId ) 
        throws InterruptedException
    {
        if ( LOG.isDebugEnabled() )
        {
            if ( modifyResponse.getLdapResult().getResultCode() == ResultCodeEnum.SUCCESS )
            {
                // Everything is fine, return the response
                if ( LOG.isDebugEnabled() )
                { 
                    LOG.debug( I18n.msg( I18n.MSG_04123_MODIFY_SUCCESSFUL, modifyResponse ) );
                }
            }
            else
            {
                // We have had an error
                if ( LOG.isDebugEnabled() )
                { 
                    LOG.debug( I18n.msg( I18n.MSG_04122_MODIFY_FAILED, modifyResponse ) );
                }
            }
        }

        // Store the response into the future
        modifyFuture.set( modifyResponse );

        // Remove the future from the map
        removeFromFutureMaps( responseId );
    }


    /**
     * Process the ModifyDnResponse received from the server
     * 
     * @param modifyDnResponse The ModifyDnResponse to process
     * @param modifyDnFuture The ModifyDnFuture to feed
     * @param responseId The associated request message ID
     * @throws InterruptedException If the Future is interrupted
     */
    private void modifyDnReceived( ModifyDnResponse modifyDnResponse, ModifyDnFuture modifyDnFuture, int responseId ) 
        throws InterruptedException
    {
        if ( LOG.isDebugEnabled() )
        {
            if ( modifyDnResponse.getLdapResult().getResultCode() == ResultCodeEnum.SUCCESS )
            {
                // Everything is fine, return the response
                LOG.debug( I18n.msg( I18n.MSG_04125_MODIFYDN_SUCCESSFUL, modifyDnResponse ) );
            }
            else
            {
                // We have had an error
                LOG.debug( I18n.msg( I18n.MSG_04124_MODIFYDN_FAILED, modifyDnResponse ) );
            }
        }

        // Store the response into the future
        modifyDnFuture.set( modifyDnResponse );

        // Remove the future from the map
        removeFromFutureMaps( responseId );
    }


    /**
     * Process the SearchResultDone received from the server
     * 
     * @param searchResultDone The SearchResultDone to process
     * @param searchFuture The SearchFuture to feed
     * @param responseId The associated request message ID
     * @throws InterruptedException If the Future is interrupted
     */
    private void searchResultDoneReceived( SearchResultDone searchResultDone, SearchFuture searchFuture, 
        int responseId ) throws InterruptedException
    {
        if ( LOG.isDebugEnabled() )
        {
            if ( searchResultDone.getLdapResult().getResultCode() == ResultCodeEnum.SUCCESS )
            {
                // Everything is fine, return the response
                LOG.debug( I18n.msg( I18n.MSG_04131_SEARCH_SUCCESSFUL, searchResultDone ) );
            }
            else
            {
                // We have had an error
                LOG.debug( I18n.msg( I18n.MSG_04129_SEARCH_FAILED, searchResultDone ) );
            }
        }

        // Store the response into the future
        searchFuture.set( searchResultDone );

        // Remove the future from the map
        removeFromFutureMaps( responseId );
    }


    /**
     * Process the SearchResultEntry received from the server
     * 
     * @param searchResultEntry The SearchResultEntry to process
     * @param searchFuture The SearchFuture to feed
     * @throws InterruptedException If the Future is interrupted
     * @throws LdapException If we weren't able to create a new Entry
     */
    private void searchResultEntryReceived( SearchResultEntry searchResultEntry, SearchFuture searchFuture ) 
        throws InterruptedException, LdapException
    {
        if ( schemaManager != null )
        {
            searchResultEntry.setEntry( new DefaultEntry( schemaManager, searchResultEntry.getEntry() ) );
        }

        if ( LOG.isDebugEnabled() )
        {
            LOG.debug( I18n.msg( I18n.MSG_04128_SEARCH_ENTRY_FOUND, searchResultEntry ) );
        }

        // Store the response into the future
        searchFuture.set( searchResultEntry );
    }
    
    
    /**
     * Process the SearchResultEntry received from the server
     * 
     * @param searchResultReference The SearchResultReference to process
     * @param searchFuture The SearchFuture to feed
     * @throws InterruptedException If the Future is interrupted
     */
    private void searchResultReferenceReceived( SearchResultReference searchResultReference, SearchFuture searchFuture ) 
        throws InterruptedException
    {
        if ( LOG.isDebugEnabled() )
        {
            LOG.debug( I18n.msg( I18n.MSG_04130_SEARCH_REFERENCE_FOUND, searchResultReference ) );
        }

        // Store the response into the future
        searchFuture.set( searchResultReference );
    }
    

    /**
     * Handle the incoming LDAP messages. This is where we feed the cursor for search
     * requests, or call the listener.
     *
     * @param session The session that received a message
     * @param message The received message
     * @throws Exception If there is some error while processing the message
     */
    @Override
    public void messageReceived( IoSession session, Object message ) throws Exception
    {
        // Feed the response and store it into the session
        Response response = ( Response ) message;

        if ( LOG.isDebugEnabled() )
        {
            LOG.debug( I18n.msg( I18n.MSG_04142_MESSAGE_RECEIVED, response ) );
        }
        
        int responseId = response.getMessageId();

        // this check is necessary to prevent adding an abandoned operation's
        // result(s) to corresponding queue
        ResponseFuture<? extends Response> responseFuture = peekFromFutureMap( responseId );

        boolean isNoD = isNoticeOfDisconnect( response );

        if ( ( responseFuture == null ) && !isNoD )
        {
            if ( LOG.isInfoEnabled() )
            {
                LOG.info( I18n.msg( I18n.MSG_04166_NO_FUTURE_ASSOCIATED_TO_MSG_ID_IGNORING, responseId ) );
            }
            
            return;
        }

        if ( isNoD )
        {
            // close the session
            session.closeNow();

            return;
        }

        switch ( response.getType() )
        {
            case ADD_RESPONSE:
                addReceived( ( AddResponse ) response, ( AddFuture ) responseFuture, responseId );

                break;

            case BIND_RESPONSE:
                bindReceived( ( BindResponse ) response, ( BindFuture ) responseFuture, responseId );

                break;

            case COMPARE_RESPONSE:
                compareReceived( ( CompareResponse ) response, ( CompareFuture ) responseFuture, responseId );

                break;

            case DEL_RESPONSE:
                deleteReceived( ( DeleteResponse ) response, ( DeleteFuture ) responseFuture, responseId );

                break;

            case EXTENDED_RESPONSE:
                extendedReceived( ( ExtendedResponse ) response, ( ExtendedFuture ) responseFuture, responseId );

                break;

            case INTERMEDIATE_RESPONSE:
                intermediateReceived( ( IntermediateResponse ) response, responseFuture );

                break;

            case MODIFY_RESPONSE:
                modifyReceived( ( ModifyResponse ) response, ( ModifyFuture ) responseFuture, responseId );

                break;

            case MODIFYDN_RESPONSE:
                modifyDnReceived( ( ModifyDnResponse ) response, ( ModifyDnFuture ) responseFuture, responseId );

                break;

            case SEARCH_RESULT_DONE:
                searchResultDoneReceived( ( SearchResultDone ) response, ( SearchFuture ) responseFuture, responseId );

                break;

            case SEARCH_RESULT_ENTRY:
                searchResultEntryReceived( ( SearchResultEntry ) response, ( SearchFuture ) responseFuture );

                break;

            case SEARCH_RESULT_REFERENCE:
                searchResultReferenceReceived( ( SearchResultReference ) response, ( SearchFuture ) responseFuture );

                break;

            default:
                throw new IllegalStateException( I18n.err( I18n.ERR_04132_UNEXPECTED_RESPONSE_TYPE, response.getType() ) );
        }
    }

    
    private ExtendedResponse handleOpaqueResponse( ExtendedResponse extendedResponse, ExtendedFuture extendedFuture ) 
        throws DecoderException
    {
        if ( ( extendedResponse instanceof OpaqueExtendedResponse ) 
            && ( Strings.isEmpty( extendedResponse.getResponseName() ) ) ) 
        {
            ExtendedOperationFactory factory = codec.getExtendedResponseFactories().
                get( extendedFuture.getExtendedRequest().getRequestName() );

            byte[] responseValue = ( ( OpaqueExtendedResponse ) extendedResponse ).getResponseValue();

            ExtendedResponse response;
            if ( responseValue != null )
            {
                response = factory.newResponse( responseValue );
            }
            else
            {
                response = factory.newResponse();
            }

            // Copy the controls
            for ( Control control : extendedResponse.getControls().values() )
            {
                response.addControl( control );
            }
            
            // copy the LDAPResult
            response.getLdapResult().setDiagnosticMessage( extendedResponse.getLdapResult().getDiagnosticMessage() );
            response.getLdapResult().setMatchedDn( extendedResponse.getLdapResult().getMatchedDn() );
            response.getLdapResult().setReferral( extendedResponse.getLdapResult().getReferral() );
            response.getLdapResult().setResultCode( extendedResponse.getLdapResult().getResultCode() );
            
            return response;
        }
        else
        {
            return extendedResponse;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void modify( Entry entry, ModificationOperation modOp ) throws LdapException
    {
        if ( entry == null )
        {
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.msg( I18n.MSG_04140_NULL_ENTRY_MODIFY ) );
            }
            
            throw new IllegalArgumentException( I18n.err( I18n.ERR_04133_NULL_MODIFIED_ENTRY ) );
        }

        ModifyRequest modReq = new ModifyRequestImpl();
        modReq.setName( entry.getDn() );

        Iterator<Attribute> itr = entry.iterator();

        while ( itr.hasNext() )
        {
            modReq.addModification( itr.next(), modOp );
        }

        ModifyResponse modifyResponse = modify( modReq );

        processResponse( modifyResponse );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void modify( Dn dn, Modification... modifications ) throws LdapException
    {
        if ( dn == null )
        {
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.msg( I18n.MSG_04139_NULL_DN_MODIFY ) );
            }
            
            throw new IllegalArgumentException( I18n.err( I18n.ERR_04134_NULL_MODIFIED_DN ) );
        }

        if ( ( modifications == null ) || ( modifications.length == 0 ) )
        {
            String msg = I18n.err( I18n.ERR_04135_CANNOT_PROCESS_NO_MODIFICATION_MOD );

            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( msg );
            }
            
            throw new IllegalArgumentException( msg );
        }

        ModifyRequest modReq = new ModifyRequestImpl();
        modReq.setName( dn );

        for ( Modification modification : modifications )
        {
            modReq.addModification( modification );
        }

        ModifyResponse modifyResponse = modify( modReq );

        processResponse( modifyResponse );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void modify( String dn, Modification... modifications ) throws LdapException
    {
        modify( new Dn( dn ), modifications );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ModifyResponse modify( ModifyRequest modRequest ) throws LdapException
    {
        if ( modRequest == null )
        {
            String msg = I18n.err( I18n.ERR_04136_CANNOT_PROCESS_NULL_MOD_REQ );

            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( msg );
            }
            
            throw new IllegalArgumentException( msg );
        }

        ModifyFuture modifyFuture = modifyAsync( modRequest );

        // Get the result from the future
        try
        {
            // Read the response, waiting for it if not available immediately
            // Get the response, blocking
            ModifyResponse modifyResponse = modifyFuture.get( timeout, TimeUnit.MILLISECONDS );

            if ( modifyResponse == null )
            {
                // We didn't received anything : this is an error
                if ( LOG.isErrorEnabled() )
                {
                    LOG.error( I18n.err( I18n.ERR_04112_OP_FAILED_TIMEOUT, "Modify" ) );
                }
                
                throw new LdapException( TIME_OUT_ERROR );
            }

            if ( modifyResponse.getLdapResult().getResultCode() == ResultCodeEnum.SUCCESS )
            {
                // Everything is fine, return the response
                if ( LOG.isDebugEnabled() )
                { 
                    LOG.debug( I18n.msg( I18n.MSG_04123_MODIFY_SUCCESSFUL, modifyResponse ) );
                }
            }
            else
            {
                if ( modifyResponse instanceof ModifyNoDResponse )
                {
                    // A NoticeOfDisconnect : deserves a special treatment
                    throw new LdapException( modifyResponse.getLdapResult().getDiagnosticMessage() );
                }

                // We have had an error
                if ( LOG.isDebugEnabled() )
                { 
                    LOG.debug( I18n.msg( I18n.MSG_04122_MODIFY_FAILED, modifyResponse ) );
                }
            }

            return modifyResponse;
        }
        catch ( Exception ie )
        {
            // Catch all other exceptions
            LOG.error( NO_RESPONSE_ERROR, ie );

            // Send an abandon request
            if ( !modifyFuture.isCancelled() )
            {
                abandon( modRequest.getMessageId() );
            }

            throw new LdapException( ie.getMessage(), ie );
        }
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ModifyFuture modifyAsync( ModifyRequest modRequest ) throws LdapException
    {
        if ( modRequest == null )
        {
            String msg = I18n.err( I18n.ERR_04136_CANNOT_PROCESS_NULL_MOD_REQ );

            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( msg );
            }
            
            throw new IllegalArgumentException( msg );
        }

        if ( modRequest.getName() == null )
        {
            String msg = I18n.err( I18n.ERR_04137_CANNOT_PROCESS_MOD_NULL_DN );

            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( msg );
            }
            
            throw new IllegalArgumentException( msg );
        }

        // try to connect, if we aren't already connected.
        connect();

        checkSession();

        int newId = messageId.incrementAndGet();
        modRequest.setMessageId( newId );

        ModifyFuture modifyFuture = new ModifyFuture( this, newId );
        addToFutureMap( newId, modifyFuture );

        // Send the request to the server
        writeRequest( modRequest );

        // Ok, done return the future
        return modifyFuture;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void rename( String entryDn, String newRdn ) throws LdapException
    {
        rename( entryDn, newRdn, true );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void rename( Dn entryDn, Rdn newRdn ) throws LdapException
    {
        rename( entryDn, newRdn, true );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void rename( String entryDn, String newRdn, boolean deleteOldRdn ) throws LdapException
    {
        if ( entryDn == null )
        {
            String msg = I18n.err( I18n.ERR_04138_CANNOT_PROCESS_RENAME_NULL_DN );

            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( msg );
            }
            
            throw new IllegalArgumentException( msg );
        }

        if ( newRdn == null )
        {
            String msg = I18n.err( I18n.ERR_04139_CANNOT_PROCESS_RENAME_NULL_RDN );

            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( msg );
            }
            
            throw new IllegalArgumentException( msg );
        }

        try
        {
            rename( new Dn( entryDn ), new Rdn( newRdn ), deleteOldRdn );
        }
        catch ( LdapInvalidDnException e )
        {
            LOG.error( e.getMessage(), e );
            throw new LdapException( e.getMessage(), e );
        }
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void rename( Dn entryDn, Rdn newRdn, boolean deleteOldRdn ) throws LdapException
    {
        if ( entryDn == null )
        {
            String msg = I18n.err( I18n.ERR_04138_CANNOT_PROCESS_RENAME_NULL_DN );

            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( msg );
            }
            
            throw new IllegalArgumentException( msg );
        }

        if ( newRdn == null )
        {
            String msg = I18n.err( I18n.ERR_04139_CANNOT_PROCESS_RENAME_NULL_RDN );
            
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( msg );
            }
            
            throw new IllegalArgumentException( msg );
        }

        ModifyDnRequest modDnRequest = new ModifyDnRequestImpl();
        modDnRequest.setName( entryDn );
        modDnRequest.setNewRdn( newRdn );
        modDnRequest.setDeleteOldRdn( deleteOldRdn );

        ModifyDnResponse modifyDnResponse = modifyDn( modDnRequest );

        processResponse( modifyDnResponse );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void move( String entryDn, String newSuperiorDn ) throws LdapException
    {
        if ( entryDn == null )
        {
            String msg = I18n.err( I18n.ERR_04140_CANNOT_PROCESS_MOVE_NULL_DN );

            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( msg );
            }
            
            throw new IllegalArgumentException( msg );
        }

        if ( newSuperiorDn == null )
        {
            String msg = I18n.err( I18n.ERR_04141_CANNOT_PROCESS_MOVE_NULL_SUPERIOR );
            
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( msg );
            }
            
            throw new IllegalArgumentException( msg );
        }

        try
        {
            move( new Dn( entryDn ), new Dn( newSuperiorDn ) );
        }
        catch ( LdapInvalidDnException e )
        {
            LOG.error( e.getMessage(), e );
            throw new LdapException( e.getMessage(), e );
        }
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void move( Dn entryDn, Dn newSuperiorDn ) throws LdapException
    {
        if ( entryDn == null )
        {
            String msg = I18n.err( I18n.ERR_04140_CANNOT_PROCESS_MOVE_NULL_DN );

            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( msg );
            }
            
            throw new IllegalArgumentException( msg );
        }

        if ( newSuperiorDn == null )
        {
            String msg = I18n.err( I18n.ERR_04141_CANNOT_PROCESS_MOVE_NULL_SUPERIOR );

            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( msg );
            }
            
            throw new IllegalArgumentException( msg );
        }

        ModifyDnRequest modDnRequest = new ModifyDnRequestImpl();
        modDnRequest.setName( entryDn );
        modDnRequest.setNewSuperior( newSuperiorDn );

        modDnRequest.setNewRdn( entryDn.getRdn() );

        ModifyDnResponse modifyDnResponse = modifyDn( modDnRequest );

        processResponse( modifyDnResponse );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void moveAndRename( Dn entryDn, Dn newDn ) throws LdapException
    {
        moveAndRename( entryDn, newDn, true );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void moveAndRename( String entryDn, String newDn ) throws LdapException
    {
        moveAndRename( new Dn( entryDn ), new Dn( newDn ), true );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void moveAndRename( Dn entryDn, Dn newDn, boolean deleteOldRdn ) throws LdapException
    {
        // Check the parameters first
        if ( entryDn == null )
        {
            throw new IllegalArgumentException( I18n.err( I18n.ERR_04142_NULL_ENTRY_DN ) );
        }

        if ( entryDn.isRootDse() )
        {
            throw new IllegalArgumentException( I18n.err( I18n.ERR_04143_CANNOT_MOVE_ROOT_DSE ) );
        }

        if ( newDn == null )
        {
            throw new IllegalArgumentException( I18n.err( I18n.ERR_04144_NULL_NEW_DN ) );
        }

        if ( newDn.isRootDse() )
        {
            throw new IllegalArgumentException( I18n.err( I18n.ERR_04145_ROOT_DSE_CANNOT_BE_TARGET ) );
        }

        // Create the request
        ModifyDnRequest modDnRequest = new ModifyDnRequestImpl();
        modDnRequest.setName( entryDn );
        modDnRequest.setNewRdn( newDn.getRdn() );
        
        // Check if we really need to specify newSuperior.
        // newSuperior is optional [RFC4511, section 4.9]
        // Some servers (e.g. OpenDJ 2.6) require a special privilege if
        // newSuperior is specified even if it is the same as the old one. Therefore let's not
        // specify it if we do not need it. This is better interoperability. 
        Dn newDnParent = newDn.getParent();
        if ( newDnParent != null && !newDnParent.equals( entryDn.getParent() ) )
        {
            modDnRequest.setNewSuperior( newDnParent );
        }
        
        modDnRequest.setDeleteOldRdn( deleteOldRdn );

        ModifyDnResponse modifyDnResponse = modifyDn( modDnRequest );

        processResponse( modifyDnResponse );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void moveAndRename( String entryDn, String newDn, boolean deleteOldRdn ) throws LdapException
    {
        moveAndRename( new Dn( entryDn ), new Dn( newDn ), true );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ModifyDnResponse modifyDn( ModifyDnRequest modDnRequest ) throws LdapException
    {
        if ( modDnRequest == null )
        {
            String msg = I18n.err( I18n.ERR_04145_ROOT_DSE_CANNOT_BE_TARGET );

            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( msg );
            }
            
            throw new IllegalArgumentException( msg );
        }

        ModifyDnFuture modifyDnFuture = modifyDnAsync( modDnRequest );

        // Get the result from the future
        try
        {
            // Read the response, waiting for it if not available immediately
            // Get the response, blocking
            ModifyDnResponse modifyDnResponse = modifyDnFuture.get( timeout, TimeUnit.MILLISECONDS );

            if ( modifyDnResponse == null )
            {
                // We didn't received anything : this is an error
                if ( LOG.isErrorEnabled() )
                {
                    LOG.error( I18n.err( I18n.ERR_04112_OP_FAILED_TIMEOUT, "ModifyDn" ) );
                }
                
                throw new LdapException( TIME_OUT_ERROR );
            }

            if ( modifyDnResponse.getLdapResult().getResultCode() == ResultCodeEnum.SUCCESS )
            {
                // Everything is fine, return the response
                if ( LOG.isDebugEnabled() )
                { 
                    LOG.debug( I18n.msg( I18n.MSG_04125_MODIFYDN_SUCCESSFUL, modifyDnResponse ) );
                }
            }
            else
            {
                // We have had an error
                if ( LOG.isDebugEnabled() )
                { 
                    LOG.debug( I18n.msg( I18n.MSG_04124_MODIFYDN_FAILED, modifyDnResponse ) );
                }
            }

            return modifyDnResponse;
        }
        catch ( Exception ie )
        {
            // Catch all other exceptions
            LOG.error( NO_RESPONSE_ERROR, ie );

            // Send an abandon request
            if ( !modifyDnFuture.isCancelled() )
            {
                abandon( modDnRequest.getMessageId() );
            }

            throw new LdapException( NO_RESPONSE_ERROR, ie );
        }
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ModifyDnFuture modifyDnAsync( ModifyDnRequest modDnRequest ) throws LdapException
    {
        if ( modDnRequest == null )
        {
            String msg = I18n.err( I18n.ERR_04145_ROOT_DSE_CANNOT_BE_TARGET );

            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( msg );
            }
            
            throw new IllegalArgumentException( msg );
        }

        if ( modDnRequest.getName() == null )
        {
            String msg = I18n.err( I18n.ERR_04137_CANNOT_PROCESS_MOD_NULL_DN );

            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( msg );
            }
            
            throw new IllegalArgumentException( msg );
        }

        if ( ( modDnRequest.getNewSuperior() == null ) && ( modDnRequest.getNewRdn() == null ) )
        {
            String msg = I18n.err( I18n.ERR_04147_CANNOT_PROCESS_MOD_NULL_DN_SUP );

            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( msg );
            }
            
            throw new IllegalArgumentException( msg );
        }

        // try to connect, if we aren't already connected.
        connect();

        checkSession();

        int newId = messageId.incrementAndGet();
        modDnRequest.setMessageId( newId );

        ModifyDnFuture modifyDnFuture = new ModifyDnFuture( this, newId );
        addToFutureMap( newId, modifyDnFuture );

        // Send the request to the server
        writeRequest( modDnRequest );

        // Ok, done return the future
        return modifyDnFuture;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void delete( String dn ) throws LdapException
    {
        delete( new Dn( dn ) );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void delete( Dn dn ) throws LdapException
    {
        DeleteRequest deleteRequest = new DeleteRequestImpl();
        deleteRequest.setName( dn );

        DeleteResponse deleteResponse = delete( deleteRequest );

        processResponse( deleteResponse );
    }


    /**
     * deletes the entry with the given Dn, and all its children
     *
     * @param dn the target entry's Dn
     * @throws LdapException If the Dn is not valid or if the deletion failed
     */
    public void deleteTree( Dn dn ) throws LdapException
    {
        if ( isControlSupported( TreeDelete.OID ) )
        {
            DeleteRequest deleteRequest = new DeleteRequestImpl();
            deleteRequest.setName( dn );
            deleteRequest.addControl( new TreeDeleteImpl() );
            DeleteResponse deleteResponse = delete( deleteRequest );

            processResponse( deleteResponse );
        }
        else
        {
            String msg = I18n.err( I18n.ERR_04148_SUBTREE_CONTROL_NOT_SUPPORTED );
            LOG.error( msg );
            throw new LdapException( msg );
        }
    }


    /**
     * deletes the entry with the given Dn, and all its children
     *
     * @param dn the target entry's Dn as a String
     * @throws LdapException If the Dn is not valid or if the deletion failed
     */
    public void deleteTree( String dn ) throws LdapException
    {
        try
        {
            String treeDeleteOid = "1.2.840.113556.1.4.805";
            Dn newDn = new Dn( dn );

            if ( isControlSupported( treeDeleteOid ) )
            {
                DeleteRequest deleteRequest = new DeleteRequestImpl();
                deleteRequest.setName( newDn );
                deleteRequest.addControl( new OpaqueControl( treeDeleteOid ) );
                DeleteResponse deleteResponse = delete( deleteRequest );

                processResponse( deleteResponse );
            }
            else
            {
                String msg = I18n.err( I18n.ERR_04148_SUBTREE_CONTROL_NOT_SUPPORTED );
                LOG.error( msg );
                throw new LdapException( msg );
            }
        }
        catch ( LdapInvalidDnException e )
        {
            LOG.error( e.getMessage(), e );
            throw new LdapException( e.getMessage(), e );
        }
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public DeleteResponse delete( DeleteRequest deleteRequest ) throws LdapException
    {
        if ( deleteRequest == null )
        {
            String msg = I18n.err( I18n.ERR_04149_CANNOT_PROCESS_NULL_DEL_REQ );

            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( msg );
            }
            
            throw new IllegalArgumentException( msg );
        }

        DeleteFuture deleteFuture = deleteAsync( deleteRequest );

        // Get the result from the future
        try
        {
            // Read the response, waiting for it if not available immediately
            // Get the response, blocking
            DeleteResponse delResponse = deleteFuture.get( timeout, TimeUnit.MILLISECONDS );

            if ( delResponse == null )
            {
                // We didn't received anything : this is an error
                if ( LOG.isErrorEnabled() )
                {
                    LOG.error( I18n.err( I18n.ERR_04112_OP_FAILED_TIMEOUT, "Delete" ) );
                }
                
                throw new LdapException( TIME_OUT_ERROR );
            }

            if ( delResponse.getLdapResult().getResultCode() == ResultCodeEnum.SUCCESS )
            {
                // Everything is fine, return the response
                if ( LOG.isDebugEnabled() )
                { 
                    LOG.debug( I18n.msg( I18n.MSG_04116_DELETE_SUCCESSFUL, delResponse ) );
                }
            }
            else
            {
                // We have had an error
                if ( LOG.isDebugEnabled() )
                { 
                    LOG.debug( I18n.msg( I18n.MSG_04115_DELETE_FAILED, delResponse ) );
                }
            }

            return delResponse;
        }
        catch ( Exception ie )
        {
            // Catch all other exceptions
            LOG.error( NO_RESPONSE_ERROR, ie );

            // Send an abandon request
            if ( !deleteFuture.isCancelled() )
            {
                abandon( deleteRequest.getMessageId() );
            }

            throw new LdapException( NO_RESPONSE_ERROR, ie );
        }
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public DeleteFuture deleteAsync( DeleteRequest deleteRequest ) throws LdapException
    {
        if ( deleteRequest == null )
        {
            String msg = I18n.err( I18n.ERR_04149_CANNOT_PROCESS_NULL_DEL_REQ );

            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( msg );
            }
            
            throw new IllegalArgumentException( msg );
        }

        if ( deleteRequest.getName() == null )
        {
            String msg = I18n.err( I18n.ERR_04150_CANNOT_PROCESS_NULL_DEL_NULL_DN );

            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( msg );
            }
            
            throw new IllegalArgumentException( msg );
        }

        // try to connect, if we aren't already connected.
        connect();

        checkSession();

        int newId = messageId.incrementAndGet();

        deleteRequest.setMessageId( newId );

        DeleteFuture deleteFuture = new DeleteFuture( this, newId );
        addToFutureMap( newId, deleteFuture );

        // Send the request to the server
        writeRequest( deleteRequest );

        // Ok, done return the future
        return deleteFuture;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean compare( String dn, String attributeName, String value ) throws LdapException
    {
        return compare( new Dn( dn ), attributeName, value );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean compare( String dn, String attributeName, byte[] value ) throws LdapException
    {
        return compare( new Dn( dn ), attributeName, value );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean compare( String dn, String attributeName, Value value ) throws LdapException
    {
        return compare( new Dn( dn ), attributeName, value );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean compare( Dn dn, String attributeName, String value ) throws LdapException
    {
        CompareRequest compareRequest = new CompareRequestImpl();
        compareRequest.setName( dn );
        compareRequest.setAttributeId( attributeName );
        compareRequest.setAssertionValue( value );

        CompareResponse compareResponse = compare( compareRequest );

        return processResponse( compareResponse );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean compare( Dn dn, String attributeName, byte[] value ) throws LdapException
    {
        CompareRequest compareRequest = new CompareRequestImpl();
        compareRequest.setName( dn );
        compareRequest.setAttributeId( attributeName );
        compareRequest.setAssertionValue( value );

        CompareResponse compareResponse = compare( compareRequest );

        return processResponse( compareResponse );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean compare( Dn dn, String attributeName, Value value ) throws LdapException
    {
        CompareRequest compareRequest = new CompareRequestImpl();
        compareRequest.setName( dn );
        compareRequest.setAttributeId( attributeName );

        if ( value.isHumanReadable() )
        {
            compareRequest.setAssertionValue( value.getString() );
        }
        else
        {
            compareRequest.setAssertionValue( value.getBytes() );
        }

        CompareResponse compareResponse = compare( compareRequest );

        return processResponse( compareResponse );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public CompareResponse compare( CompareRequest compareRequest ) throws LdapException
    {
        if ( compareRequest == null )
        {
            String msg = I18n.err( I18n.ERR_04151_CANNOT_PROCESS_NULL_COMP_REQ );

            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( msg );
            }
            
            throw new IllegalArgumentException( msg );
        }

        CompareFuture compareFuture = compareAsync( compareRequest );

        // Get the result from the future
        try
        {
            // Read the response, waiting for it if not available immediately
            // Get the response, blocking
            CompareResponse compareResponse = compareFuture.get( timeout, TimeUnit.MILLISECONDS );

            if ( compareResponse == null )
            {
                // We didn't received anything : this is an error
                if ( LOG.isErrorEnabled() )
                {
                    LOG.error( I18n.err( I18n.ERR_04112_OP_FAILED_TIMEOUT, "Compare" ) );
                }
                
                throw new LdapException( TIME_OUT_ERROR );
            }

            if ( compareResponse.getLdapResult().getResultCode() == ResultCodeEnum.SUCCESS )
            {
                // Everything is fine, return the response
                if ( LOG.isDebugEnabled() )
                { 
                    LOG.debug( I18n.msg( I18n.MSG_04114_COMPARE_SUCCESSFUL, compareResponse ) );
                }
            }
            else
            {
                // We have had an error
                if ( LOG.isDebugEnabled() )
                { 
                    LOG.debug( I18n.msg( I18n.MSG_04113_COMPARE_FAILED, compareResponse ) );
                }
            }

            return compareResponse;
        }
        catch ( Exception ie )
        {
            // Catch all other exceptions
            LOG.error( NO_RESPONSE_ERROR, ie );

            // Send an abandon request
            if ( !compareFuture.isCancelled() )
            {
                abandon( compareRequest.getMessageId() );
            }

            throw new LdapException( NO_RESPONSE_ERROR, ie );
        }
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public CompareFuture compareAsync( CompareRequest compareRequest ) throws LdapException
    {
        if ( compareRequest == null )
        {
            String msg = I18n.err( I18n.ERR_04151_CANNOT_PROCESS_NULL_COMP_REQ );

            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( msg );
            }
            
            throw new IllegalArgumentException( msg );
        }

        if ( compareRequest.getName() == null )
        {
            String msg = I18n.err( I18n.ERR_04152_CANNOT_PROCESS_NULL_DN_COMP_REQ );

            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( msg );
            }
            
            throw new IllegalArgumentException( msg );
        }

        // try to connect, if we aren't already connected.
        connect();

        checkSession();

        int newId = messageId.incrementAndGet();

        compareRequest.setMessageId( newId );

        CompareFuture compareFuture = new CompareFuture( this, newId );
        addToFutureMap( newId, compareFuture );

        // Send the request to the server
        writeRequest( compareRequest );

        // Ok, done return the future
        return compareFuture;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ExtendedResponse extended( String oid ) throws LdapException
    {
        return extended( oid, null );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ExtendedResponse extended( String oid, byte[] value ) throws LdapException
    {
        try
        {
            return extended( Oid.fromString( oid ), value );
        }
        catch ( DecoderException e )
        {
            String msg = I18n.err( I18n.ERR_04153_OID_DECODING_FAILURE, oid );
            LOG.error( msg );
            throw new LdapException( msg, e );
        }
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ExtendedResponse extended( Oid oid ) throws LdapException
    {
        return extended( oid, null );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ExtendedResponse extended( Oid oid, byte[] value ) throws LdapException
    {
        Map<String, ExtendedOperationFactory> factories = LdapApiServiceFactory.getSingleton().getExtendedRequestFactories();
        String oidStr = oid.toString();
        
        ExtendedOperationFactory factory = factories.get( oidStr );
        
        if ( factory != null )
        {
            try
            {
                if ( value == null )
                {
                    return extended( factory.newRequest() );
                }
                else
                {
                    return extended( factory.newRequest( value ) );
                }
            }
            catch ( DecoderException de )
            {
                throw new LdapNoSuchObjectException( de.getMessage() );
            }
        }
        else
        {
            return extended( new OpaqueExtendedRequest( oidStr, value ) );
        }
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ExtendedResponse extended( ExtendedRequest extendedRequest ) throws LdapException
    {
        if ( extendedRequest == null )
        {
            String msg = I18n.err( I18n.ERR_04154_CANNOT_PROCESS_NULL_EXT_REQ );

            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( msg );
            }
            
            throw new IllegalArgumentException( msg );
        }

        ExtendedFuture extendedFuture = extendedAsync( extendedRequest );

        // Get the result from the future
        try
        {
            // Read the response, waiting for it if not available immediately
            // Get the response, blocking
            ExtendedResponse response = ( ExtendedResponse ) extendedFuture
                .get( timeout, TimeUnit.MILLISECONDS );

            if ( response == null )
            {
                // We didn't received anything : this is an error
                if ( LOG.isErrorEnabled() )
                {
                    LOG.error( I18n.err( I18n.ERR_04112_OP_FAILED_TIMEOUT, "Extended" ) );
                }
                
                throw new LdapException( TIME_OUT_ERROR );
            }

            if ( response.getLdapResult().getResultCode() == ResultCodeEnum.SUCCESS )
            {
                // Everything is fine, return the response
                if ( LOG.isDebugEnabled() )
                { 
                    LOG.debug( I18n.msg( I18n.MSG_04118_EXTENDED_SUCCESSFUL, response ) );
                }
            }
            else
            {
                // We have had an error
                if ( LOG.isDebugEnabled() )
                { 
                    LOG.debug( I18n.msg( I18n.MSG_04117_EXTENDED_FAILED, response ) );
                }
            }

            // Get back the response. It's still an opaque response
            if ( Strings.isEmpty( response.getResponseName() ) )
            {
                response.setResponseName( extendedRequest.getRequestName() );
            }

            // Decode the payload now
            return response;
        }
        catch ( Exception ie )
        {
            if ( ie instanceof LdapException )
            {
                throw ( LdapException ) ie;
            }

            // Catch all other exceptions
            LOG.error( NO_RESPONSE_ERROR, ie );

            // Send an abandon request
            if ( !extendedFuture.isCancelled() )
            {
                abandon( extendedRequest.getMessageId() );
            }

            throw new LdapException( NO_RESPONSE_ERROR, ie );
        }
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ExtendedFuture extendedAsync( ExtendedRequest extendedRequest ) throws LdapException
    {
        if ( extendedRequest == null )
        {
            String msg = I18n.err( I18n.ERR_04154_CANNOT_PROCESS_NULL_EXT_REQ );

            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( msg );
            }
            
            throw new IllegalArgumentException( msg );
        }

        // try to connect, if we aren't already connected.
        connect();

        checkSession();

        int newId = messageId.incrementAndGet();

        extendedRequest.setMessageId( newId );
        ExtendedFuture extendedFuture = new ExtendedFuture( this, newId );
        extendedFuture.setExtendedRequest( extendedRequest );
        addToFutureMap( newId, extendedFuture );

        // Send the request to the server
        writeRequest( extendedRequest );

        // Ok, done return the future
        return extendedFuture;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean exists( String dn ) throws LdapException
    {
        return exists( new Dn( dn ) );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean exists( Dn dn ) throws LdapException
    {
        try
        {
            Entry entry = lookup( dn, SchemaConstants.NO_ATTRIBUTE_ARRAY );

            return entry != null;
        }
        catch ( LdapNoPermissionException lnpe )
        {
            // Special case to deal with insufficient permissions
            return false;
        }
        catch ( LdapException le )
        {
            throw le;
        }
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Entry getRootDse() throws LdapException
    {
        return lookup( Dn.ROOT_DSE, SchemaConstants.ALL_ATTRIBUTES_ARRAY );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Entry getRootDse( String... attributes ) throws LdapException
    {
        return lookup( Dn.ROOT_DSE, attributes );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Entry lookup( Dn dn ) throws LdapException
    {
        return lookup( dn, SchemaConstants.ALL_USER_ATTRIBUTES_ARRAY );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Entry lookup( String dn ) throws LdapException
    {
        return lookup( dn, SchemaConstants.ALL_USER_ATTRIBUTES_ARRAY );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Entry lookup( Dn dn, String... attributes ) throws LdapException
    {
        return lookup( dn, null, attributes );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Entry lookup( Dn dn, Control[] controls, String... attributes ) throws LdapException
    {
        Entry entry = null;

        try
        {
            SearchRequest searchRequest = new SearchRequestImpl();

            searchRequest.setBase( dn );
            searchRequest.setFilter( LdapConstants.OBJECT_CLASS_STAR );
            searchRequest.setScope( SearchScope.OBJECT );
            searchRequest.addAttributes( attributes );
            searchRequest.setDerefAliases( AliasDerefMode.DEREF_ALWAYS );

            if ( ( controls != null ) && ( controls.length > 0 ) )
            {
                searchRequest.addAllControls( controls );
            }

            try ( Cursor<Response> cursor = search( searchRequest ) )
            {
                // Read the response
                if ( cursor.next() )
                {
                    // cursor will always hold SearchResultEntry objects cause there is no ManageDsaITControl passed with search request
                    entry = ( ( SearchResultEntry ) cursor.get() ).getEntry();
                }
    
                // Pass through the SaerchResultDone, or stop
                // if we have other responses
                cursor.next();
            }
        }
        catch ( CursorException e )
        {
            throw new LdapException( e.getMessage(), e );
        }
        catch ( IOException ioe )
        {
            throw new LdapException( ioe.getMessage(), ioe );
        }

        return entry;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Entry lookup( String dn, String... attributes ) throws LdapException
    {
        return lookup( new Dn( dn ), null, attributes );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Entry lookup( String dn, Control[] controls, String... attributes ) throws LdapException
    {
        return lookup( new Dn( dn ), controls, attributes );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isControlSupported( String controlOID ) throws LdapException
    {
        return getSupportedControls().contains( controlOID );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public List<String> getSupportedControls() throws LdapException
    {
        if ( supportedControls != null )
        {
            return supportedControls;
        }

        if ( rootDse == null )
        {
            fetchRootDSE();
        }

        supportedControls = new ArrayList<>();

        Attribute attr = rootDse.get( SchemaConstants.SUPPORTED_CONTROL_AT );

        if ( attr == null )
        {
            // Unlikely. Perhaps the server does not respond properly to "+" attribute query
            // (such as 389ds server). So let's try again and let's be more explicit.
            fetchRootDSE( SchemaConstants.ALL_USER_ATTRIBUTES, 
                SchemaConstants.ALL_OPERATIONAL_ATTRIBUTES, SchemaConstants.SUPPORTED_CONTROL_AT );
            attr = rootDse.get( SchemaConstants.SUPPORTED_CONTROL_AT );
            if ( attr == null )
            {
                return supportedControls;
            }
        }
        
        for ( Value value : attr )
        {
            supportedControls.add( value.getString() );
        }

        return supportedControls;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void loadSchema() throws LdapException
    {
        loadSchema( new DefaultSchemaLoader( this ) );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void loadSchemaRelaxed() throws LdapException
    {
        loadSchema( new DefaultSchemaLoader( this, true ) );
    }


    /**
     * loads schema using the specified schema loader
     *
     * @param loader the {@link SchemaLoader} to be used to load schema
     * @throws LdapException If the schema loading failed
     */
    public void loadSchema( SchemaLoader loader ) throws LdapException
    {
        try
        {
            SchemaManager tmp = new DefaultSchemaManager( loader );

            tmp.loadAllEnabled();

            if ( !tmp.getErrors().isEmpty() && loader.isStrict() )
            {
                String msg = I18n.err( I18n.ERR_04115_ERROR_LOADING_SCHEMA );
                
                if ( LOG.isErrorEnabled() )
                {
                    LOG.error( I18n.err( I18n.ERR_05114_ERROR_MESSAGE, msg, Strings.listToString( tmp.getErrors() ) ) );
                }
                
                throw new LdapException( msg );
            }

            schemaManager = tmp;

            // Change the container's BinaryDetector
            ioSession.setAttribute( LdapDecoder.MESSAGE_CONTAINER_ATTR,
                new LdapMessageContainer<>( codec,
                    new SchemaBinaryAttributeDetector( schemaManager ) ) );

        }
        catch ( LdapException le )
        {
            throw le;
        }
        catch ( Exception e )
        {
            LOG.error( I18n.err( I18n.ERR_04116_FAIL_LOAD_SCHEMA ), e );
            throw new LdapException( e );
        }
    }


    /**
     * parses the given schema file present in OpenLDAP schema format
     * and adds all the SchemaObjects present in it to the SchemaManager
     *
     * @param schemaFile the schema file in OpenLDAP schema format
     * @throws LdapException in case of any errors while parsing
     */
    public void addSchema( File schemaFile ) throws LdapException
    {
        try
        {
            if ( schemaManager == null )
            {
                loadSchema();
            }
            
            if ( schemaManager == null )
            {
                throw new LdapException( I18n.err( I18n.ERR_04116_FAIL_LOAD_SCHEMA ) );
            }

            OpenLdapSchemaParser olsp = new OpenLdapSchemaParser();
            olsp.setQuirksMode( true );
            olsp.parse( schemaFile );

            Registries registries = schemaManager.getRegistries();

            for ( AttributeType atType : olsp.getAttributeTypes() )
            {
                registries.buildReference( atType );
                registries.getAttributeTypeRegistry().register( atType );
            }

            for ( ObjectClass oc : olsp.getObjectClasses() )
            {
                registries.buildReference( oc );
                registries.getObjectClassRegistry().register( oc );
            }

            if ( LOG.isInfoEnabled() )
            {
                LOG.info( I18n.msg( I18n.MSG_04167_SCHEMA_LOADED_SUCCESSFULLY, schemaFile.getAbsolutePath() ) );
            }
        }
        catch ( Exception e )
        {
            LOG.error( I18n.err( I18n.ERR_04117_FAIL_LOAD_SCHEMA_FILE, schemaFile.getAbsolutePath() ) );
            throw new LdapException( e );
        }
    }


    /**
     * @see #addSchema(File)
     * @param schemaFileName The schema file name to add
     * @throws LdapException If the schema addition failed
     */
    public void addSchema( String schemaFileName ) throws LdapException
    {
        addSchema( new File( schemaFileName ) );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public LdapApiService getCodecService()
    {
        return codec;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public SchemaManager getSchemaManager()
    {
        return schemaManager;
    }


    /**
     * fetches the rootDSE from the server
     * 
     * @param explicitAttributes The list of requested attributes
     * @throws LdapException If we weren't bale to fetch the RootDSE
     */
    private void fetchRootDSE( String... explicitAttributes ) throws LdapException
    {
        EntryCursor cursor = null;

        String[] attributes = explicitAttributes;
        if ( attributes.length == 0 )
        {
            attributes = new String[]
                { SchemaConstants.ALL_USER_ATTRIBUTES, SchemaConstants.ALL_OPERATIONAL_ATTRIBUTES };
        }
        
        try
        {
            cursor = search( "", LdapConstants.OBJECT_CLASS_STAR, SearchScope.OBJECT, attributes );
            if ( cursor.next() )
            {
                rootDse = cursor.get();
                // We have to call cursor.next() here, as we need to make sure that the "done" status of the cursor
                // is properly updated. Otherwise the subsequent cursor.close() initiates an ABANDON operation to
                // stop the search, which is in fact finished already.
                cursor.next();
            }
            else
            {
                throw new LdapException( I18n.err( I18n.ERR_04155_ROOT_DSE_SEARCH_FAILED ) );
            }
        }
        catch ( Exception e )
        {
            String msg = I18n.err( I18n.ERR_04156_FAILED_FETCHING_ROOT_DSE );
            LOG.error( msg );
            throw new LdapException( msg, e );
        }
        finally
        {
            if ( cursor != null )
            {
                try
                {
                    cursor.close();
                }
                catch ( Exception e )
                {
                    LOG.error( I18n.err( I18n.ERR_04114_CURSOR_CLOSE_FAIL ), e );
                }
            }
        }
    }


    /**
     * gives the configuration information of the connection
     *
     * @return the configuration of the connection
     */
    @Override
    public LdapConnectionConfig getConfig()
    {
        return config;
    }


    /**
     * removes the Objects associated with the given message ID
     * from future and response queue maps
     *
     * @param msgId id of the message
     */
    private void removeFromFutureMaps( int msgId )
    {
        getFromFutureMap( msgId );
    }


    /**
     * clears the async listener, responseQueue and future mapppings to the corresponding request IDs
     */
    private void clearMaps()
    {
        futureMap.clear();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isRequestCompleted( int messageId )
    {
        ResponseFuture<?> responseFuture = futureMap.get( messageId );
        
        return responseFuture == null;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean doesFutureExistFor( int messageId )
    {
        ResponseFuture<?> responseFuture = futureMap.get( messageId );
        return responseFuture != null;
    }


    /**
     * Adds the connection closed event listener.
     *
     * @param ccListener the connection closed listener
     */
    public void addConnectionClosedEventListener( ConnectionClosedEventListener ccListener )
    {
        if ( conCloseListeners == null )
        {
            conCloseListeners = new ArrayList<>();
        }

        conCloseListeners.add( ccListener );
    }
    
    
    /**
     * {@inheritDoc}
     */
    @Override
    public void inputClosed( IoSession session ) throws Exception 
    {
        session.closeNow();
    }


    /**
     * This method is called when a new session is created. We will store some
     * informations that the session will need to process incoming requests.
     * 
     * @param session the newly created session
     */
    @Override
    public void sessionCreated( IoSession session ) throws Exception
    {
        // Last, store the message container
        LdapMessageContainer<Message> ldapMessageContainer =
            new LdapMessageContainer<>(
                codec, config.getBinaryAttributeDetector() );

        session.setAttribute( LdapDecoder.MESSAGE_CONTAINER_ATTR, ldapMessageContainer );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void sessionClosed( IoSession session ) throws Exception
    {
        authenticated.set( false );
        
        // Close all the Future for this session
        for ( ResponseFuture<? extends Response> responseFuture : futureMap.values() )
        {
            responseFuture.cancel();
        }

        // clear the mappings
        clearMaps();

        // Last, not least, reset the MessageId value
        messageId.set( 0 );

        connectorMutex.lock();

        try
        {
            if ( connector != null )
            {
                connector.dispose();
                connector = null;
            }
        }
        finally
        {
            connectorMutex.unlock();
        }

        if ( conCloseListeners != null )
        {
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.msg( I18n.MSG_04136_NOTIFYING_CLOSE_LISTENERS ) );
            }

            for ( ConnectionClosedEventListener listener : conCloseListeners )
            {
                listener.connectionClosed();
            }
        }
        
        connectionCloseFuture.complete( 0 );
    }


    /**
     * Sends the StartTLS extended request to server and adds a security layer
     * upon receiving a response with successful result. Note that we will use
     * the default LDAP connection.
     *
     * @throws LdapException If the StartTLS operation failed
     */
    public void startTls() throws LdapException
    {
        try
        {
            if ( config.isUseSsl() )
            {
                throw new LdapException( I18n.err( I18n.ERR_04157_CANNOT_USE_TLS_WITH_SSL_FLAG ) );
            }

            // try to connect, if we aren't already connected.
            connect();

            checkSession();
            
            if ( ioSession.isSecured() )
            {
                if ( LOG.isDebugEnabled() )
                { 
                    LOG.debug( I18n.msg( I18n.MSG_04121_LDAP_ALREADY_USING_START_TLS ) );
                }
                
                return;
            }

            ExtendedResponse resp = extended( new StartTlsRequestImpl() );
            LdapResult result = resp.getLdapResult();

            if ( result.getResultCode() == ResultCodeEnum.SUCCESS )
            {
                addSslFilter();
            }
            else
            {
                throw new LdapOperationException( result.getResultCode(), result.getDiagnosticMessage() );
            }
        }
        catch ( LdapException e )
        {
            throw e;
        }
        catch ( Exception e )
        {
            throw new LdapException( e );
        }
    }


    /**
     * Adds a {@link SaslFilter} to the session's filter chain.
     * 
     * @param saslClient The initialized SASL client
     * 
     * @throws LdapException
     */
    private void addSaslFilter( SaslClient saslClient ) throws LdapException
    {
        IoFilterChain filterChain = ioSession.getFilterChain();
        if ( filterChain.contains( SASL_FILTER_KEY ) )
        {
            filterChain.remove( SASL_FILTER_KEY );
        }

        SaslFilter saslFilter = new SaslFilter( saslClient );
        filterChain.addBefore( LDAP_CODEC_FILTER_KEY, SASL_FILTER_KEY, saslFilter );
    }


    /**
     * Adds {@link SslFilter} to the IOConnector or IOSession's filter chain
     * 
     * @throws LdapException If the SSL filter addition failed
     */
    private void addSslFilter() throws LdapException
    {
        try
        {
            SSLContext sslContext = SSLContext.getInstance( config.getSslProtocol() );
            
            sslContext.init( config.getKeyManagers(), config.getTrustManagers(), config.getSecureRandom() );

            SslFilter sslFilter = new SslFilter( sslContext );
            sslFilter.setUseClientMode( true );

            // Configure the enabled cipher lists
            String[] enabledCipherSuite = config.getEnabledCipherSuites();

            if ( ( enabledCipherSuite != null ) && ( enabledCipherSuite.length != 0 ) )
            {
                sslFilter.setEnabledCipherSuites( enabledCipherSuite );
            }

            // Be sure we disable SSLV3
            String[] enabledProtocols = config.getEnabledProtocols();

            if ( ( enabledProtocols != null ) && ( enabledProtocols.length != 0 ) )
            {
                sslFilter.setEnabledProtocols( enabledProtocols );
            }
            else
            {
                // Default to TLS
                sslFilter.setEnabledProtocols( new String[]
                    { "TLSv1", "TLSv1.1", "TLSv1.2" } );
            }

            // for LDAPS/TLS
            handshakeFuture = new HandshakeFuture();
            
            if ( ( ioSession == null ) || !isConnected() )
            {
                connector.getFilterChain().addFirst( SSL_FILTER_KEY, sslFilter );
            }
            else
            // for StartTLS
            {
                ioSession.getFilterChain().addFirst( SSL_FILTER_KEY, sslFilter );
                
                boolean isSecured = handshakeFuture.get( timeout, TimeUnit.MILLISECONDS );
                
                if ( !isSecured )
                {
                    Throwable cause = ( Throwable ) ioSession.getAttribute( EXCEPTION_KEY );
                    throw new LdapTlsHandshakeException( I18n.err( I18n.ERR_04120_TLS_HANDSHAKE_ERROR ), cause );
                }
            }
        }
        catch ( Exception e )
        {
            if ( e instanceof LdapException )
            {
                throw ( LdapException ) e;
            }

            String msg = I18n.err( I18n.ERR_04122_SSL_CONTEXT_INIT_FAILURE );
            LOG.error( msg, e );
            throw new LdapException( msg, e );
        }
    }


    /**
     * Process the SASL Bind. It's a dialog with the server, we will send a first BindRequest, receive
     * a response and the, if this response is a challenge, continue by sending a new BindRequest with
     * the requested informations.
     *
     * @param saslRequest The SASL request object containing all the needed parameters
     * @return A {@link BindResponse} containing the result
     * @throws LdapException if some error occurred
     */
    public BindFuture bindSasl( SaslRequest saslRequest ) throws LdapException
    {
        // First switch to anonymous state
        authenticated.set( false );

        // try to connect, if we aren't already connected.
        connect();

        // If the session has not been establish, or is closed, we get out immediately
        checkSession();

        BindRequest bindRequest = createBindRequest( ( String ) null, null,
            saslRequest.getSaslMechanism(), saslRequest.getControls() );

        // Update the messageId
        int newId = messageId.incrementAndGet();
        bindRequest.setMessageId( newId );

        if ( LOG.isDebugEnabled() )
        {
            LOG.debug( I18n.msg( I18n.MSG_04104_SENDING_REQUEST, bindRequest ) );
        }

        // Create a future for this Bind operation
        BindFuture bindFuture = new BindFuture( this, newId );

        // Store it in the future Map
        addToFutureMap( newId, bindFuture );

        try
        {
            BindResponse bindResponse;
            byte[] response;
            ResultCodeEnum result;

            // Creating a map for SASL properties
            Map<String, Object> properties = new HashMap<>();

            // Quality of Protection SASL property
            if ( saslRequest.getQualityOfProtection() != null )
            {
                properties.put( Sasl.QOP, saslRequest.getQualityOfProtection().getValue() );
            }

            // Security Strength SASL property
            if ( saslRequest.getSecurityStrength() != null )
            {
                properties.put( Sasl.STRENGTH, saslRequest.getSecurityStrength().getValue() );
            }

            // Mutual Authentication SASL property
            if ( saslRequest.isMutualAuthentication() )
            {
                properties.put( Sasl.SERVER_AUTH, "true" );
            }

            // Creating a SASL Client
            SaslClient sc = Sasl.createSaslClient(
                new String[]
                    { bindRequest.getSaslMechanism() },
                saslRequest.getAuthorizationId(),
                "ldap",
                config.getLdapHost(),
                properties,
                new SaslCallbackHandler( saslRequest ) );

            // If the SaslClient wasn't created, that means we can't create the SASL client
            // for the requested mechanism. We then produce an Exception
            if ( sc == null )
            {
                String message = I18n.err( I18n.ERR_04158_CANNOT_FIND_SASL_FACTORY_FOR_MECH, bindRequest.getSaslMechanism() );
                LOG.error( message );
                throw new LdapException( message );
            }

            // Corner case : the SASL mech might send an initial challenge, and we have to
            // deal with it immediately.
            if ( sc.hasInitialResponse() )
            {
                byte[] challengeResponse = sc.evaluateChallenge( Strings.EMPTY_BYTES );

                // Stores the challenge's response, and send it to the server
                bindRequest.setCredentials( challengeResponse );
                writeRequest( bindRequest );

                // Get the server's response, blocking
                bindResponse = bindFuture.get( timeout, TimeUnit.MILLISECONDS );

                if ( bindResponse == null )
                {
                    // We didn't received anything : this is an error
                    if ( LOG.isErrorEnabled() )
                    { 
                        LOG.error( I18n.err( I18n.ERR_04112_OP_FAILED_TIMEOUT, "Bind" ) );
                    }
                    
                    throw new LdapException( TIME_OUT_ERROR );
                }

                result = bindResponse.getLdapResult().getResultCode();
            }
            else
            {
                // Copy the bindRequest without setting the credentials
                BindRequest bindRequestCopy = new BindRequestImpl();
                bindRequestCopy.setMessageId( newId );

                bindRequestCopy.setName( bindRequest.getName() );
                bindRequestCopy.setSaslMechanism( bindRequest.getSaslMechanism() );
                bindRequestCopy.setSimple( bindRequest.isSimple() );
                bindRequestCopy.setVersion3( bindRequest.getVersion3() );
                bindRequestCopy.addAllControls( bindRequest.getControls().values().toArray( new Control[0] ) );

                writeRequest( bindRequestCopy );

                bindResponse = bindFuture.get( timeout, TimeUnit.MILLISECONDS );

                if ( bindResponse == null )
                {
                    // We didn't received anything : this is an error
                    if ( LOG.isErrorEnabled() )
                    {
                        LOG.error( I18n.err( I18n.ERR_04112_OP_FAILED_TIMEOUT, "Bind" ) );
                    }
                    
                    throw new LdapException( TIME_OUT_ERROR );
                }

                result = bindResponse.getLdapResult().getResultCode();
            }

            while ( !sc.isComplete()
                && ( ( result == ResultCodeEnum.SASL_BIND_IN_PROGRESS ) || ( result == ResultCodeEnum.SUCCESS ) ) )
            {
                response = sc.evaluateChallenge( bindResponse.getServerSaslCreds() );

                if ( result == ResultCodeEnum.SUCCESS )
                {
                    if ( response != null )
                    {
                        throw new LdapException( I18n.err( I18n.ERR_04159_PROTOCOL_ERROR ) );
                    }
                }
                else
                {
                    newId = messageId.incrementAndGet();
                    bindRequest.setMessageId( newId );
                    bindRequest.setCredentials( response );

                    addToFutureMap( newId, bindFuture );

                    writeRequest( bindRequest );

                    bindResponse = bindFuture.get( timeout, TimeUnit.MILLISECONDS );

                    if ( bindResponse == null )
                    {
                        // We didn't received anything : this is an error
                        if ( LOG.isErrorEnabled() )
                        {
                            LOG.error( I18n.err( I18n.ERR_04112_OP_FAILED_TIMEOUT, "Bind" ) );
                        }
                        
                        throw new LdapException( TIME_OUT_ERROR );
                    }

                    result = bindResponse.getLdapResult().getResultCode();
                }
            }

            /*
             * Install the SASL filter when the SASL auth is complete.
             * This adds the security layer if it was negotiated.
             */
            if ( sc.isComplete() )
            {
                addSaslFilter( sc );
            }

            bindFuture.set( bindResponse );

            return bindFuture;
        }
        catch ( LdapException e )
        {
            throw e;
        }
        catch ( Exception e )
        {
            LOG.error( e.getMessage() );
            throw new LdapException( e );
        }
    }


    /**
     * A reusable code block to be used in various bind methods
     * 
     * @param request The request to send
     * @throws LdapException If the request was ot properly sent
     */
    private void writeRequest( Request request ) throws LdapException
    {
        // Send the request to the server
        WriteFuture writeFuture = ioSession.write( request );

        long localTimeout = timeout;

        while ( localTimeout > 0 )
        {
            // Wait only 100 ms
            boolean done = writeFuture.awaitUninterruptibly( 100 );

            if ( done )
            {
                return;
            }

            // Wait for the message to be sent to the server
            if ( !ioSession.isConnected() )
            {
                // We didn't received anything : this is an error
                if ( LOG.isErrorEnabled() )
                {
                    LOG.error( I18n.err( I18n.ERR_04118_SOMETHING_WRONG_HAPPENED ) );
                }

                Exception exception = ( Exception ) ioSession.removeAttribute( EXCEPTION_KEY );

                if ( exception instanceof LdapException )
                {
                    throw ( LdapException ) exception;
                }
                else if ( exception != null )
                {
                    throw new InvalidConnectionException( exception.getMessage(), exception );
                }

                throw new InvalidConnectionException( I18n.err( I18n.ERR_04160_SESSION_HAS_BEEN_CLOSED ) );
            }

            localTimeout -= 100;
        }

        if ( LOG.isErrorEnabled() )
        {
            LOG.error( I18n.err( I18n.ERR_04119_TIMEOUT ) );
        }
        
        throw new LdapException( TIME_OUT_ERROR );
    }


    /**
     * method to write the kerberos config in the standard MIT kerberos format
     *
     * This is required cause the JGSS api is not able to recognize the port value set
     * in the system property java.security.krb5.kdc this issue makes it impossible
     * to set a kdc running non standard ports (other than 88)
     *
     * e.g localhost:6088
     *
     * <pre>
     * [libdefaults]
     *     default_realm = EXAMPLE.COM
     *
     * [realms]
     *     EXAMPLE.COM = {
     *         kdc = localhost:6088
     *     }
     * </pre>
     *
     * @param realmName The realm name
     * @param kdcHost The Kerberos server host
     * @param kdcPort The Kerberos server port
     * @return the full path of the config file
     * @throws IOException If the config file cannot be created
     */
    private String createKrb5ConfFile( String realmName, String kdcHost, int kdcPort ) throws IOException
    {
        StringBuilder sb = new StringBuilder();

        sb.append( "[libdefaults]" )
            .append( "\n\t" );
        sb.append( "default_realm = " )
            .append( realmName )
            .append( "\n" );

        sb.append( "[realms]" )
            .append( "\n\t" );

        sb.append( realmName )
            .append( " = {" )
            .append( "\n\t\t" );
        sb.append( "kdc = " )
            .append( kdcHost )
            .append( ":" )
            .append( kdcPort )
            .append( "\n\t}\n" );

        File krb5Conf = Files.createTempFile( "client-api-krb5", ".conf" ).toFile();
        krb5Conf.deleteOnExit();

        try ( Writer writer = new OutputStreamWriter( Files.newOutputStream( Paths.get( krb5Conf.getPath() ) ), 
            Charset.defaultCharset() ) )
        {
            writer.write( sb.toString() );
        }

        String krb5ConfPath = krb5Conf.getAbsolutePath();

        if ( LOG.isDebugEnabled() )
        {
            LOG.debug( I18n.msg( I18n.MSG_04135_KRB5_FILE_CREATED, krb5ConfPath ) );
        }

        return krb5ConfPath;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public BinaryAttributeDetector getBinaryAttributeDetector()
    {
        if ( config != null )
        {
            return config.getBinaryAttributeDetector();
        }
        else
        {
            return null;
        }
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setBinaryAttributeDetector( BinaryAttributeDetector binaryAttributeDetector )
    {
        if ( config != null )
        {
            config.setBinaryAttributeDetector( binaryAttributeDetector );
        }
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setSchemaManager( SchemaManager schemaManager )
    {
        this.schemaManager = schemaManager;
    }


    /**
     * @return the socketSessionConfig
     */
    public SocketSessionConfig getSocketSessionConfig()
    {
        return socketSessionConfig;
    }


    /**
     * @param socketSessionConfig the socketSessionConfig to set
     */
    public void setSocketSessionConfig( SocketSessionConfig socketSessionConfig )
    {
        this.socketSessionConfig = socketSessionConfig;
    }
    
    
    /**
     * {@inheritDoc}
     */
    @Override
    public void event( IoSession session, FilterEvent event ) throws Exception 
    {
        // Check if it's a SSLevent 
        if ( ( event instanceof SslEvent ) && ( ( SslEvent ) event == SslEvent.SECURED ) )
        {
            handshakeFuture.secured();
        }
    }
}
