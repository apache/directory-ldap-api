/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
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
import java.io.FileWriter;
import java.io.IOException;
import java.net.ConnectException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.channels.UnresolvedAddressException;
import java.security.PrivilegedExceptionAction;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.ReentrantLock;

import javax.net.ssl.SSLContext;
import javax.security.auth.Subject;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.util.Oid;
import org.apache.directory.api.ldap.codec.api.BinaryAttributeDetector;
import org.apache.directory.api.ldap.codec.api.DefaultConfigurableBinaryAttributeDetector;
import org.apache.directory.api.ldap.codec.api.ExtendedResponseDecorator;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.codec.api.LdapApiServiceFactory;
import org.apache.directory.api.ldap.codec.api.LdapDecoder;
import org.apache.directory.api.ldap.codec.api.LdapMessageContainer;
import org.apache.directory.api.ldap.codec.api.MessageDecorator;
import org.apache.directory.api.ldap.codec.api.MessageEncoderException;
import org.apache.directory.api.ldap.codec.api.SchemaBinaryAttributeDetector;
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
import org.apache.directory.api.ldap.model.exception.LdapOperationException;
import org.apache.directory.api.ldap.model.exception.LdapOtherException;
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
import org.apache.directory.api.ldap.model.message.IntermediateResponseImpl;
import org.apache.directory.api.ldap.model.message.LdapResult;
import org.apache.directory.api.ldap.model.message.Message;
import org.apache.directory.api.ldap.model.message.ModifyDnRequest;
import org.apache.directory.api.ldap.model.message.ModifyDnRequestImpl;
import org.apache.directory.api.ldap.model.message.ModifyDnResponse;
import org.apache.directory.api.ldap.model.message.ModifyRequest;
import org.apache.directory.api.ldap.model.message.ModifyRequestImpl;
import org.apache.directory.api.ldap.model.message.ModifyResponse;
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
import org.apache.directory.api.util.StringConstants;
import org.apache.directory.api.util.Strings;
import org.apache.directory.ldap.client.api.callback.SaslCallbackHandler;
import org.apache.directory.ldap.client.api.exception.InvalidConnectionException;
import org.apache.directory.ldap.client.api.future.AddFuture;
import org.apache.directory.ldap.client.api.future.BindFuture;
import org.apache.directory.ldap.client.api.future.CompareFuture;
import org.apache.directory.ldap.client.api.future.DeleteFuture;
import org.apache.directory.ldap.client.api.future.ExtendedFuture;
import org.apache.directory.ldap.client.api.future.ModifyDnFuture;
import org.apache.directory.ldap.client.api.future.ModifyFuture;
import org.apache.directory.ldap.client.api.future.ResponseFuture;
import org.apache.directory.ldap.client.api.future.SearchFuture;
import org.apache.mina.core.filterchain.IoFilter;
import org.apache.mina.core.future.CloseFuture;
import org.apache.mina.core.future.ConnectFuture;
import org.apache.mina.core.future.IoFuture;
import org.apache.mina.core.future.IoFutureListener;
import org.apache.mina.core.future.WriteFuture;
import org.apache.mina.core.service.IoConnector;
import org.apache.mina.core.session.IoSession;
import org.apache.mina.filter.codec.ProtocolCodecFilter;
import org.apache.mina.filter.codec.ProtocolEncoderException;
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

    /** The connector open with the remote server */
    private IoConnector connector;

    /** A mutex used to avoid a double close of the connector */
    private ReentrantLock connectorMutex = new ReentrantLock();

    /**
     * The created session, created when we open a connection with
     * the Ldap server.
     */
    private IoSession ldapSession;

    /** a map to hold the ResponseFutures for all operations */
    private Map<Integer, ResponseFuture<? extends Response>> futureMap = new ConcurrentHashMap<Integer, ResponseFuture<? extends Response>>();

    /** list of controls supported by the server */
    private List<String> supportedControls;

    /** The ROOT DSE entry */
    private Entry rootDse;

    /** A flag indicating that the BindRequest has been issued and successfully authenticated the user */
    private AtomicBoolean authenticated = new AtomicBoolean( false );

    /** A flag indicating that the connection is connected or not */
    private AtomicBoolean connected = new AtomicBoolean( false );

    /** a list of listeners interested in getting notified when the
     *  connection's session gets closed cause of network issues
     */
    private List<ConnectionClosedEventListener> conCloseListeners;

    /** The Ldap codec protocol filter */
    private IoFilter ldapProtocolFilter = new ProtocolCodecFilter( codec.getProtocolCodecFactory() );

    /** the SslFilter key */
    private static final String SSL_FILTER_KEY = "sslFilter";

    /** The exception stored in the session if we've got one */
    private static final String EXCEPTION_KEY = "sessionException";

    // ~~~~~~~~~~~~~~~~~ common error messages ~~~~~~~~~~~~~~~~~~~~~~~~~~

    static final String TIME_OUT_ERROR = "TimeOut occurred";

    static final String NO_RESPONSE_ERROR = "The response queue has been emptied, no response was found.";


    //--------------------------- Helper methods ---------------------------//
    /**
     * {@inheritDoc}
     */
    public boolean isConnected()
    {
        return ( ldapSession != null ) && connected.get() && !ldapSession.isClosing();
    }


    /**
     * {@inheritDoc}
     */
    public boolean isAuthenticated()
    {
        return isConnected() && authenticated.get();
    }


    /**
     * Check that a session is valid, ie we can send requests to the
     * server
     *
     * @throws Exception If the session is not valid
     */
    private void checkSession() throws InvalidConnectionException
    {
        if ( ldapSession == null )
        {
            throw new InvalidConnectionException( "Cannot connect on the server, the connection is null" );
        }

        if ( !connected.get() )
        {
            throw new InvalidConnectionException( "Cannot connect on the server, the connection is invalid" );
        }
    }


    private void addToFutureMap( int messageId, ResponseFuture<? extends Response> future )
    {
        LOG.debug( "Adding <" + messageId + ", " + future.getClass().getName() + ">" );
        futureMap.put( messageId, future );
    }


    private ResponseFuture<? extends Response> getFromFutureMap( int messageId )
    {
        ResponseFuture<? extends Response> future = futureMap.remove( messageId );

        if ( future != null )
        {
            LOG.debug( "Removing <" + messageId + ", " + future.getClass().getName() + ">" );
        }

        return future;
    }


    private ResponseFuture<? extends Response> peekFromFutureMap( int messageId )
    {
        ResponseFuture<? extends Response> future = futureMap.get( messageId );

        // future can be null if there was a abandon operation on that messageId
        if ( future != null )
        {
            LOG.debug( "Getting <" + messageId + ", " + future.getClass().getName() + ">" );
        }

        return future;
    }


    /**
     * Get the largest timeout from the search time limit and the connection
     * timeout.
     */
    static long getTimeout( long connectionTimoutInMS, int searchTimeLimitInSeconds )
    {
        if ( searchTimeLimitInSeconds < 0 )
        {
            return connectionTimoutInMS;
        }
        else if ( searchTimeLimitInSeconds == 0 )
        {
            return Long.MAX_VALUE;
        }
        else
        {
            long searchTimeLimitInMS = searchTimeLimitInSeconds * 1000L;
            return Math.max( searchTimeLimitInMS, connectionTimoutInMS );
        }
    }


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


    public LdapNetworkConnection( LdapConnectionConfig config, LdapApiService ldapApiService )
    {
        super( ldapApiService );
        this.config = config;

        if ( config.getBinaryAttributeDetector() == null )
        {
            config.setBinaryAttributeDetector( new DefaultConfigurableBinaryAttributeDetector() );
        }
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
            config.setLdapHost( "localhost" );
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
     */
    private void createConnector() throws LdapException
    {
        // Use only one thread inside the connector
        connector = new NioSocketConnector( 1 );

        ( ( SocketSessionConfig ) connector.getSessionConfig() ).setReuseAddress( true );

        // Add the codec to the chain
        connector.getFilterChain().addLast( "ldapCodec", ldapProtocolFilter );

        // If we use SSL, we have to add the SslFilter to the chain
        if ( config.isUseSsl() )
        {
            addSslFilter();
        }

        // Inject the protocolHandler
        connector.setHandler( this );
    }


    //-------------------------- The methods ---------------------------//
    /**
     * {@inheritDoc}
     */
    public boolean connect() throws LdapException
    {
        if ( ( ldapSession != null ) && connected.get() )
        {
            // No need to connect if we already have a connected session
            return true;
        }

        // Create the connector if needed
        if ( connector == null )
        {
            createConnector();
        }

        // Build the connection address
        SocketAddress address = new InetSocketAddress( config.getLdapHost(), config.getLdapPort() );

        // And create the connection future
        timeout = config.getTimeout();
        long maxRetry = System.currentTimeMillis() + timeout;
        ConnectFuture connectionFuture = null;

        while ( maxRetry > System.currentTimeMillis() )
        {
            connectionFuture = connector.connect( address );

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
                LOG.debug( "Interrupted while waiting for connection to establish with server {}:{}",
                    config.getLdapHost(),
                    config.getLdapPort(), e );
                throw new LdapOtherException( e.getMessage(), e );
            }
            finally
            {
                if ( result )
                {
                    boolean isConnected = connectionFuture.isConnected();

                    if ( !isConnected )
                    {
                        if ( connectionFuture.getException() instanceof ConnectException )
                        {
                            // No need to wait
                            // We know that there was a permanent error such as "connection refused".
                            LOG.debug( "------>> Connection error: {}", connectionFuture.getException().getMessage() );
                            break;
                        }

                        LOG.debug( "------>>   Cannot get the connection... Retrying" );

                        // Wait 500 ms and retry
                        try
                        {
                            Thread.sleep( 500 );
                        }
                        catch ( InterruptedException e )
                        {
                            connector = null;
                            LOG.debug( "Interrupted while waiting for connection to establish with server {}:{}",
                                config.getLdapHost(),
                                config.getLdapPort(), e );
                            throw new LdapOtherException( e.getMessage(), e );
                        }
                    }
                    else
                    {
                        break;
                    }
                }
            }
        }

        if ( connectionFuture == null )
        {
            connector.dispose();
            throw new InvalidConnectionException( "Cannot connect" );
        }

        boolean isConnected = connectionFuture.isConnected();

        if ( !isConnected )
        {
            // disposing connector if not connected
            try
            {
                close();
            }
            catch ( IOException ioe )
            {
                // Nothing to do
            }

            Throwable e = connectionFuture.getException();

            if ( e != null )
            {
                StringBuilder message = new StringBuilder( "Cannot connect to the server: " );

                // Special case for UnresolvedAddressException
                // (most of the time no message is associated with this exception)
                if ( ( e instanceof UnresolvedAddressException ) && ( e.getMessage() == null ) )
                {
                    message.append( "Hostname '" );
                    message.append( config.getLdapHost() );
                    message.append( "' could not be resolved." );
                    throw new InvalidConnectionException( message.toString(), e );
                }

                // Default case
                message.append( e.getMessage() );
                throw new InvalidConnectionException( message.toString(), e );
            }

            return false;
        }

        // Get the close future for this session
        CloseFuture closeFuture = connectionFuture.getSession().getCloseFuture();

        // Add a listener to close the session in the session.
        closeFuture.addListener( new IoFutureListener<IoFuture>()
        {
            public void operationComplete( IoFuture future )
            {
                // Process all the waiting operations and cancel them
                LOG.debug( "received a NoD, closing everything" );

                for ( int messageId : futureMap.keySet() )
                {
                    ResponseFuture<?> responseFuture = futureMap.get( messageId );
                    LOG.debug( "closing {}", responseFuture );

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
                    catch ( ExecutionException e )
                    {
                        LOG.error( "Error while processing the NoD for {}", responseFuture );
                    }
                    catch ( InterruptedException e )
                    {
                        LOG.error( "Error while processing the NoD for {}", responseFuture );
                    }

                    futureMap.remove( messageId );
                }

                futureMap.clear();
            }
        } );

        // Get back the session
        ldapSession = connectionFuture.getSession();
        connected.set( true );

        // Store the container into the session if we don't have one
        @SuppressWarnings("unchecked")
        LdapMessageContainer<MessageDecorator<? extends Message>> container =
            ( LdapMessageContainer<MessageDecorator<? extends Message>> ) ldapSession
                .getAttribute( LdapDecoder.MESSAGE_CONTAINER_ATTR );

        if ( container != null )
        {
            if ( schemaManager != null )
            {
                if ( !( container.getBinaryAttributeDetector() instanceof SchemaBinaryAttributeDetector ) )
                {
                    container.setBinaryAttributeDetector( new SchemaBinaryAttributeDetector( schemaManager ) );
                }
            }
        }
        else
        {
            BinaryAttributeDetector atDetector = new DefaultConfigurableBinaryAttributeDetector();

            if ( schemaManager != null )
            {
                atDetector = new SchemaBinaryAttributeDetector( schemaManager );
            }

            ldapSession.setAttribute( LdapDecoder.MESSAGE_CONTAINER_ATTR,
                new LdapMessageContainer<MessageDecorator<? extends Message>>( codec, atDetector ) );
        }

        // Initialize the MessageId
        messageId.set( 0 );

        // And return
        return true;
    }


    /**
     * {@inheritDoc}
     */
    public void close() throws IOException
    {
        // Close the session
        if ( ( ldapSession != null ) && connected.get() )
        {
            ldapSession.close( true );
            connected.set( false );
        }

        // And close the connector if it has been created locally
        // Release the connector
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

        // Reset the messageId
        messageId.set( 0 );
    }


    //------------------------ The LDAP operations ------------------------//
    // Add operations                                                      //
    //---------------------------------------------------------------------//
    /**
     * {@inheritDoc}
     */
    public void add( Entry entry ) throws LdapException
    {
        if ( entry == null )
        {
            String msg = "Cannot add an empty entry";
            LOG.debug( msg );
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
    public AddFuture addAsync( Entry entry ) throws LdapException
    {
        if ( entry == null )
        {
            String msg = "Cannot add null entry";
            LOG.debug( msg );
            throw new IllegalArgumentException( msg );
        }

        AddRequest addRequest = new AddRequestImpl();
        addRequest.setEntry( entry );

        return addAsync( addRequest );
    }


    /**
     * {@inheritDoc}
     */
    public AddResponse add( AddRequest addRequest ) throws LdapException
    {
        if ( addRequest == null )
        {
            String msg = "Cannot process a null addRequest";
            LOG.debug( msg );
            throw new IllegalArgumentException( msg );
        }

        if ( addRequest.getEntry() == null )
        {
            String msg = "Cannot add a null entry";
            LOG.debug( msg );
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
                LOG.error( "Add failed : timeout occurred" );
                throw new LdapException( TIME_OUT_ERROR );
            }

            if ( addResponse.getLdapResult().getResultCode() == ResultCodeEnum.SUCCESS )
            {
                // Everything is fine, return the response
                LOG.debug( "Add successful : {}", addResponse );
            }
            else
            {
                // We have had an error
                LOG.debug( "Add failed : {}", addResponse );
            }

            return addResponse;
        }
        catch ( TimeoutException te )
        {
            // Send an abandon request
            if ( !addFuture.isCancelled() )
            {
                abandon( addRequest.getMessageId() );
            }

            // We didn't received anything : this is an error
            LOG.error( "Add failed : timeout occurred" );
            throw new LdapException( TIME_OUT_ERROR, te );
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
    public AddFuture addAsync( AddRequest addRequest ) throws LdapException
    {
        if ( addRequest == null )
        {
            String msg = "Cannot process a null addRequest";
            LOG.debug( msg );
            throw new IllegalArgumentException( msg );
        }

        if ( addRequest.getEntry() == null )
        {
            String msg = "Cannot add a null entry";
            LOG.debug( msg );
            throw new IllegalArgumentException( msg );
        }

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
    public void abandon( int messageId )
    {
        if ( messageId < 0 )
        {
            String msg = "Cannot abandon a negative message ID";
            LOG.debug( msg );
            throw new IllegalArgumentException( msg );
        }

        AbandonRequest abandonRequest = new AbandonRequestImpl();
        abandonRequest.setAbandoned( messageId );

        abandonInternal( abandonRequest );
    }


    /**
     * {@inheritDoc}
     */
    public void abandon( AbandonRequest abandonRequest )
    {
        if ( abandonRequest == null )
        {
            String msg = "Cannot process a null abandonRequest";
            LOG.debug( msg );
            throw new IllegalArgumentException( msg );
        }

        abandonInternal( abandonRequest );
    }


    /**
     * Internal AbandonRequest handling
     */
    private void abandonInternal( AbandonRequest abandonRequest )
    {
        LOG.debug( "Sending request \n{}", abandonRequest );

        int newId = messageId.incrementAndGet();
        abandonRequest.setMessageId( newId );

        // Send the request to the server
        ldapSession.write( abandonRequest );

        // remove the associated listener if any
        int abandonId = abandonRequest.getAbandoned();

        ResponseFuture<? extends Response> rf = getFromFutureMap( abandonId );

        // if the listener is not null, this is a async operation and no need to
        // send cancel signal on future, sending so will leave a dangling poision object in the corresponding queue
        // this is a sync operation send cancel signal to the corresponding ResponseFuture
        if ( rf != null )
        {
            LOG.debug( "sending cancel signal to future" );
            rf.cancel( true );
        }
        else
        {
            // this shouldn't happen
            LOG
                .warn(
                    "There is no future associated with operation message ID {}, the operation has been completed.",
                    abandonId );
        }
    }


    /**
     * {@inheritDoc}
     */
    public void bind() throws LdapException
    {
        LOG.debug( "Bind request" );

        // Create the BindRequest
        BindRequest bindRequest = createBindRequest( config.getName(), Strings.getBytesUtf8( config.getCredentials() ) );

        BindResponse bindResponse = bind( bindRequest );

        processResponse( bindResponse );
    }


    /**
     * {@inheritDoc}
     */
    public void anonymousBind() throws LdapException
    {
        LOG.debug( "Anonymous Bind request" );

        // Create the BindRequest
        BindRequest bindRequest = createBindRequest( StringConstants.EMPTY, StringConstants.EMPTY_BYTES );

        BindResponse bindResponse = bind( bindRequest );

        processResponse( bindResponse );
    }


    /**
     * {@inheritDoc}
     */
    public BindFuture bindAsync() throws LdapException
    {
        LOG.debug( "Asynchronous Bind request" );

        // Create the BindRequest
        BindRequest bindRequest = createBindRequest( config.getName(), Strings.getBytesUtf8( config.getCredentials() ) );

        return bindAsync( bindRequest );
    }


    /**
     * {@inheritDoc}
     */
    public BindFuture anonymousBindAsync() throws LdapException
    {
        LOG.debug( "Anonymous asynchronous Bind request" );

        // Create the BindRequest
        BindRequest bindRequest = createBindRequest( StringConstants.EMPTY, StringConstants.EMPTY_BYTES );

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
        LOG.debug( "Bind request : {}", name );

        // Create the BindRequest
        BindRequest bindRequest = createBindRequest( name, StringConstants.EMPTY_BYTES );

        return bindAsync( bindRequest );
    }


    /**
     * {@inheritDoc}
     */
    public BindFuture bindAsync( String name, String credentials ) throws LdapException
    {
        LOG.debug( "Bind request : {}", name );

        // The password must not be empty or null
        if ( Strings.isEmpty( credentials ) && Strings.isNotEmpty( name ) )
        {
            LOG.debug( "The password is missing" );
            throw new LdapAuthenticationException( "The password is missing" );
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
        LOG.debug( "Bind request : {}", name );

        // Create the BindRequest
        BindRequest bindRequest = createBindRequest( name, StringConstants.EMPTY_BYTES );

        return bindAsync( bindRequest );
    }


    /**
     * {@inheritDoc}
     */
    public BindFuture bindAsync( Dn name, String credentials ) throws LdapException
    {
        LOG.debug( "Bind request : {}", name );

        // The password must not be empty or null
        if ( Strings.isEmpty( credentials ) && ( !Dn.EMPTY_DN.equals( name ) ) )
        {
            LOG.debug( "The password is missing" );
            throw new LdapAuthenticationException( "The password is missing" );
        }

        // Create the BindRequest
        BindRequest bindRequest = createBindRequest( name, Strings.getBytesUtf8( credentials ) );

        return bindAsync( bindRequest );
    }


    /**
     * {@inheritDoc}
     */
    public BindResponse bind( BindRequest bindRequest ) throws LdapException
    {
        if ( bindRequest == null )
        {
            String msg = "Cannot process a null bindRequest";
            LOG.debug( msg );
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
                LOG.error( "Bind failed : timeout occurred" );
                throw new LdapException( TIME_OUT_ERROR );
            }

            if ( bindResponse.getLdapResult().getResultCode() == ResultCodeEnum.SUCCESS )
            {
                authenticated.set( true );

                // Everything is fine, return the response
                LOG.debug( "Bind successful : {}", bindResponse );
            }
            else
            {
                // We have had an error
                LOG.debug( "Bind failed : {}", bindResponse );
            }

            return bindResponse;
        }
        catch ( TimeoutException te )
        {
            // We didn't received anything : this is an error
            LOG.error( "Bind failed : timeout occurred" );
            throw new LdapException( TIME_OUT_ERROR, te );
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
     */
    private BindRequest createBindRequest( String name, byte[] credentials ) throws LdapException
    {
        return createBindRequest( name, credentials, null, ( Control[] ) null );
    }


    /**
     * Create a Simple BindRequest ready to be sent.
     */
    private BindRequest createBindRequest( Dn name, byte[] credentials ) throws LdapException
    {
        return createBindRequest( name.getName(), credentials, null, ( Control[] ) null );
    }


    /**
     * {@inheritDoc}
     */
    public BindFuture bindAsync( BindRequest bindRequest ) throws LdapException
    {
        if ( bindRequest == null )
        {
            String msg = "Cannot process a null bindRequest";
            LOG.debug( msg );
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

        LOG.debug( "Sending request \n{}", bindRequest );

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
     * @throws {@link LdapException} if some error occurred
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
     * @throws {@link LdapException} if some error occurred
     */
    public BindResponse bindSaslPlain( String authzid, String authcid, String credentials ) throws LdapException
    {
        LOG.debug( "SASL PLAIN Bind request" );

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
                LOG.error( "Bind failed : timeout occurred" );
                throw new LdapException( TIME_OUT_ERROR );
            }

            if ( bindResponse.getLdapResult().getResultCode() == ResultCodeEnum.SUCCESS )
            {
                authenticated.set( true );

                // Everything is fine, return the response
                LOG.debug( "Bind successful : {}", bindResponse );
            }
            else
            {
                // We have had an error
                LOG.debug( "Bind failed : {}", bindResponse );
            }

            return bindResponse;
        }
        catch ( TimeoutException te )
        {
            // We didn't received anything : this is an error
            LOG.error( "Bind failed : timeout occurred" );
            throw new LdapException( TIME_OUT_ERROR, te );
        }
        catch ( Exception ie )
        {
            // Catch all other exceptions
            LOG.error( NO_RESPONSE_ERROR, ie );

            throw new LdapException( NO_RESPONSE_ERROR, ie );
        }
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
            String msg = "Cannot process a null request";
            LOG.debug( msg );
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
                LOG.error( "Bind failed : timeout occurred" );
                throw new LdapException( TIME_OUT_ERROR );
            }

            if ( bindResponse.getLdapResult().getResultCode() == ResultCodeEnum.SUCCESS )
            {
                authenticated.set( true );

                // Everything is fine, return the response
                LOG.debug( "Bind successful : {}", bindResponse );
            }
            else
            {
                // We have had an error
                LOG.debug( "Bind failed : {}", bindResponse );
            }

            return bindResponse;
        }
        catch ( TimeoutException te )
        {
            // We didn't received anything : this is an error
            LOG.error( "Bind failed : timeout occurred" );
            throw new LdapException( TIME_OUT_ERROR, te );
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
            String msg = "Cannot process a null request";
            LOG.debug( msg );
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
                LOG.error( "Bind failed : timeout occurred" );
                throw new LdapException( TIME_OUT_ERROR );
            }

            if ( bindResponse.getLdapResult().getResultCode() == ResultCodeEnum.SUCCESS )
            {
                authenticated.set( true );

                // Everything is fine, return the response
                LOG.debug( "Bind successful : {}", bindResponse );
            }
            else
            {
                // We have had an error
                LOG.debug( "Bind failed : {}", bindResponse );
            }

            return bindResponse;
        }
        catch ( TimeoutException te )
        {
            // We didn't received anything : this is an error
            LOG.error( "Bind failed : timeout occurred" );
            throw new LdapException( TIME_OUT_ERROR, te );
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
            String msg = "Cannot process a null request";
            LOG.debug( msg );
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
                LOG.error( "Bind failed : timeout occurred" );
                throw new LdapException( TIME_OUT_ERROR );
            }

            if ( bindResponse.getLdapResult().getResultCode() == ResultCodeEnum.SUCCESS )
            {
                authenticated.set( true );

                // Everything is fine, return the response
                LOG.debug( "Bind successful : {}", bindResponse );
            }
            else
            {
                // We have had an error
                LOG.debug( "Bind failed : {}", bindResponse );
            }

            return bindResponse;
        }
        catch ( TimeoutException te )
        {
            // We didn't received anything : this is an error
            LOG.error( "Bind failed : timeout occurred" );
            throw new LdapException( TIME_OUT_ERROR, te );
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
            System.setProperty( "java.security.krb5.conf", request.getKrb5ConfFilePath() );
        }
        else if ( ( request.getRealmName() != null ) && ( request.getKdcHost() != null )
            && ( request.getKdcPort() != 0 ) )
        {
            try
            {
                // Using a custom krb5.conf we create from the settings provided by the user
                String krb5ConfPath = createKrb5ConfFile( request.getRealmName(), request.getKdcHost(),
                    request.getKdcPort() );
                System.setProperty( "java.security.krb5.conf", krb5ConfPath );
            }
            catch ( IOException ioe )
            {
                throw new LdapException( ioe );
            }
        }
        else
        {
            // Using the system Kerberos configuration
            System.clearProperty( "java.security.krb5.conf" );
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
                public Object run() throws Exception
                {
                    return bindSasl( requetFinal );
                }
            } );
        }
        catch ( Exception e )
        {
            throw new LdapException( e );
        }
    }


    /**
     * {@inheritDoc}
     */
    public EntryCursor search( Dn baseDn, String filter, SearchScope scope, String... attributes )
        throws LdapException
    {
        if ( baseDn == null )
        {
            LOG.debug( "received a null dn for a search" );
            throw new IllegalArgumentException( "The base Dn cannot be null" );
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
    public EntryCursor search( String baseDn, String filter, SearchScope scope, String... attributes )
        throws LdapException
    {
        return search( new Dn( baseDn ), filter, scope, attributes );
    }


    /**
     * {@inheritDoc}
     */
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
    public SearchFuture searchAsync( String baseDn, String filter, SearchScope scope, String... attributes )
        throws LdapException
    {
        return searchAsync( new Dn( baseDn ), filter, scope, attributes );
    }


    /**
     * {@inheritDoc}
     */
    public SearchFuture searchAsync( SearchRequest searchRequest ) throws LdapException
    {
        if ( searchRequest == null )
        {
            String msg = "Cannot process a null searchRequest";
            LOG.debug( msg );
            throw new IllegalArgumentException( msg );
        }

        if ( searchRequest.getBase() == null )
        {
            String msg = "Cannot process a searchRequest which base DN is null";
            LOG.debug( msg );
            throw new IllegalArgumentException( msg );
        }

        // If the session has not been establish, or is closed, we get out immediately
        checkSession();

        int newId = messageId.incrementAndGet();
        searchRequest.setMessageId( newId );

        if ( searchRequest.isIgnoreReferrals() )
        {
            // We want to ignore the referral, inject the ManageDSAIT control in the request
            searchRequest.addControl( new ManageDsaITImpl() );
        }

        LOG.debug( "Sending request \n{}", searchRequest );

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
    public SearchCursor search( SearchRequest searchRequest ) throws LdapException
    {
        if ( searchRequest == null )
        {
            String msg = "Cannot process a null searchRequest";
            LOG.debug( msg );
            throw new IllegalArgumentException( msg );
        }

        SearchFuture searchFuture = searchAsync( searchRequest );

        long timeout = getTimeout( this.timeout, searchRequest.getTimeLimit() );

        return new SearchCursorImpl( searchFuture, timeout, TimeUnit.MILLISECONDS );
    }


    //------------------------ The LDAP operations ------------------------//
    // Unbind operations                                                   //
    //---------------------------------------------------------------------//
    /**
     * {@inheritDoc}
     */
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

        LOG.debug( "Sending Unbind request \n{}", unbindRequest );

        // Send the request to the server
        // Use this for logging instead: WriteFuture unbindFuture = ldapSession.write( unbindRequest );
        WriteFuture unbindFuture = ldapSession.write( unbindRequest );

        //LOG.debug( "waiting for unbindFuture" );
        unbindFuture.awaitUninterruptibly( timeout );
        //LOG.debug( "unbindFuture done" );

        authenticated.set( false );

        // clear the mappings
        clearMaps();

        //  We now have to close the session
        try
        {
            close();
        }
        catch ( IOException e )
        {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        connected.set( false );

        // Last, not least, reset the MessageId value
        messageId.set( 0 );

        // And get out
        LOG.debug( "Unbind successful" );
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
     * @throws Exception The t
     */
    @Override
    public void exceptionCaught( IoSession session, Throwable cause ) throws Exception
    {
        LOG.warn( cause.getMessage(), cause );
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

        session.close( true );
    }


    /**
     * Check if the message is a NoticeOfDisconnect message
     */
    private boolean isNoticeOfDisconnect( Message message )
    {
        if ( message instanceof ExtendedResponse )
        {
            ExtendedResponse response = ( ExtendedResponse ) message;

            if ( response.getResponseName().equals( NoticeOfDisconnect.EXTENSION_OID ) )
            {
                return true;
            }
        }

        return false;
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
        Message response = ( Message ) message;
        LOG.debug( "-------> {} Message received <-------", response );
        int messageId = response.getMessageId();

        // this check is necessary to prevent adding an abandoned operation's
        // result(s) to corresponding queue
        ResponseFuture<? extends Response> responseFuture = peekFromFutureMap( messageId );

        boolean isNoD = isNoticeOfDisconnect( response );

        if ( ( responseFuture == null ) && !isNoD )
        {
            LOG.info( "There is no future associated with the messageId {}, ignoring the message", messageId );
            return;
        }

        if ( isNoD )
        {
            // close the session
            session.close( true );

            return;
        }

        switch ( response.getType() )
        {
            case ADD_RESPONSE:
                // Transform the response
                AddResponse addResponse = ( AddResponse ) response;

                AddFuture addFuture = ( AddFuture ) responseFuture;

                // remove the listener from the listener map
                if ( LOG.isDebugEnabled() )
                {
                    if ( addResponse.getLdapResult().getResultCode() == ResultCodeEnum.SUCCESS )
                    {
                        // Everything is fine, return the response
                        LOG.debug( "Add successful : {}", addResponse );
                    }
                    else
                    {
                        // We have had an error
                        LOG.debug( "Add failed : {}", addResponse );
                    }
                }

                // Store the response into the future
                addFuture.set( addResponse );

                // Remove the future from the map
                removeFromFutureMaps( messageId );

                break;

            case BIND_RESPONSE:
                // Transform the response
                BindResponse bindResponse = ( BindResponse ) response;

                BindFuture bindFuture = ( BindFuture ) responseFuture;

                // remove the listener from the listener map
                if ( bindResponse.getLdapResult().getResultCode() == ResultCodeEnum.SUCCESS )
                {
                    authenticated.set( true );

                    // Everything is fine, return the response
                    LOG.debug( "Bind successful : {}", bindResponse );
                }
                else
                {
                    // We have had an error
                    LOG.debug( "Bind failed : {}", bindResponse );
                }

                // Store the response into the future
                bindFuture.set( bindResponse );

                // Remove the future from the map
                removeFromFutureMaps( messageId );

                break;

            case COMPARE_RESPONSE:
                // Transform the response
                CompareResponse compareResponse = ( CompareResponse ) response;

                CompareFuture compareFuture = ( CompareFuture ) responseFuture;

                // remove the listener from the listener map
                if ( LOG.isDebugEnabled() )
                {
                    if ( compareResponse.getLdapResult().getResultCode() == ResultCodeEnum.SUCCESS )
                    {
                        // Everything is fine, return the response
                        LOG.debug( "Compare successful : {}", compareResponse );
                    }
                    else
                    {
                        // We have had an error
                        LOG.debug( "Compare failed : {}", compareResponse );
                    }
                }

                // Store the response into the future
                compareFuture.set( compareResponse );

                // Remove the future from the map
                removeFromFutureMaps( messageId );

                break;

            case DEL_RESPONSE:
                // Transform the response
                DeleteResponse deleteResponse = ( DeleteResponse ) response;

                DeleteFuture deleteFuture = ( DeleteFuture ) responseFuture;

                if ( LOG.isDebugEnabled() )
                {
                    if ( deleteResponse.getLdapResult().getResultCode() == ResultCodeEnum.SUCCESS )
                    {
                        // Everything is fine, return the response
                        LOG.debug( "Delete successful : {}", deleteResponse );
                    }
                    else
                    {
                        // We have had an error
                        LOG.debug( "Delete failed : {}", deleteResponse );
                    }
                }

                // Store the response into the future
                deleteFuture.set( deleteResponse );

                // Remove the future from the map
                removeFromFutureMaps( messageId );

                break;

            case EXTENDED_RESPONSE:
                // Transform the response
                ExtendedResponse extendedResponse = ( ExtendedResponse ) response;

                ExtendedFuture extendedFuture = ( ExtendedFuture ) responseFuture;

                // remove the listener from the listener map
                if ( LOG.isDebugEnabled() )
                {
                    if ( extendedResponse.getLdapResult().getResultCode() == ResultCodeEnum.SUCCESS )
                    {
                        // Everything is fine, return the response
                        LOG.debug( "Extended successful : {}", extendedResponse );
                    }
                    else
                    {
                        // We have had an error
                        LOG.debug( "Extended failed : {}", extendedResponse );
                    }
                }

                // Store the response into the future
                extendedFuture.set( extendedResponse );

                // Remove the future from the map
                removeFromFutureMaps( messageId );

                break;

            case INTERMEDIATE_RESPONSE:
                IntermediateResponse intermediateResponse = null;

                if ( responseFuture instanceof SearchFuture )
                {
                    intermediateResponse = new IntermediateResponseImpl( messageId );
                    addControls( intermediateResponse, response );
                    ( ( SearchFuture ) responseFuture ).set( intermediateResponse );
                }
                else if ( responseFuture instanceof ExtendedFuture )
                {
                    intermediateResponse = new IntermediateResponseImpl( messageId );
                    addControls( intermediateResponse, response );
                    ( ( ExtendedFuture ) responseFuture ).set( intermediateResponse );
                }
                else
                {
                    // currently we only support IR for search and extended operations
                    throw new UnsupportedOperationException( "Unknown ResponseFuture type "
                        + responseFuture.getClass().getName() );
                }

                intermediateResponse.setResponseName( ( ( IntermediateResponse ) response ).getResponseName() );
                intermediateResponse.setResponseValue( ( ( IntermediateResponse ) response ).getResponseValue() );

                break;

            case MODIFY_RESPONSE:
                // Transform the response
                ModifyResponse modifyResponse = ( ModifyResponse ) response;

                ModifyFuture modifyFuture = ( ModifyFuture ) responseFuture;

                if ( LOG.isDebugEnabled() )
                {
                    if ( modifyResponse.getLdapResult().getResultCode() == ResultCodeEnum.SUCCESS )
                    {
                        // Everything is fine, return the response
                        LOG.debug( "ModifyFuture successful : {}", modifyResponse );
                    }
                    else
                    {
                        // We have had an error
                        LOG.debug( "ModifyFuture failed : {}", modifyResponse );
                    }
                }

                // Store the response into the future
                modifyFuture.set( modifyResponse );

                // Remove the future from the map
                removeFromFutureMaps( messageId );

                break;

            case MODIFYDN_RESPONSE:
                // Transform the response
                ModifyDnResponse modifyDnResponse = ( ModifyDnResponse ) response;

                ModifyDnFuture modifyDnFuture = ( ModifyDnFuture ) responseFuture;

                if ( LOG.isDebugEnabled() )
                {
                    if ( modifyDnResponse.getLdapResult().getResultCode() == ResultCodeEnum.SUCCESS )
                    {
                        // Everything is fine, return the response
                        LOG.debug( "ModifyDN successful : {}", modifyDnResponse );
                    }
                    else
                    {
                        // We have had an error
                        LOG.debug( "ModifyDN failed : {}", modifyDnResponse );
                    }
                }

                // Store the response into the future
                modifyDnFuture.set( modifyDnResponse );

                // Remove the future from the map
                removeFromFutureMaps( messageId );

                break;

            case SEARCH_RESULT_DONE:
                // Store the response into the responseQueue
                SearchResultDone searchResultDone = ( SearchResultDone ) response;

                SearchFuture searchFuture = ( SearchFuture ) responseFuture;

                if ( LOG.isDebugEnabled() )
                {
                    if ( searchResultDone.getLdapResult().getResultCode() == ResultCodeEnum.SUCCESS )
                    {
                        // Everything is fine, return the response
                        LOG.debug( "Search successful : {}", searchResultDone );
                    }
                    else
                    {
                        // We have had an error
                        LOG.debug( "Search failed : {}", searchResultDone );
                    }
                }

                // Store the response into the future
                searchFuture.set( searchResultDone );

                // Remove the future from the map
                removeFromFutureMaps( messageId );

                break;

            case SEARCH_RESULT_ENTRY:
                // Store the response into the responseQueue
                SearchResultEntry searchResultEntry = ( SearchResultEntry ) response;

                if ( schemaManager != null )
                {
                    searchResultEntry.setEntry( new DefaultEntry( schemaManager, searchResultEntry.getEntry() ) );
                }

                searchFuture = ( SearchFuture ) responseFuture;

                if ( LOG.isDebugEnabled() )
                {
                    LOG.debug( "Search entry found : {}", searchResultEntry );
                }

                // Store the response into the future
                searchFuture.set( searchResultEntry );

                break;

            case SEARCH_RESULT_REFERENCE:
                // Store the response into the responseQueue
                SearchResultReference searchResultReference = ( SearchResultReference ) response;

                searchFuture = ( SearchFuture ) responseFuture;

                if ( LOG.isDebugEnabled() )
                {
                    LOG.debug( "Search reference found : {}", searchResultReference );
                }

                // Store the response into the future
                searchFuture.set( searchResultReference );

                break;

            default:
                throw new IllegalStateException( "Unexpected response type " + response.getType() );
        }
    }


    /**
     * {@inheritDoc}
     */
    public void modify( Entry entry, ModificationOperation modOp ) throws LdapException
    {
        if ( entry == null )
        {
            LOG.debug( "received a null entry for modification" );
            throw new IllegalArgumentException( "Entry to be modified cannot be null" );
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
    public void modify( Dn dn, Modification... modifications ) throws LdapException
    {
        if ( dn == null )
        {
            LOG.debug( "received a null dn for modification" );
            throw new IllegalArgumentException( "The Dn to be modified cannot be null" );
        }

        if ( ( modifications == null ) || ( modifications.length == 0 ) )
        {
            String msg = "Cannot process a ModifyRequest without any modification";
            LOG.debug( msg );
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
    public void modify( String dn, Modification... modifications ) throws LdapException
    {
        modify( new Dn( dn ), modifications );
    }


    /**
     * {@inheritDoc}
     */
    public ModifyResponse modify( ModifyRequest modRequest ) throws LdapException
    {
        if ( modRequest == null )
        {
            String msg = "Cannot process a null modifyRequest";
            LOG.debug( msg );
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
                LOG.error( "Modify failed : timeout occurred" );
                throw new LdapException( TIME_OUT_ERROR );
            }

            if ( modifyResponse.getLdapResult().getResultCode() == ResultCodeEnum.SUCCESS )
            {
                // Everything is fine, return the response
                LOG.debug( "Modify successful : {}", modifyResponse );
            }
            else
            {
                if ( modifyResponse instanceof ModifyNoDResponse )
                {
                    // A NoticeOfDisconnect : deserves a special treatment
                    throw new LdapException( modifyResponse.getLdapResult().getDiagnosticMessage() );
                }

                // We have had an error
                LOG.debug( "Modify failed : {}", modifyResponse );
            }

            return modifyResponse;
        }
        catch ( TimeoutException te )
        {
            // Send an abandon request
            if ( !modifyFuture.isCancelled() )
            {
                abandon( modRequest.getMessageId() );
            }

            // We didn't received anything : this is an error
            LOG.error( "Modify failed : timeout occurred" );
            throw new LdapException( TIME_OUT_ERROR, te );
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
    public ModifyFuture modifyAsync( ModifyRequest modRequest ) throws LdapException
    {
        if ( modRequest == null )
        {
            String msg = "Cannot process a null modifyRequest";
            LOG.debug( msg );
            throw new IllegalArgumentException( msg );
        }

        if ( modRequest.getName() == null )
        {
            String msg = "Cannot process a modifyRequest which DN is null";
            LOG.debug( msg );
            throw new IllegalArgumentException( msg );
        }

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
    public void rename( String entryDn, String newRdn ) throws LdapException
    {
        rename( entryDn, newRdn, true );
    }


    /**
     * {@inheritDoc}
     */
    public void rename( Dn entryDn, Rdn newRdn ) throws LdapException
    {
        rename( entryDn, newRdn, true );
    }


    /**
     * {@inheritDoc}
     */
    public void rename( String entryDn, String newRdn, boolean deleteOldRdn ) throws LdapException
    {
        if ( entryDn == null )
        {
            String msg = "Cannot process a rename of a null Dn";
            LOG.debug( msg );
            throw new IllegalArgumentException( msg );
        }

        if ( newRdn == null )
        {
            String msg = "Cannot process a rename with a null Rdn";
            LOG.debug( msg );
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
    public void rename( Dn entryDn, Rdn newRdn, boolean deleteOldRdn ) throws LdapException
    {
        if ( entryDn == null )
        {
            String msg = "Cannot process a rename of a null Dn";
            LOG.debug( msg );
            throw new IllegalArgumentException( msg );
        }

        if ( newRdn == null )
        {
            String msg = "Cannot process a rename with a null Rdn";
            LOG.debug( msg );
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
    public void move( String entryDn, String newSuperiorDn ) throws LdapException
    {
        if ( entryDn == null )
        {
            String msg = "Cannot process a move of a null Dn";
            LOG.debug( msg );
            throw new IllegalArgumentException( msg );
        }

        if ( newSuperiorDn == null )
        {
            String msg = "Cannot process a move to a null newSuperior";
            LOG.debug( msg );
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
    public void move( Dn entryDn, Dn newSuperiorDn ) throws LdapException
    {
        if ( entryDn == null )
        {
            String msg = "Cannot process a move of a null Dn";
            LOG.debug( msg );
            throw new IllegalArgumentException( msg );
        }

        if ( newSuperiorDn == null )
        {
            String msg = "Cannot process a move to a null newSuperior";
            LOG.debug( msg );
            throw new IllegalArgumentException( msg );
        }

        ModifyDnRequest modDnRequest = new ModifyDnRequestImpl();
        modDnRequest.setName( entryDn );
        modDnRequest.setNewSuperior( newSuperiorDn );

        //TODO not setting the below value is resulting in error
        modDnRequest.setNewRdn( entryDn.getRdn() );

        ModifyDnResponse modifyDnResponse = modifyDn( modDnRequest );

        processResponse( modifyDnResponse );
    }


    /**
     * {@inheritDoc}
     */
    public void moveAndRename( Dn entryDn, Dn newDn ) throws LdapException
    {
        moveAndRename( entryDn, newDn, true );
    }


    /**
     * {@inheritDoc}
     */
    public void moveAndRename( String entryDn, String newDn ) throws LdapException
    {
        moveAndRename( new Dn( entryDn ), new Dn( newDn ), true );
    }


    /**
     * {@inheritDoc}
     */
    public void moveAndRename( Dn entryDn, Dn newDn, boolean deleteOldRdn ) throws LdapException
    {
        // Check the parameters first
        if ( entryDn == null )
        {
            throw new IllegalArgumentException( "The entry Dn must not be null" );
        }

        if ( entryDn.isRootDse() )
        {
            throw new IllegalArgumentException( "The RootDSE cannot be moved" );
        }

        if ( newDn == null )
        {
            throw new IllegalArgumentException( "The new Dn must not be null" );
        }

        if ( newDn.isRootDse() )
        {
            throw new IllegalArgumentException( "The RootDSE cannot be the target" );
        }

        // Create the request
        ModifyDnRequest modDnRequest = new ModifyDnRequestImpl();
        modDnRequest.setName( entryDn );
        modDnRequest.setNewRdn( newDn.getRdn() );
        modDnRequest.setNewSuperior( newDn.getParent() );
        modDnRequest.setDeleteOldRdn( deleteOldRdn );

        ModifyDnResponse modifyDnResponse = modifyDn( modDnRequest );

        processResponse( modifyDnResponse );
    }


    /**
     * {@inheritDoc}
     */
    public void moveAndRename( String entryDn, String newDn, boolean deleteOldRdn ) throws LdapException
    {
        moveAndRename( new Dn( entryDn ), new Dn( newDn ), true );
    }


    /**
     * {@inheritDoc}
     */
    public ModifyDnResponse modifyDn( ModifyDnRequest modDnRequest ) throws LdapException
    {
        if ( modDnRequest == null )
        {
            String msg = "Cannot process a null modDnRequest";
            LOG.debug( msg );
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
                LOG.error( "ModifyDN failed : timeout occurred" );
                throw new LdapException( TIME_OUT_ERROR );
            }

            if ( modifyDnResponse.getLdapResult().getResultCode() == ResultCodeEnum.SUCCESS )
            {
                // Everything is fine, return the response
                LOG.debug( "ModifyDN successful : {}", modifyDnResponse );
            }
            else
            {
                // We have had an error
                LOG.debug( "Modify failed : {}", modifyDnResponse );
            }

            return modifyDnResponse;
        }
        catch ( TimeoutException te )
        {
            // Send an abandon request
            if ( !modifyDnFuture.isCancelled() )
            {
                abandon( modDnRequest.getMessageId() );
            }

            // We didn't received anything : this is an error
            LOG.error( "Modify failed : timeout occurred" );
            throw new LdapException( TIME_OUT_ERROR, te );
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
    public ModifyDnFuture modifyDnAsync( ModifyDnRequest modDnRequest ) throws LdapException
    {
        if ( modDnRequest == null )
        {
            String msg = "Cannot process a null modDnRequest";
            LOG.debug( msg );
            throw new IllegalArgumentException( msg );
        }

        if ( modDnRequest.getName() == null )
        {
            String msg = "Cannot process a modifyRequest which DN is null";
            LOG.debug( msg );
            throw new IllegalArgumentException( msg );
        }

        if ( ( modDnRequest.getNewSuperior() == null ) && ( modDnRequest.getNewRdn() == null ) )
        {
            String msg = "Cannot process a modifyRequest which new superior and new Rdn are null";
            LOG.debug( msg );
            throw new IllegalArgumentException( msg );
        }

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
    public void delete( String dn ) throws LdapException
    {
        delete( new Dn( dn ) );
    }


    /**
     * {@inheritDoc}
     */
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
     * @return operation's response
     * @throws LdapException If the Dn is not valid or if the deletion failed
     */
    public void deleteTree( Dn dn ) throws LdapException
    {
        String treeDeleteOid = "1.2.840.113556.1.4.805";

        if ( isControlSupported( treeDeleteOid ) )
        {
            DeleteRequest deleteRequest = new DeleteRequestImpl();
            deleteRequest.setName( dn );
            deleteRequest.addControl( new OpaqueControl( treeDeleteOid ) );
            DeleteResponse deleteResponse = delete( deleteRequest );

            processResponse( deleteResponse );
        }
        else
        {
            String msg = "The subtreeDelete control (1.2.840.113556.1.4.805) is not supported by the server\n"
                + " The deletion has been aborted";
            LOG.error( msg );
            throw new LdapException( msg );
        }
    }


    /**
     * deletes the entry with the given Dn, and all its children
     *
     * @param dn the target entry's Dn as a String
     * @return operation's response
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
                String msg = "The subtreeDelete control (1.2.840.113556.1.4.805) is not supported by the server\n"
                    + " The deletion has been aborted";
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
    public DeleteResponse delete( DeleteRequest deleteRequest ) throws LdapException
    {
        if ( deleteRequest == null )
        {
            String msg = "Cannot process a null deleteRequest";
            LOG.debug( msg );
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
                LOG.error( "Delete failed : timeout occurred" );
                throw new LdapException( TIME_OUT_ERROR );
            }

            if ( delResponse.getLdapResult().getResultCode() == ResultCodeEnum.SUCCESS )
            {
                // Everything is fine, return the response
                LOG.debug( "Delete successful : {}", delResponse );
            }
            else
            {
                // We have had an error
                LOG.debug( "Delete failed : {}", delResponse );
            }

            return delResponse;
        }
        catch ( TimeoutException te )
        {
            // Send an abandon request
            if ( !deleteFuture.isCancelled() )
            {
                abandon( deleteRequest.getMessageId() );
            }

            // We didn't received anything : this is an error
            LOG.error( "Del failed : timeout occurred" );
            throw new LdapException( TIME_OUT_ERROR, te );
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
    public DeleteFuture deleteAsync( DeleteRequest deleteRequest ) throws LdapException
    {
        if ( deleteRequest == null )
        {
            String msg = "Cannot process a null deleteRequest";
            LOG.debug( msg );
            throw new IllegalArgumentException( msg );
        }

        if ( deleteRequest.getName() == null )
        {
            String msg = "Cannot process a deleteRequest which DN is null";
            LOG.debug( msg );
            throw new IllegalArgumentException( msg );
        }

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
    public boolean compare( String dn, String attributeName, String value ) throws LdapException
    {
        return compare( new Dn( dn ), attributeName, value );
    }


    /**
     * {@inheritDoc}
     */
    public boolean compare( String dn, String attributeName, byte[] value ) throws LdapException
    {
        return compare( new Dn( dn ), attributeName, value );
    }


    /**
     * {@inheritDoc}
     */
    public boolean compare( String dn, String attributeName, Value<?> value ) throws LdapException
    {
        return compare( new Dn( dn ), attributeName, value );
    }


    /**
     * {@inheritDoc}
     */
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
    public boolean compare( Dn dn, String attributeName, Value<?> value ) throws LdapException
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
    public CompareResponse compare( CompareRequest compareRequest ) throws LdapException
    {
        if ( compareRequest == null )
        {
            String msg = "Cannot process a null compareRequest";
            LOG.debug( msg );
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
                LOG.error( "Compare failed : timeout occurred" );
                throw new LdapException( TIME_OUT_ERROR );
            }

            if ( compareResponse.getLdapResult().getResultCode() == ResultCodeEnum.SUCCESS )
            {
                // Everything is fine, return the response
                LOG.debug( "Compare successful : {}", compareResponse );
            }
            else
            {
                // We have had an error
                LOG.debug( "Compare failed : {}", compareResponse );
            }

            return compareResponse;
        }
        catch ( TimeoutException te )
        {
            // Send an abandon request
            if ( !compareFuture.isCancelled() )
            {
                abandon( compareRequest.getMessageId() );
            }

            // We didn't received anything : this is an error
            LOG.error( "Compare failed : timeout occurred" );
            throw new LdapException( TIME_OUT_ERROR, te );
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
    public CompareFuture compareAsync( CompareRequest compareRequest ) throws LdapException
    {
        if ( compareRequest == null )
        {
            String msg = "Cannot process a null compareRequest";
            LOG.debug( msg );
            throw new IllegalArgumentException( msg );
        }

        if ( compareRequest.getName() == null )
        {
            String msg = "Cannot process a compareRequest which DN is null";
            LOG.debug( msg );
            throw new IllegalArgumentException( msg );
        }

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
    public ExtendedResponse extended( String oid ) throws LdapException
    {
        return extended( oid, null );
    }


    /**
     * {@inheritDoc}
     */
    public ExtendedResponse extended( String oid, byte[] value ) throws LdapException
    {
        try
        {
            return extended( Oid.fromString( oid ), value );
        }
        catch ( DecoderException e )
        {
            String msg = "Failed to decode the OID " + oid;
            LOG.error( msg );
            throw new LdapException( msg, e );
        }
    }


    /**
     * {@inheritDoc}
     */
    public ExtendedResponse extended( Oid oid ) throws LdapException
    {
        return extended( oid, null );
    }


    /**
     * {@inheritDoc}
     */
    public ExtendedResponse extended( Oid oid, byte[] value ) throws LdapException
    {
        ExtendedRequest extendedRequest =
            LdapApiServiceFactory.getSingleton().newExtendedRequest( oid.toString(), value );
        return extended( extendedRequest );
    }


    /**
     * {@inheritDoc}
     */
    public ExtendedResponse extended( ExtendedRequest extendedRequest ) throws LdapException
    {
        if ( extendedRequest == null )
        {
            String msg = "Cannot process a null extendedRequest";
            LOG.debug( msg );
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
                LOG.error( "Extended failed : timeout occurred" );
                throw new LdapException( TIME_OUT_ERROR );
            }

            if ( response.getLdapResult().getResultCode() == ResultCodeEnum.SUCCESS )
            {
                // Everything is fine, return the response
                LOG.debug( "Extended successful : {}", response );
            }
            else
            {
                // We have had an error
                LOG.debug( "Extended failed : {}", response );
            }

            // Get back the response. It's still an opaque response
            if ( Strings.isEmpty( response.getResponseName() ) )
            {
                response.setResponseName( extendedRequest.getRequestName() );
            }

            // Decode the payload now
            ExtendedResponseDecorator<?> decoratedResponse = codec.decorate( response );

            return decoratedResponse;
        }
        catch ( TimeoutException te )
        {
            // Send an abandon request
            if ( !extendedFuture.isCancelled() )
            {
                abandon( extendedRequest.getMessageId() );
            }

            // We didn't received anything : this is an error
            LOG.error( "Extended failed : timeout occurred" );
            throw new LdapException( TIME_OUT_ERROR, te );
        }
        catch ( Exception ie )
        {
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
    public ExtendedFuture extendedAsync( ExtendedRequest extendedRequest ) throws LdapException
    {
        if ( extendedRequest == null )
        {
            String msg = "Cannot process a null extendedRequest";
            LOG.debug( msg );
            throw new IllegalArgumentException( msg );
        }

        checkSession();

        int newId = messageId.incrementAndGet();

        extendedRequest.setMessageId( newId );
        ExtendedFuture extendedFuture = new ExtendedFuture( this, newId );
        addToFutureMap( newId, extendedFuture );

        // Send the request to the server
        writeRequest( extendedRequest );

        // Ok, done return the future
        return extendedFuture;
    }


    /**
     * {@inheritDoc}
     */
    public boolean exists( String dn ) throws LdapException
    {
        return exists( new Dn( dn ) );
    }


    /**
     * {@inheritDoc}
     */
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
    public Entry getRootDse() throws LdapException
    {
        return lookup( Dn.ROOT_DSE, SchemaConstants.ALL_USER_ATTRIBUTES_ARRAY );
    }


    /**
     * {@inheritDoc}
     */
    public Entry getRootDse( String... attributes ) throws LdapException
    {
        return lookup( Dn.ROOT_DSE, attributes );
    }


    /**
     * {@inheritDoc}
     */
    public Entry lookup( Dn dn ) throws LdapException
    {
        return lookup( dn, SchemaConstants.ALL_USER_ATTRIBUTES_ARRAY );
    }


    /**
     * {@inheritDoc}
     */
    public Entry lookup( String dn ) throws LdapException
    {
        return lookup( dn, SchemaConstants.ALL_USER_ATTRIBUTES_ARRAY );
    }


    /**
     * {@inheritDoc}
     */
    public Entry lookup( Dn dn, String... attributes ) throws LdapException
    {
        return lookup( dn, null, attributes );
    }


    /**
     * {@inheritDoc}
     */
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

            Cursor<Response> cursor = search( searchRequest );

            // Read the response
            if ( cursor.next() )
            {
                // cursor will always hold SearchResultEntry objects cause there is no ManageDsaITControl passed with search request
                entry = ( ( SearchResultEntry ) cursor.get() ).getEntry();
            }

            // Pass through the SaerchResultDone, or stop
            // if we have other responses
            cursor.next();

            // And close the cursor
            cursor.close();
        }
        catch ( CursorException e )
        {
            throw new LdapException( e );
        }

        return entry;
    }


    /**
     * {@inheritDoc}
     */
    public Entry lookup( String dn, String... attributes ) throws LdapException
    {
        return lookup( new Dn( dn ), null, attributes );
    }


    /**
     * {@inheritDoc}
     */
    public Entry lookup( String dn, Control[] controls, String... attributes ) throws LdapException
    {
        return lookup( new Dn( dn ), controls, attributes );
    }


    /**
     * {@inheritDoc}
     */
    public boolean isControlSupported( String controlOID ) throws LdapException
    {
        return getSupportedControls().contains( controlOID );
    }


    /**
     * {@inheritDoc}
     */
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

        supportedControls = new ArrayList<String>();

        Attribute attr = rootDse.get( SchemaConstants.SUPPORTED_CONTROL_AT );

        for ( Value<?> value : attr )
        {
            supportedControls.add( value.getString() );
        }

        return supportedControls;
    }


    /**
     * {@inheritDoc}
     */
    public void loadSchema() throws LdapException
    {
        loadSchema( new DefaultSchemaLoader( this ) );
    }


    /**
     * loads schema using the specified schema loader
     *
     * @param loader the {@link SchemaLoader} to be used to load schema
     * @throws LdapException
     */
    public void loadSchema( SchemaLoader loader ) throws LdapException
    {
        try
        {
            SchemaManager tmp = new DefaultSchemaManager( loader );

            tmp.loadAllEnabled();

            if ( !tmp.getErrors().isEmpty() )
            {
                String msg = "there are errors while loading the schema";
                LOG.error( msg + " {}", tmp.getErrors() );
                throw new LdapException( msg );
            }

            schemaManager = tmp;

            // Change the container's BinaryDetector
            ldapSession.setAttribute( LdapDecoder.MESSAGE_CONTAINER_ATTR,
                new LdapMessageContainer<MessageDecorator<? extends Message>>( codec,
                    new SchemaBinaryAttributeDetector( schemaManager ) ) );

        }
        catch ( LdapException le )
        {
            throw le;
        }
        catch ( Exception e )
        {
            LOG.error( "failed to load the schema", e );
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

            OpenLdapSchemaParser olsp = new OpenLdapSchemaParser();
            olsp.setQuirksMode( true );
            olsp.parse( schemaFile );

            Registries registries = schemaManager.getRegistries();
            List<Throwable> errors = new ArrayList<Throwable>();

            for ( AttributeType atType : olsp.getAttributeTypes() )
            {
                registries.buildReference( errors, atType );
                registries.getAttributeTypeRegistry().register( atType );
            }

            for ( ObjectClass oc : olsp.getObjectClassTypes() )
            {
                registries.buildReference( errors, oc );
                registries.getObjectClassRegistry().register( oc );
            }

            LOG.info( "successfully loaded the schema from file {}", schemaFile.getAbsolutePath() );
        }
        catch ( Exception e )
        {
            LOG.error( "failed to load the schema from file {}", schemaFile.getAbsolutePath() );
            throw new LdapException( e );
        }
    }


    /**
     * @see #addSchema(File)
     */
    public void addSchema( String schemaFileName ) throws LdapException
    {
        addSchema( new File( schemaFileName ) );
    }


    /**
     * {@inheritDoc}
     */
    public LdapApiService getCodecService()
    {
        return codec;
    }


    /**
     * {@inheritDoc}
     */
    public SchemaManager getSchemaManager()
    {
        return schemaManager;
    }


    /**
     * fetches the rootDSE from the server
     * @throws LdapException
     */
    private void fetchRootDSE() throws LdapException
    {
        EntryCursor cursor = null;

        try
        {
            cursor = search( "", LdapConstants.OBJECT_CLASS_STAR, SearchScope.OBJECT,
                SchemaConstants.ALL_USER_ATTRIBUTES,
                SchemaConstants.ALL_OPERATIONAL_ATTRIBUTES );
            cursor.next();
            rootDse = cursor.get();
        }
        catch ( Exception e )
        {
            String msg = "Failed to fetch the RootDSE";
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
                    LOG.error( "Failed to close open cursor", e );
                }
            }
        }
    }


    /**
     * gives the configuration information of the connection
     *
     * @return the configuration of the connection
     */
    public LdapConnectionConfig getConfig()
    {
        return config;
    }


    private void addControls( Message codec, Message message )
    {
        Map<String, Control> controls = codec.getControls();

        if ( controls != null )
        {
            for ( Control cc : controls.values() )
            {
                if ( cc == null )
                {
                    continue;
                }

                message.addControl( cc );
            }
        }
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
            conCloseListeners = new ArrayList<ConnectionClosedEventListener>();
        }

        conCloseListeners.add( ccListener );
    }


    /**
     * This method is called when a new session is created. We will store some
     * informations that the session will need to process incoming requests.
     * 
     * @param session the newly created session
     */
    public void sessionCreated( IoSession session ) throws Exception
    {
        // Last, store the message container
        LdapMessageContainer<? extends MessageDecorator<Message>> ldapMessageContainer =
            new LdapMessageContainer<MessageDecorator<Message>>(
                codec, config.getBinaryAttributeDetector() );

        session.setAttribute( LdapDecoder.MESSAGE_CONTAINER_ATTR, ldapMessageContainer );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void sessionClosed( IoSession session ) throws Exception
    {
        // no need to handle if this session was closed by the user
        if ( !connected.get() )
        {
            return;
        }

        ldapSession.close( true );
        connected.set( false );
        // Reset the messageId
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

        clearMaps();

        if ( conCloseListeners != null )
        {
            LOG.debug( "notifying the registered ConnectionClosedEventListeners.." );

            for ( ConnectionClosedEventListener listener : conCloseListeners )
            {
                listener.connectionClosed();
            }
        }
    }


    /**
     * Sends the StartTLS extended request to server and adds a security layer
     * upon receiving a response with successful result. Note that we will use
     * the default LDAP connection.
     *
     * @throws LdapException
     */
    public void startTls() throws LdapException
    {
        try
        {
            if ( config.isUseSsl() )
            {
                throw new LdapException( "Cannot use TLS when the useSsl flag is set true in the configuration" );
            }

            checkSession();

            IoFilter sslFilter = ldapSession.getFilterChain().get( SSL_FILTER_KEY );
            if ( sslFilter != null )
            {
                LOG.debug( "LDAP session already using startTLS" );
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
     * adds {@link SslFilter} to the IOConnector or IOSession's filter chain
     */
    private void addSslFilter() throws LdapException
    {
        try
        {
            SSLContext sslContext = SSLContext.getInstance( config.getSslProtocol() );
            sslContext.init( config.getKeyManagers(), config.getTrustManagers(), config.getSecureRandom() );

            SslFilter sslFilter = new SslFilter( sslContext, true );
            sslFilter.setUseClientMode( true );
            sslFilter.setEnabledCipherSuites( config.getEnabledCipherSuites() );

            // Be sure we disable SSLV3
            sslFilter.setEnabledProtocols( new String[]
                { "TLSv1", "TLSv1.1", "TLSv1.2" } );

            // for LDAPS
            if ( ldapSession == null )
            {
                connector.getFilterChain().addFirst( SSL_FILTER_KEY, sslFilter );
            }
            else
            // for StartTLS
            {
                ldapSession.getFilterChain().addFirst( SSL_FILTER_KEY, sslFilter );
            }
        }
        catch ( Exception e )
        {
            String msg = "Failed to initialize the SSL context";
            LOG.error( msg, e );
            throw new LdapException( msg, e );
        }
    }


    /**
     * Process the SASL Bind. It's a dialog with the server, we will send a first BindRequest, receive
     * a response and the, if this response is a challenge, continue by sending a new BindRequest with
     * the requested informations.
     */
    private BindFuture bindSasl( SaslRequest saslRequest ) throws LdapException
    {
        // First switch to anonymous state
        authenticated.set( false );

        // try to connect, if we aren't already connected.
        connect();

        // If the session has not been establish, or is closed, we get out immediately
        checkSession();

        BindRequest bindRequest = createBindRequest( ( String ) null, null,
            saslRequest.getSaslMechanism(), saslRequest
                .getControls() );

        // Update the messageId
        int newId = messageId.incrementAndGet();
        bindRequest.setMessageId( newId );

        LOG.debug( "Sending request \n{}", bindRequest );

        // Create a future for this Bind operation
        BindFuture bindFuture = new BindFuture( this, newId );

        // Store it in the future Map
        addToFutureMap( newId, bindFuture );

        try
        {
            BindResponse bindResponse = null;
            byte[] response = null;
            ResultCodeEnum result = null;

            // Creating a map for SASL properties
            Map<String, Object> properties = new HashMap<String, Object>();

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
                String message = "Cannot find a SASL factory for the " + bindRequest.getSaslMechanism() + " mechanism";
                LOG.error( message );
                throw new LdapException( message );
            }

            // Corner case : the SASL mech might send an initial challenge, and we have to
            // deal with it immediately.
            if ( sc.hasInitialResponse() )
            {
                byte[] challengeResponse = sc.evaluateChallenge( new byte[0] );

                // Stores the challenge's response, and send it to the server
                bindRequest.setCredentials( challengeResponse );
                writeRequest( bindRequest );

                // Get the server's response, blocking
                bindResponse = bindFuture.get( timeout, TimeUnit.MILLISECONDS );

                if ( bindResponse == null )
                {
                    // We didn't received anything : this is an error
                    LOG.error( "bind failed : timeout occurred" );
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
                    LOG.error( "bind failed : timeout occurred" );
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
                        throw new LdapException( "protocol error" );
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
                        LOG.error( "bind failed : timeout occurred" );
                        throw new LdapException( TIME_OUT_ERROR );
                    }

                    result = bindResponse.getLdapResult().getResultCode();
                }
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
            e.printStackTrace();
            throw new LdapException( e );
        }
    }


    /**
     * a reusable code block to be used in various bind methods
     */
    private void writeRequest( Request request ) throws LdapException
    {
        // Send the request to the server
        WriteFuture writeFuture = ldapSession.write( request );

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
            if ( !ldapSession.isConnected() )
            {
                // We didn't received anything : this is an error
                LOG.error( "Message failed : something wrong has occurred" );

                Exception exception = ( Exception ) ldapSession.removeAttribute( EXCEPTION_KEY );

                if ( exception != null )
                {
                    if ( exception instanceof LdapException )
                    {
                        throw ( LdapException ) exception;
                    }
                    else
                    {
                        throw new InvalidConnectionException( exception.getMessage() );
                    }
                }

                throw new InvalidConnectionException( "Error while sending some message : the session has been closed" );
            }

            localTimeout -= 100;
        }

        LOG.error( "TimeOut has occurred" );
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
     * @return the full path of the config file
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

        File krb5Conf = File.createTempFile( "client-api-krb5", ".conf" );
        krb5Conf.deleteOnExit();
        FileWriter fw = new FileWriter( krb5Conf );
        fw.write( sb.toString() );
        fw.close();

        String krb5ConfPath = krb5Conf.getAbsolutePath();

        LOG.debug( "krb 5 config file created at {}", krb5ConfPath );

        return krb5ConfPath;
    }


    /**
     * {@inheritDoc}
     */
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
}
