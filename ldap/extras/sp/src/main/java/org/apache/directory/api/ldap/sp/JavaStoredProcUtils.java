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

package org.apache.directory.api.ldap.sp;


import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;

import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttributes;
import javax.naming.ldap.ExtendedRequest;
import javax.naming.ldap.ExtendedResponse;
import javax.naming.ldap.LdapContext;

import org.apache.commons.lang3.SerializationUtils;
import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.codec.api.LdapApiServiceFactory;
import org.apache.directory.api.ldap.extras.extended.storedProcedure.StoredProcedureRequestImpl;
import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.directory.api.util.IOUtils;


/**
 * A utility class for working with Java Stored Procedures at the base level.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public final class JavaStoredProcUtils
{

    /**
     * Private constructor.
     */
    private JavaStoredProcUtils()
    {
    }


    /**
     * Returns the stream data of a Java class.
     *
     * @param clazz
     *           The class whose stream data will be retrieved.
     * @return
     *           Stream data of the class file as a byte array.
     * @throws NamingException
     *           If an IO error occurs during reading the class file.
     */
    public static byte[] getClassFileAsStream( Class<?> clazz ) throws NamingException
    {
        String fullClassName = clazz.getName();
        int lastDot = fullClassName.lastIndexOf( '.' );
        String classFileName = fullClassName.substring( lastDot + 1 ) + ".class";
        URL url = clazz.getResource( classFileName );
        InputStream in = null;
        
        try
        {
            in = url.openStream();
            File file = new File( url.toURI() );
            int size = ( int ) file.length();
            byte[] buf = new byte[size];
            int nbRead = in.read( buf );
            
            if ( nbRead == -1 ) 
            {
                NamingException ne = new NamingException( I18n.err( I18n.ERR_10000_EMPTY_SP_CLASS, url.toURI() ) );
                throw ne;
            }

            return buf;
        }
        catch ( URISyntaxException urie )
        {
            NamingException ne = new NamingException();
            ne.setRootCause( urie );
            throw ne;
        }
        catch ( IOException ioe )
        {
            NamingException ne = new NamingException();
            ne.setRootCause( ioe );
            throw ne;
        }
        finally
        {
            if ( in != null )
            {
                IOUtils.closeQuietly( in );
            }
        }
    }


    /**
     * Loads a Java class's stream data as a subcontext of an LdapContext given.
     *
     * @param ctx
     *           The parent context of the Java class entry to be loaded.
     * @param clazz
     *           Class to be loaded.
     * @throws NamingException
     *           If an error occurs during creating the subcontext.
     */
    public static void loadStoredProcedureClass( LdapContext ctx, Class<?> clazz ) throws NamingException
    {
        byte[] buf = getClassFileAsStream( clazz );
        String fullClassName = clazz.getName();

        Attributes attributes = new BasicAttributes( SchemaConstants.OBJECT_CLASS_AT, SchemaConstants.TOP_OC, true );
        attributes.get( SchemaConstants.OBJECT_CLASS_AT ).add( "storedProcUnit" );
        attributes.get( SchemaConstants.OBJECT_CLASS_AT ).add( "javaStoredProcUnit" );
        attributes.put( "storedProcLangId", "Java" );
        attributes.put( "storedProcUnitName", fullClassName );
        attributes.put( "javaByteCode", buf );

        ctx.createSubcontext( "storedProcUnitName=" + fullClassName, attributes );
    }


    /**
     * Invoke a Stored Procedure
     *
     * @param ctx The execution context
     * @param procedureName The procedure to execute
     * @param arguments The procedure's arguments
     * @return The execution resut
     * @throws NamingException If we have had an error whil executing the stored procedure
     */
    public static Object callStoredProcedure( LdapContext ctx, String procedureName, Object[] arguments )
        throws NamingException
    {
        String language = "Java";

        Object responseObject;
        try
        {
            /**
             * Create a new stored procedure execution request.
             */
            StoredProcedureRequestImpl req = new StoredProcedureRequestImpl( 0, procedureName, language );

            /**
             * For each argument UTF-8-encode the type name
             * and Java-serialize the value
             * and add them to the request as a parameter object.
             */
            for ( int i = 0; i < arguments.length; i++ )
            {
                byte[] type;
                byte[] value;
                type = arguments[i].getClass().getName().getBytes( StandardCharsets.UTF_8 );
                value = SerializationUtils.serialize( ( Serializable ) arguments[i] );
                req.addParameter( type, value );
            }

            /**
             * Call the stored procedure via the extended operation
             * and get back its return value.
             */
            ExtendedRequest jndiReq = LdapApiServiceFactory.getSingleton().toJndi( req );
            ExtendedResponse resp = ctx.extendedOperation( jndiReq );

            /**
             * Restore a Java object from the return value.
             */
            byte[] responseStream = resp.getEncodedValue();
            responseObject = SerializationUtils.deserialize( responseStream );
        }
        catch ( Exception e )
        {
            NamingException ne = new NamingException();
            ne.setRootCause( e );
            throw ne;
        }

        return responseObject;
    }

}
