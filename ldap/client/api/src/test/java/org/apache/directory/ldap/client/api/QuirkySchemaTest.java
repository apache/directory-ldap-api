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


import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Collection;
import java.util.List;

import org.apache.directory.api.asn1.util.Oid;
import org.apache.directory.api.ldap.codec.api.BinaryAttributeDetector;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.directory.api.ldap.model.cursor.EntryCursor;
import org.apache.directory.api.ldap.model.cursor.SearchCursor;
import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Modification;
import org.apache.directory.api.ldap.model.entry.ModificationOperation;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.ldif.LdifEntry;
import org.apache.directory.api.ldap.model.ldif.LdifReader;
import org.apache.directory.api.ldap.model.message.AbandonRequest;
import org.apache.directory.api.ldap.model.message.AddRequest;
import org.apache.directory.api.ldap.model.message.AddResponse;
import org.apache.directory.api.ldap.model.message.BindRequest;
import org.apache.directory.api.ldap.model.message.BindResponse;
import org.apache.directory.api.ldap.model.message.CompareRequest;
import org.apache.directory.api.ldap.model.message.CompareResponse;
import org.apache.directory.api.ldap.model.message.Control;
import org.apache.directory.api.ldap.model.message.DeleteRequest;
import org.apache.directory.api.ldap.model.message.DeleteResponse;
import org.apache.directory.api.ldap.model.message.ExtendedRequest;
import org.apache.directory.api.ldap.model.message.ExtendedResponse;
import org.apache.directory.api.ldap.model.message.ModifyDnRequest;
import org.apache.directory.api.ldap.model.message.ModifyDnResponse;
import org.apache.directory.api.ldap.model.message.ModifyRequest;
import org.apache.directory.api.ldap.model.message.ModifyResponse;
import org.apache.directory.api.ldap.model.message.SearchRequest;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.name.Rdn;
import org.apache.directory.api.ldap.model.schema.ObjectClass;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.api.ldap.model.schema.registries.Schema;
import org.apache.directory.api.ldap.schema.manager.impl.DefaultSchemaManager;
import org.apache.directory.api.util.exception.Exceptions;
import org.junit.Test;


/**
 * Tests the DefaultSchemaLoader and DefaultSchemaManager with schema that is full of quirks.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class QuirkySchemaTest
{

    protected static final String SCHEMA_DN = "cn=schema";


    /**
     * Try to load a very minimal (and correct) schema. It has just 'person' objectclass and all
     * the necessary attributes, matching rules and syntaxes. Load it in strict mode.
     * This test is here mostly to make sure that the test itself works.
     */
    @Test
    public void testLoadMinimalSchema() throws Exception
    {
        LdapConnection connection = createFakeConnection( "src/test/resources/schema-minimal.ldif" );
        DefaultSchemaLoader loader = new DefaultSchemaLoader( connection );
        Collection<Schema> allEnabled = loader.getAllEnabled();
        assertEquals( 1, allEnabled.size() );
        Schema schema = allEnabled.iterator().next();
        assertNotNull( schema );
        assertEquals( 26, schema.getContent().size() );

        SchemaManager schemaManager = new DefaultSchemaManager( loader );

        boolean loaded = schemaManager.loadAllEnabled();

        if ( !loaded )
        {
            fail( "Schema load failed : " + Exceptions.printErrors( schemaManager.getErrors() ) );
        }

        assertTrue( schemaManager.getRegistries().getAttributeTypeRegistry().contains( "cn" ) );
        ObjectClass person = schemaManager.getRegistries().getObjectClassRegistry().lookup( "person" );
        assertNotNull( person );
        assertEquals( 2, person.getMustAttributeTypes().size() );
        assertEquals( 4, person.getMayAttributeTypes().size() );
    }
    
    /**
     * Try to load a quirky schema. This schema has a lot of issues that violate the
     * standards. Therefore load the schema in relaxed mode. We should be able to work
     * with this schema anyway. E.g. the loader and schema manager should not die on
     * null pointer or similar trivial error.
     */
    @Test
    public void testLoadQuirkySchema() throws Exception
    {
        LdapConnection connection = createFakeConnection( "src/test/resources/schema-quirky.ldif" );
        DefaultSchemaLoader loader = new DefaultSchemaLoader( connection, true );
        Collection<Schema> allEnabled = loader.getAllEnabled();
        assertEquals( 1, allEnabled.size() );
        Schema schema = allEnabled.iterator().next();
        assertNotNull( schema );
//        assertEquals( 26, schema.getContent().size() );

        SchemaManager schemaManager = new DefaultSchemaManager( loader );

        boolean loaded = schemaManager.loadAllEnabledRelaxed();
        
        if ( !loaded )
        {
            fail( "Schema load failed : " + Exceptions.printErrors( schemaManager.getErrors() ) );
        }
        
        assertTrue ( "Surprisingly no errors after load", schemaManager.getErrors().size() > 0 );

        assertTrue( schemaManager.getRegistries().getAttributeTypeRegistry().contains( "cn" ) );
        ObjectClass person = schemaManager.getRegistries().getObjectClassRegistry().lookup( "person" );
        assertNotNull( person );
        assertEquals( 2, person.getMustAttributeTypes().size() );
        assertEquals( 5, person.getMayAttributeTypes().size() );
    }


    private LdapConnection createFakeConnection( final String schemaFileName )
    {
        return new LdapConnection()
        {
            
            @Override
            public void unBind() throws LdapException
            {
            }
            
            
            @Override
            public void setTimeOut( long timeOut )
            {
            }
            
            
            @Override
            public void setSchemaManager( SchemaManager schemaManager )
            {
            }
            
            
            @Override
            public void setBinaryAttributeDetector( BinaryAttributeDetector binaryAttributeDetecter )
            {
            }
            
            
            @Override
            public SearchCursor search( SearchRequest searchRequest ) throws LdapException
            {
                return null;
            }
            
            
            @Override
            public EntryCursor search( String baseDn, String filter, SearchScope scope, String... attributes )
                throws LdapException
            {
                return null;
            }
            
            
            @Override
            public EntryCursor search( Dn baseDn, String filter, SearchScope scope, String... attributes ) throws LdapException
            {
                return null;
            }
            
            
            @Override
            public void rename( Dn entryDn, Rdn newRdn, boolean deleteOldRdn ) throws LdapException
            {
            }
            
            
            @Override
            public void rename( String entryDn, String newRdn, boolean deleteOldRdn ) throws LdapException
            {
            }
            
            
            @Override
            public void rename( Dn entryDn, Rdn newRdn ) throws LdapException
            {
            }
            
            
            @Override
            public void rename( String entryDn, String newRdn ) throws LdapException
            {
            }
            
            
            @Override
            public void moveAndRename( String entryDn, String newDn, boolean deleteOldRdn ) throws LdapException
            {
            }
            
            
            @Override
            public void moveAndRename( Dn entryDn, Dn newDn, boolean deleteOldRdn ) throws LdapException
            {
            }
            
            
            @Override
            public void moveAndRename( String entryDn, String newDn ) throws LdapException
            {
            }
            
            
            @Override
            public void moveAndRename( Dn entryDn, Dn newDn ) throws LdapException
            {
            }
            
            
            @Override
            public void move( Dn entryDn, Dn newSuperiorDn ) throws LdapException
            {
            }
            
            
            @Override
            public void move( String entryDn, String newSuperiorDn ) throws LdapException
            {
            }
            
            
            @Override
            public ModifyDnResponse modifyDn( ModifyDnRequest modDnRequest ) throws LdapException
            {
                return null;
            }
            
            
            @Override
            public ModifyResponse modify( ModifyRequest modRequest ) throws LdapException
            {
                return null;
            }
            
            
            @Override
            public void modify( Entry entry, ModificationOperation modOp ) throws LdapException
            {
            }
            
            
            @Override
            public void modify( String dn, Modification... modifications ) throws LdapException
            {
            }
            
            
            @Override
            public void modify( Dn dn, Modification... modifications ) throws LdapException
            {
            }
            
            
            @Override
            public Entry lookup( String dn, Control[] controls, String... attributes ) throws LdapException
            {
            	return lookup(new Dn(dn));
            }
            
            
            @Override
            public Entry lookup( String dn, String... attributes ) throws LdapException
            {
            	return lookup(new Dn(dn));
            }
            
            
            @Override
            public Entry lookup( Dn dn, Control[] controls, String... attributes ) throws LdapException
            {
            	return lookup(dn);
            }
            
            
            @Override
            public Entry lookup( Dn dn, String... attributes ) throws LdapException
            {
            	return lookup(dn);
            }
            
            
            @Override
            public Entry lookup( String dn ) throws LdapException
            {
                return lookup(new Dn(dn));
            }
            
            
            @Override
            public Entry lookup( Dn dn ) throws LdapException
            {
            	if (dn.isRootDse()) {
            		Entry entry = new DefaultEntry( dn );
            		entry.add( SchemaConstants.SUBSCHEMA_SUBENTRY_AT, SCHEMA_DN );
            		return entry;
            	} else if (dn.toString().equals( SCHEMA_DN )) {
            		Entry entry = loadSchemaEntry( schemaFileName );
            		return entry;
            	} else {
            		throw new UnsupportedOperationException("Unexpected DN "+dn);
            	}
            }


            @Override
            public void loadSchemaRelaxed() throws LdapException
            {
            }
            
            
            @Override
            public void loadSchema() throws LdapException
            {
            }
            
            
            @Override
            public boolean isRequestCompleted( int messageId )
            {
                return true;
            }
            
            
            @Override
            public boolean isControlSupported( String controlOID ) throws LdapException
            {
                return true;
            }
            
            
            @Override
            public boolean isConnected()
            {
                return true;
            }
            
            
            @Override
            public boolean isAuthenticated()
            {
                return false;
            }
            
            
            @Override
            public List<String> getSupportedControls() throws LdapException
            {
                return null;
            }
            
            
            @Override
            public SchemaManager getSchemaManager()
            {
                return null;
            }
            
            
            @Override
            public Entry getRootDse( String... attributes ) throws LdapException
            {
                return lookup( Dn.ROOT_DSE );
            }
            
            
            @Override
            public Entry getRootDse() throws LdapException
            {
                return lookup( Dn.ROOT_DSE );
            }
            
            
            @Override
            public LdapApiService getCodecService()
            {
                return null;
            }
            
            
            @Override
            public BinaryAttributeDetector getBinaryAttributeDetector()
            {
                return null;
            }
            
            
            @Override
            public ExtendedResponse extended( ExtendedRequest extendedRequest ) throws LdapException
            {
                return null;
            }
            
            
            @Override
            public ExtendedResponse extended( Oid oid, byte[] value ) throws LdapException
            {
                return null;
            }
            
            
            @Override
            public ExtendedResponse extended( Oid oid ) throws LdapException
            {
                return null;
            }
            
            
            @Override
            public ExtendedResponse extended( String oid, byte[] value ) throws LdapException
            {
                return null;
            }
            
            
            @Override
            public ExtendedResponse extended( String oid ) throws LdapException
            {
                return null;
            }
            
            
            @Override
            public boolean exists( Dn dn ) throws LdapException
            {
                return false;
            }
            
            
            @Override
            public boolean exists( String dn ) throws LdapException
            {
                return false;
            }
            
            
            @Override
            public boolean doesFutureExistFor( int messageId )
            {
                return false;
            }
            
            
            @Override
            public DeleteResponse delete( DeleteRequest deleteRequest ) throws LdapException
            {
                return null;
            }
            
            
            @Override
            public void delete( Dn dn ) throws LdapException
            {
            }
            
            
            @Override
            public void delete( String dn ) throws LdapException
            {
            }
            
            
            @Override
            public boolean connect() throws LdapException
            {
                return true;
            }
            
            
            @Override
            public CompareResponse compare( CompareRequest compareRequest ) throws LdapException
            {
                return null;
            }
            
            
            @Override
            public boolean compare( Dn dn, String attributeName, Value<?> value ) throws LdapException
            {
                return false;
            }
            
            
            @Override
            public boolean compare( Dn dn, String attributeName, byte[] value ) throws LdapException
            {
                return false;
            }
            
            
            @Override
            public boolean compare( Dn dn, String attributeName, String value ) throws LdapException
            {
                return false;
            }
            
            
            @Override
            public boolean compare( String dn, String attributeName, Value<?> value ) throws LdapException
            {
                return false;
            }
            
            
            @Override
            public boolean compare( String dn, String attributeName, byte[] value ) throws LdapException
            {
                return false;
            }
            
            
            @Override
            public boolean compare( String dn, String attributeName, String value ) throws LdapException
            {
                return false;
            }
            
            
            @Override
            public void close() throws IOException
            {                
            }
            
            
            @Override
            public BindResponse bind( BindRequest bindRequest ) throws LdapException
            {
                return null;
            }
            
            
            @Override
            public void bind( Dn name, String credentials ) throws LdapException
            {
            }
            
            
            @Override
            public void bind( Dn name ) throws LdapException
            {
            }
            
            
            @Override
            public void bind( String name, String credentials ) throws LdapException
            {
            }
            
            
            @Override
            public void bind( String name ) throws LdapException
            {
            }
            
            
            @Override
            public void bind() throws LdapException
            {
            }
            
            
            @Override
            public void anonymousBind() throws LdapException
            {
            }
            
            
            @Override
            public AddResponse add( AddRequest addRequest ) throws LdapException
            {
                return null;
            }
            
            
            @Override
            public void add( Entry entry ) throws LdapException
            {
            }
            
            
            @Override
            public void abandon( AbandonRequest abandonRequest )
            {
            }
            
            
            @Override
            public void abandon( int messageId )
            {
            }
        };
    }
    
    private Entry loadSchemaEntry( String schemaFileName )
    {
    	LdifEntry ldifEntry = null;
    	try
        {
        	InputStream in = new FileInputStream( schemaFileName );
        	LdifReader ldifReader = new LdifReader( in );
            if (ldifReader.hasNext()) 
            {
            	ldifEntry = ldifReader.next();
            }
        
            ldifReader.close();
        }
        catch ( IOException e )
        {
            throw new IllegalStateException( "IO error with " + schemaFileName , e );
        }
    	catch (LdapException e ) {
    		throw new IllegalStateException( "LDAP error with " + schemaFileName , e );
    	}
        if (ldifEntry == null) {
        	throw new IllegalStateException( "No entry in LDIF " + schemaFileName );
        }
        return ldifEntry.getEntry();
    }
}
