/*
 *   Licensed to the Apache Software Foundation (ASF) under one
 *   or more contributor license agreements.  See the NOTICE file
 *   distributed with this work for additional information
 *   regarding copyright ownership.  The ASF licenses this file
 *   to you under the Apache License, Version 2.0 (the
 *   "License"); you may not use this file except in compliance
 *   with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing,
 *   software distributed under the License is distributed on an
 *   "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *   KIND, either express or implied.  See the License for the
 *   specific language governing permissions and limitations
 *   under the License.
 *
 */

package org.apache.directory.ldap.client.api;


import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.Writer;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.DefaultAttribute;
import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.ldif.LdifEntry;
import org.apache.directory.api.ldap.model.ldif.LdifReader;
import org.apache.directory.api.ldap.model.ldif.LdifUtils;
import org.apache.directory.api.ldap.model.ldif.anonymizer.Anonymizer;
import org.apache.directory.api.ldap.model.ldif.anonymizer.BinaryAnonymizer;
import org.apache.directory.api.ldap.model.ldif.anonymizer.IntegerAnonymizer;
import org.apache.directory.api.ldap.model.ldif.anonymizer.StringAnonymizer;
import org.apache.directory.api.ldap.model.name.Ava;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.name.Rdn;
import org.apache.directory.api.ldap.model.schema.AttributeType;
import org.apache.directory.api.ldap.model.schema.LdapSyntax;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.api.ldap.model.schema.syntaxCheckers.DnSyntaxChecker;
import org.apache.directory.api.ldap.schema.manager.impl.DefaultSchemaManager;


/**
 * Anonymize the content of a LDIF file.
 * 
 * We will replace the values of the defined attributes with random chars. There are a default
 * list of attributes that are going to be anonymized :
 * <ul>
 * <li>userPassword</li>
 * <li>displayName</li>
 * <li>givenName</li>
 * <li>surName</li>
 * <li>homePhone</li>
 * <li>homePostalAddress</li>
 * <li>jpegPhoto</li>
 * <li>labeledURI</li>
 * <li>mail</li>
 * <li>manager</li>
 * <li>mobile</li>
 * <li>organizationName</li>
 * <li>pager</li>
 * <li>photo</li>
 * <li>secretary</li>
 * <li>uid</li>
 * <li>userCertificate</li>
 * <li>userPKCS12</li>
 * <li>userSMIMECertificate</li>
 * <li>x500UniqueIdentifier</li>
 * <li>carLicense</li>
 * <li>host</li>
 * <li>locality</li>
 * <li>organizationName</li>
 * <li>organizationalUnitName</li>
 * <li>seelAlso</li>
 * <li>homeDirectory</li>
 * <li>uidNumber</li>
 * <li>gidNumber</li>
 * <li>commonName</li>
 * <li>gecos</li>
 * <li>description</li>
 * <li>memberUid</li>
 * </ul>
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class LdifAnonymizer
{
    /** The map that stores the anonymized values associated to the original value */
    Map<Value<?>, Value<?>> valueMap = new HashMap<Value<?>, Value<?>>();
    
    /** The map of AttributeType'sOID we want to anonymize. They are all associated with anonymizers */
    Map<String, Anonymizer> attributeAnonymizers = new HashMap<String, Anonymizer>();
    
    /** The list of existing NamingContexts */
    Set<Dn> namingContexts = new HashSet<Dn>();

    /** The schemaManager */
    SchemaManager schemaManager;

    /**
     * Creates a default instance of LdifAnonymizer. The list of anonymized attribute
     * is set to a default value.
     *
     */
    public LdifAnonymizer()
    {
        try
        {
            schemaManager = new DefaultSchemaManager();
        }
        catch ( Exception e )
        {
            // Todo : we need a schemaManager
            System.out.println( "Missing a SchemaManager !" );
            System.exit( -1 );
        }

        init();
    }
    

    /**
     * Creates a default instance of LdifAnonymizer. The list of anonymized attribute
     * is set to a default value.
     * 
     * @param schemaManager The SchemaManager instance we will use
     */
    public LdifAnonymizer( SchemaManager schemaManager )
    {
        this.schemaManager = schemaManager;

        init();
    }
    
    
    /**
     * Initialize the anonymizer, filling the maps we use.
     */
    private void init()
    {
        // Load the anonymizers
        attributeAnonymizers.put( SchemaConstants.CAR_LICENSE_AT_OID,
            new StringAnonymizer() );
        attributeAnonymizers.put( SchemaConstants.CN_AT_OID, new StringAnonymizer() );
        attributeAnonymizers.put( SchemaConstants.DESCRIPTION_AT_OID,
            new StringAnonymizer() );
        attributeAnonymizers.put( SchemaConstants.DISPLAY_NAME_AT_OID,
            new StringAnonymizer() );
        attributeAnonymizers.put( SchemaConstants.GECOS_AT_OID, new StringAnonymizer() );
        attributeAnonymizers.put( SchemaConstants.GID_NUMBER_AT_OID,
            new IntegerAnonymizer() );
        attributeAnonymizers.put( SchemaConstants.GIVENNAME_AT_OID,
            new StringAnonymizer() );
        attributeAnonymizers.put( SchemaConstants.HOME_DIRECTORY_AT_OID,
            new StringAnonymizer() );
        attributeAnonymizers.put( SchemaConstants.HOME_PHONE_AT_OID,
            new StringAnonymizer() );
        attributeAnonymizers.put( SchemaConstants.HOME_POSTAL_ADDRESS_AT_OID,
            new StringAnonymizer() );
        attributeAnonymizers.put( SchemaConstants.HOST_AT_OID, new StringAnonymizer() );
        attributeAnonymizers.put( SchemaConstants.HOUSE_IDENTIFIER_AT_OID,
            new StringAnonymizer() );
        attributeAnonymizers.put( SchemaConstants.JPEG_PHOTO_AT_OID,
            new BinaryAnonymizer() );
        attributeAnonymizers.put( SchemaConstants.LABELED_URI_AT_OID,
            new StringAnonymizer() );
        attributeAnonymizers.put( SchemaConstants.LOCALITY_NAME_AT_OID,
            new StringAnonymizer() );
        attributeAnonymizers.put( SchemaConstants.MAIL_AT_OID, new StringAnonymizer() );
        attributeAnonymizers.put( SchemaConstants.MANAGER_AT_OID, new StringAnonymizer() );
        attributeAnonymizers.put( SchemaConstants.MEMBER_UID_AT_OID,
            new StringAnonymizer() );
        attributeAnonymizers.put( SchemaConstants.MOBILE_AT_OID, new StringAnonymizer() );
        attributeAnonymizers.put( SchemaConstants.ORGANIZATION_NAME_AT_OID,
            new StringAnonymizer() );
        attributeAnonymizers.put( SchemaConstants.ORGANIZATIONAL_UNIT_NAME_AT_OID,
            new StringAnonymizer() );
        attributeAnonymizers.put( SchemaConstants.PAGER_AT_OID, new StringAnonymizer() );
        attributeAnonymizers.put( SchemaConstants.POSTAL_ADDRESS_AT_OID,
            new StringAnonymizer() );
        attributeAnonymizers.put( SchemaConstants.PHOTO_AT_OID, new StringAnonymizer() );
        attributeAnonymizers.put( SchemaConstants.SECRETARY_AT_OID,
            new StringAnonymizer() );
        attributeAnonymizers
            .put( SchemaConstants.SEE_ALSO_AT_OID, new StringAnonymizer() );
        attributeAnonymizers.put( SchemaConstants.SN_AT_OID, new StringAnonymizer() );
        attributeAnonymizers.put( SchemaConstants.TELEPHONE_NUMBER_AT_OID,
            new StringAnonymizer() );
        attributeAnonymizers.put( SchemaConstants.UID_AT_OID, new StringAnonymizer() );
        attributeAnonymizers.put( SchemaConstants.UID_NUMBER_AT_OID,
            new IntegerAnonymizer() );
        attributeAnonymizers.put( SchemaConstants.USER_CERTIFICATE_AT_OID,
            new StringAnonymizer() );
        attributeAnonymizers.put( SchemaConstants.USER_PASSWORD_AT_OID,
            new BinaryAnonymizer() );
        attributeAnonymizers.put( SchemaConstants.USER_PKCS12_AT_OID,
            new BinaryAnonymizer() );
        attributeAnonymizers.put( SchemaConstants.USER_SMIME_CERTIFICATE_AT_OID,
            new BinaryAnonymizer() );
        attributeAnonymizers.put( SchemaConstants.X500_UNIQUE_IDENTIFIER_AT_OID,
            new BinaryAnonymizer() );
    }
    
    
    /**
     * Add an attributeType that has to be anonymized
     *
     * @param attributeType the AttributeType that has to be anonymized
     * @throws LdapException If the attributeType cannot be added
     */
    public void addAnonAttributeType( AttributeType attributeType ) throws LdapException
    {
        schemaManager.add( attributeType );
        LdapSyntax syntax = attributeType.getSyntax();
        
        if ( syntax.isHumanReadable() )
        {
            if ( syntax.getOid().equals( SchemaConstants.INTEGER_SYNTAX ) )
            {
                attributeAnonymizers.put( attributeType.getOid(), new IntegerAnonymizer() );
            }
            if ( syntax.getOid().equals( SchemaConstants.DIRECTORY_STRING_SYNTAX ) )
            {
                attributeAnonymizers.put( attributeType.getOid(), new StringAnonymizer() );
            }
        }
        else
        {
            attributeAnonymizers.put( attributeType.getOid(), new BinaryAnonymizer() );
        }
    }
    
    
    /**
     * Add an attributeType that has to be anonymized, with its associated anonymizer.
     *
     * @param attributeType the AttributeType that has to be anonymized
     * @param anonymizer the instance of anonymizer to use with this AttributeType
     * @throws LdapException If the attributeType cannot be added
     */
    public void addAnonAttributeType( AttributeType attributeType, Anonymizer<?> anonymizer ) throws LdapException
    {
        schemaManager.add( attributeType );
        attributeAnonymizers.put( attributeType.getOid(), anonymizer );
    }
    
    
    /**
     * Remove an attributeType that has to be anonymized
     *
     * @param attributeType the AttributeType that we don't want to be anonymized
     * @throws LdapException If the attributeType cannot be removed
     */
    public void removeAnonAttributeType( AttributeType attributeType ) throws LdapException
    {
        attributeAnonymizers.remove( attributeType );
    }
    
    
    /**
     * Add a new NamingContext
     *
     * @param dn The naming context to add
     * @throws LdapInvalidDnException if it's an invalid naming context
     */
    public void addNamingContext( String dn ) throws LdapInvalidDnException
    {
        Dn namingContext = new Dn( schemaManager, dn );
        namingContexts.add( namingContext );
    }

    
    /**
     * Anonymize an AVA
     */
    private Ava anonymizeAva( Ava ava ) throws LdapInvalidDnException, LdapInvalidAttributeValueException
    {
        Value<?> value = ava.getValue();
        AttributeType attributeType = ava.getAttributeType();
        Value<?> anonymizedValue = valueMap.get( value );
        Ava anonymizedAva = null;
        
        if ( anonymizedValue == null )
        {
            Attribute attribute = new DefaultAttribute( attributeType );
            attribute.add( value );
            Anonymizer anonymizer = attributeAnonymizers.get( attribute.getAttributeType().getOid() );

            if ( value.isHumanReadable() )
            {
                if ( anonymizer == null )
                {
                    anonymizedAva = new Ava( schemaManager, attributeType.getName(), value.getString() );
                }
                else
                {
                    Attribute anonymizedAttribute = anonymizer.anonymize( valueMap, attribute );

                    anonymizedAva = new Ava( schemaManager, attributeType.getName(), anonymizedAttribute.getString() );
                }
            }
            else
            {
                if ( anonymizer == null )
                {
                    anonymizedAva = new Ava( schemaManager, attributeType.getName(), value.getBytes() );
                }
                else
                {
                    Attribute anonymizedAttribute = anonymizer.anonymize( valueMap, attribute );

                    anonymizedAva = new Ava( schemaManager, attributeType.getName(), anonymizedAttribute.getBytes() );
                }
            }
        }
        else
        {
            if ( value.isHumanReadable() )
            {
                anonymizedAva = new Ava( schemaManager, attributeType.getName(), anonymizedValue.getString() );
            }
            else
            {
                anonymizedAva = new Ava( schemaManager, attributeType.getName(), anonymizedValue.getBytes() );
            }
        }

        return anonymizedAva;
    }
    
    
    /**
     * Anonymize the entry's DN
     */
    private Dn anonymizeDn( Dn entryDn ) throws LdapException
    {
        // Search for the naming context
        Dn descendant = entryDn;
        Dn namingContext = null;
        
        for ( Dn nc : namingContexts )
        {
            if ( entryDn.isDescendantOf( nc ) )
            { 
                descendant = entryDn.getDescendantOf( nc );
                namingContext = nc;
                break;
            }
        }
        
        if ( namingContext == null )
        {
            throw new LdapException( "No naming context attached with this entry : " + entryDn );
        }

        Rdn[] anonymizedRdns = new Rdn[entryDn.size()];
        int rdnPos = entryDn.size() - 1;

        // Copy the naming contex
        for ( Rdn ncRdn : namingContext )
        {
            anonymizedRdns[rdnPos] = ncRdn;
            rdnPos--;
        }
        
        // Iterate on all the RDN
        for ( Rdn rdn : descendant )
        {
            Ava[] anonymizedAvas = new Ava[rdn.size()];
            int pos = 0;
            
            // Iterate on the AVAs
            for ( Ava ava : rdn )
            {
                Ava anonymizedAva = anonymizeAva( ava );
                anonymizedAvas[pos] = anonymizedAva;
                pos++;
            }

            Rdn anonymizedRdn = new Rdn( schemaManager, anonymizedAvas );
            anonymizedRdns[rdnPos] = anonymizedRdn;
            rdnPos--;
        }
        
        Dn anonymizedDn = new Dn( schemaManager, anonymizedRdns );
        
        return anonymizedDn;
    }


    /**
     * Anonymize a LDIF 
     * 
     * @param ldif The ldif content to anonymize
     * @return an anonymized version of the given ldif
     * @throws LdapException If we got some LDAP related exception
     * @throws IOException If we had some issue during some IO operations
     */
    public void anonymizeFile( String ldifFile, Writer writer ) throws LdapException, IOException
    {
        File inputFile = new File( ldifFile );
        
        if ( !inputFile.exists() )
        {
            System.out.println( "Cannot open file " + ldifFile );
            return;
        }
        
        LdifReader ldifReader = new LdifReader( inputFile, schemaManager );
        int count = 0;
        List<LdifEntry> errors = new ArrayList<LdifEntry>();

        try
        {
            for ( LdifEntry ldifEntry : ldifReader )
            {
                count++;
                
                try
                {
                    Entry entry = ldifEntry.getEntry();
                    Entry newEntry = new DefaultEntry( schemaManager );
    
                    // Process the DN first
                    Dn entryDn = entry.getDn();
                    
                    Dn anonymizedDn = anonymizeDn( entryDn );
                    
                    if ( anonymizedDn == null )
                    {
                        // Wrong entry base DN
                        continue;
                    }
    
                    // Now, process the entry
                    for ( Attribute attribute : entry )
                    {
                        AttributeType attributeType = attribute.getAttributeType();
                        
                        if ( attributeType.getSyntax().getSyntaxChecker() instanceof DnSyntaxChecker )
                        {
                            for ( Value<?> dnValue : attribute )
                            {
                                String dnStr = dnValue.getString();
                                Dn dn = new Dn( schemaManager, dnStr );
                                Dn newdDn = anonymizeDn( dn );
                                newEntry.add( attributeType, newdDn.toString() );
                            }
                        }
                        else
                        {
                            Anonymizer anonymizer = attributeAnonymizers.get( attribute.getAttributeType().getOid() );
        
                            if ( anonymizer == null )
                            {
                                newEntry.add( attribute );
                            }
                            else
                            {
                                Attribute anonymizedAttribute = anonymizer.anonymize( valueMap, attribute );
        
                                newEntry.add( anonymizedAttribute );
                            }
                        }
                    }

                    newEntry.setDn( anonymizedDn );
                    writer.write( LdifUtils.convertToLdif( newEntry ) );
                    writer.write( "\n" );

                    System.out.print( '.' );
                    
                    if ( count % 100  == 0 )
                    {
                        System.out.println();
                    }
                }
                catch ( Exception e )
                {
                    System.out.print( '*' );

                    if ( count % 100  == 0 )
                    {
                        System.out.println();
                    }
                    
                    errors.add( ldifEntry );
                }
            }

            System.out.println();
            
            if ( errors.size() != 0 )
            {
                System.out.println( "There are " + errors.size() + " bad entries" );
                
                for ( LdifEntry ldifEntry : errors )
                {
                    System.out.println( "---------------------------------------------------" );
                    System.out.println( ldifEntry.getDn() );
                }
            }
        }
        finally
        {
            System.out.println();

            if ( errors.size() != 0 )
            {
                System.out.println( "There are " + errors.size() + " bad entries" );
            }
                
            System.out.println( "Nb entries : " + count ); 
            ldifReader.close();
        }
    }


    /**
     * Anonymize a LDIF 
     * 
     * @param ldif The ldif content to anonymize
     * @return an anonymized version of the given ldif
     * @throws LdapException If we got some LDAP related exception
     * @throws IOException If we had some issue during some IO operations
     */
    public String anonymize( String ldif ) throws LdapException, IOException
    {
        LdifReader ldifReader = new LdifReader( schemaManager );

        try
        {
            List<LdifEntry> entries = ldifReader.parseLdif( ldif );
            StringBuilder result = new StringBuilder();

            for ( LdifEntry ldifEntry : entries )
            {
                Entry entry = ldifEntry.getEntry();
                Entry newEntry = new DefaultEntry( schemaManager );

                // Process the DN first
                Dn entryDn = entry.getDn();
                
                Dn anonymizedDn = anonymizeDn( entryDn );
                
                if ( anonymizedDn == null )
                {
                    continue;
                }

                // Now, process the entry
                for ( Attribute attribute : entry )
                {
                    AttributeType attributeType = attribute.getAttributeType();
                    
                    // Deal with the special case of 
                    
                    if ( attributeType.getSyntax().getSyntaxChecker() instanceof DnSyntaxChecker )
                    {
                        for ( Value<?> dnValue : attribute )
                        {
                            Dn dn = new Dn( schemaManager, dnValue.getString() );
                            Dn newdDn = anonymizeDn( dn );
                            newEntry.add( attributeType, newdDn.toString() );
                        }
                    }
                    else
                    {
                        Anonymizer anonymizer = attributeAnonymizers.get( attribute.getAttributeType().getOid() );
    
                        if ( anonymizer == null )
                        {
                            newEntry.add( attribute );
                        }
                        else
                        {
                            Attribute anonymizedAttribute = anonymizer.anonymize( valueMap, attribute );
                            
                            if ( anonymizedAttribute != null )
                            {
                                newEntry.add( anonymizedAttribute );
                            }
                        }
                    }
                }

                newEntry.setDn( anonymizedDn );
                result.append( LdifUtils.convertToLdif( newEntry ) );
                result.append( "\n" );
            }

            return result.toString();
        }
        catch ( Exception e )
        {
            System.out.println( "Error :"  + e.getMessage() );
            return null;
        }
        finally
        {
            ldifReader.close();
        }
    }


    /**
     * @return the valueMap
     */
    public Map<Value<?>, Value<?>> getValueMap()
    {
        return valueMap;
    }


    /**
     * @param valueMap the valueMap to set
     */
    public void setValueMap( Map<Value<?>, Value<?>> valueMap )
    {
        this.valueMap = valueMap;
    }


    /**
     * The entry point, when used as a standalone application.
     *
     * @param args Contains the arguments : the file to convert. The anonymized 
     * LDIF will be printed on stdout
     */
    public static void main( String[] args ) throws IOException, LdapException
    {
        if ( ( args == null ) || ( args.length < 1 ) )
        {
            System.out.println( "No file to anonymize" );
            return;
        }

        LdifAnonymizer anonymizer = new LdifAnonymizer();

        BufferedReader br = new BufferedReader( new FileReader( args[0] ) );
        String ldifString = null;

        try
        {
            StringBuilder sb = new StringBuilder();
            String line = br.readLine();

            while ( line != null )
            {
                sb.append( line );
                sb.append( System.lineSeparator() );
                line = br.readLine();
            }

            ldifString = sb.toString();
        }
        finally
        {
            br.close();
        }

        String result = anonymizer.anonymize( ldifString );

        System.out.println( result );
    }
}
