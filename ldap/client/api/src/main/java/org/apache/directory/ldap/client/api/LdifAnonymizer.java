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
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.io.Writer;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
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
import org.apache.directory.api.ldap.model.entry.DefaultModification;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Modification;
import org.apache.directory.api.ldap.model.entry.StringValue;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.ldif.ChangeType;
import org.apache.directory.api.ldap.model.ldif.LdifEntry;
import org.apache.directory.api.ldap.model.ldif.LdifReader;
import org.apache.directory.api.ldap.model.ldif.LdifUtils;
import org.apache.directory.api.ldap.model.ldif.anonymizer.Anonymizer;
import org.apache.directory.api.ldap.model.ldif.anonymizer.BinaryAnonymizer;
import org.apache.directory.api.ldap.model.ldif.anonymizer.CaseSensitiveStringAnonymizer;
import org.apache.directory.api.ldap.model.ldif.anonymizer.IntegerAnonymizer;
import org.apache.directory.api.ldap.model.ldif.anonymizer.StringAnonymizer;
import org.apache.directory.api.ldap.model.ldif.anonymizer.TelephoneNumberAnonymizer;
import org.apache.directory.api.ldap.model.name.Ava;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.name.Rdn;
import org.apache.directory.api.ldap.model.schema.AttributeType;
import org.apache.directory.api.ldap.model.schema.LdapSyntax;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.api.ldap.model.schema.syntaxCheckers.DnSyntaxChecker;
import org.apache.directory.api.ldap.model.schema.syntaxCheckers.NameAndOptionalUIDSyntaxChecker;
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
    private Map<Value<?>, Value<?>> valueMap = new HashMap<>();
    
    /** The set that contains all the values we already have anonymized */
    private Set<Value<?>> valueSet = new HashSet<>();
    
    /** The latest anonymized String value Map */
    private Map<Integer, String> latestStringMap;
    
    /** The latest anonymized byte[] value Map */
    private Map<Integer, byte[]> latestBytesMap;
    
    /** The map of AttributeType'sOID we want to anonymize. They are all associated with anonymizers */
    private Map<String, Anonymizer> attributeAnonymizers = new HashMap<>();
    
    /** The list of existing NamingContexts */
    private Set<Dn> namingContexts = new HashSet<>();

    /** The schemaManager */
    private SchemaManager schemaManager;
    
    /** The PrintStream used to write informations about the processing */
    private PrintStream out = null;

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
            println( "Missing a SchemaManager !" );
            System.exit( -1 );
        }

        init( null, null, null, null );
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

        init( null, null, null, null );
    }
    
    
    /**
     * Set the PrintStream to use to print information about the processing
     * 
     * @param out The PrintStream to use
     */
    public void setOut( PrintStream out )
    {
        this.out = out;
    }
    
    
    /**
     * Print the string into the PrintStream
     */
    private void print( String str )
    {
        if ( out != null )
        {
            out.print( str );
        }
    }
    
    
    /**
     * Print the string into the PrintStream, with a NL at the end
     */
    private void println( String str )
    {
        if ( out != null )
        {
            out.println( str );
        }
    }
    
    
    /**
     * Print a nl into the PrintStream
     */
    private void println()
    {
        if ( out != null )
        {
            out.println();
        }
    }
    
    
    /**
     * Initialize the anonymizer, filling the maps we use.
     */
    private void init( Map<Integer, String> stringLatestValueMap, Map<Integer, byte[]> binaryLatestValueMap, 
        Map<Integer, String> integerLatestValueMap, Map<Integer, String> telephoneNumberLatestValueMap )
    {
        // Load the anonymizers
        attributeAnonymizers.put( SchemaConstants.CAR_LICENSE_AT_OID,
            new StringAnonymizer( stringLatestValueMap ) );
        attributeAnonymizers.put( SchemaConstants.DOMAIN_COMPONENT_AT_OID,
            new StringAnonymizer( stringLatestValueMap ) );
        attributeAnonymizers.put( SchemaConstants.CN_AT_OID, new StringAnonymizer( stringLatestValueMap ) );
        attributeAnonymizers.put( SchemaConstants.DESCRIPTION_AT_OID,
            new StringAnonymizer( stringLatestValueMap ) );
        attributeAnonymizers.put( SchemaConstants.DISPLAY_NAME_AT_OID,
            new StringAnonymizer( stringLatestValueMap ) );
        attributeAnonymizers.put( SchemaConstants.GECOS_AT_OID, new StringAnonymizer( stringLatestValueMap ) );
        attributeAnonymizers.put( SchemaConstants.GID_NUMBER_AT_OID,
            new IntegerAnonymizer( integerLatestValueMap ) );
        attributeAnonymizers.put( SchemaConstants.GIVENNAME_AT_OID,
            new StringAnonymizer( stringLatestValueMap ) );
        attributeAnonymizers.put( SchemaConstants.HOME_DIRECTORY_AT_OID,
            new CaseSensitiveStringAnonymizer( stringLatestValueMap ) );
        attributeAnonymizers.put( SchemaConstants.HOME_PHONE_AT_OID,
            new TelephoneNumberAnonymizer() );
        attributeAnonymizers.put( SchemaConstants.HOME_POSTAL_ADDRESS_AT_OID,
            new StringAnonymizer( stringLatestValueMap ) );
        attributeAnonymizers.put( SchemaConstants.HOST_AT_OID, new StringAnonymizer( stringLatestValueMap ) );
        attributeAnonymizers.put( SchemaConstants.HOUSE_IDENTIFIER_AT_OID,
            new StringAnonymizer( stringLatestValueMap ) );
        attributeAnonymizers.put( SchemaConstants.JPEG_PHOTO_AT_OID,
            new BinaryAnonymizer( binaryLatestValueMap ) );
        attributeAnonymizers.put( SchemaConstants.LABELED_URI_AT_OID,
            new CaseSensitiveStringAnonymizer( stringLatestValueMap ) );
        attributeAnonymizers.put( SchemaConstants.LOCALITY_NAME_AT_OID,
            new StringAnonymizer( stringLatestValueMap ) );
        attributeAnonymizers.put( SchemaConstants.MAIL_AT_OID, new StringAnonymizer( stringLatestValueMap ) );
        attributeAnonymizers.put( SchemaConstants.MANAGER_AT_OID, new StringAnonymizer( stringLatestValueMap ) );
        attributeAnonymizers.put( SchemaConstants.MEMBER_UID_AT_OID,
            new StringAnonymizer( stringLatestValueMap ) );
        attributeAnonymizers.put( SchemaConstants.MOBILE_AT_OID, new TelephoneNumberAnonymizer() );
        attributeAnonymizers.put( SchemaConstants.ORGANIZATION_NAME_AT_OID,
            new StringAnonymizer( stringLatestValueMap ) );
        attributeAnonymizers.put( SchemaConstants.ORGANIZATIONAL_UNIT_NAME_AT_OID,
            new StringAnonymizer( stringLatestValueMap ) );
        attributeAnonymizers.put( SchemaConstants.PAGER_AT_OID, new TelephoneNumberAnonymizer() );
        attributeAnonymizers.put( SchemaConstants.POSTAL_ADDRESS_AT_OID,
            new StringAnonymizer( stringLatestValueMap ) );
        attributeAnonymizers.put( SchemaConstants.PHOTO_AT_OID, new BinaryAnonymizer( binaryLatestValueMap ) );
        attributeAnonymizers.put( SchemaConstants.SECRETARY_AT_OID,
            new StringAnonymizer( stringLatestValueMap ) );
        attributeAnonymizers
            .put( SchemaConstants.SEE_ALSO_AT_OID, new StringAnonymizer( stringLatestValueMap ) );
        attributeAnonymizers.put( SchemaConstants.SN_AT_OID, new StringAnonymizer( stringLatestValueMap ) );
        attributeAnonymizers.put( SchemaConstants.TELEPHONE_NUMBER_AT_OID,
            new TelephoneNumberAnonymizer( telephoneNumberLatestValueMap ) );
        attributeAnonymizers.put( SchemaConstants.UID_AT_OID, new StringAnonymizer( stringLatestValueMap ) );
        attributeAnonymizers.put( SchemaConstants.UID_NUMBER_AT_OID,
            new IntegerAnonymizer( integerLatestValueMap ) );
        attributeAnonymizers.put( SchemaConstants.USER_CERTIFICATE_AT_OID,
            new BinaryAnonymizer( binaryLatestValueMap ) );
        attributeAnonymizers.put( SchemaConstants.USER_PASSWORD_AT_OID,
            new BinaryAnonymizer( binaryLatestValueMap ) );
        attributeAnonymizers.put( SchemaConstants.USER_PKCS12_AT_OID,
            new BinaryAnonymizer( binaryLatestValueMap ) );
        attributeAnonymizers.put( SchemaConstants.USER_SMIME_CERTIFICATE_AT_OID,
            new BinaryAnonymizer( binaryLatestValueMap ) );
        attributeAnonymizers.put( SchemaConstants.X500_UNIQUE_IDENTIFIER_AT_OID,
            new BinaryAnonymizer( binaryLatestValueMap ) );
        attributeAnonymizers.put( SchemaConstants.FACSIMILE_TELEPHONE_NUMBER_AT_OID,
            new TelephoneNumberAnonymizer( telephoneNumberLatestValueMap ) );
    }
    
    
    /**
     * Set the latest value map to a defined anonymizer - if it exists -.
     *
     * @param attributeType The AttributeType we are targetting
     * @param latestValueMap The latest value map for this attribute
     */
    public void setAttributeLatestValueMap( AttributeType attributeType, Map<Integer, ?> latestValueMap )
    {
        Anonymizer anonymizer = attributeAnonymizers.get( attributeType.getOid() );
        
        if ( anonymizer != null )
        {
            if ( attributeType.getSyntax().isHumanReadable() )
            {
                anonymizer.setLatestStringMap( latestValueMap );
            }
            else
            {
                anonymizer.setLatestBytesMap( latestValueMap );
            }
        }
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
            else if ( syntax.getOid().equals( SchemaConstants.DIRECTORY_STRING_SYNTAX ) )
            {
                attributeAnonymizers.put( attributeType.getOid(), new StringAnonymizer() );
            }
            else if ( syntax.getOid().equals( SchemaConstants.TELEPHONE_NUMBER_SYNTAX ) )
            {
                attributeAnonymizers.put( attributeType.getOid(), new TelephoneNumberAnonymizer() );
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
     * @return The list of configured anonymizers
     */
    public Map<String, Anonymizer> getAttributeAnonymizers()
    {
        return attributeAnonymizers;
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
        Ava anonymizedAva;
        
        if ( anonymizedValue == null )
        {
            Attribute attribute = new DefaultAttribute( attributeType );
            attribute.add( value );
            Anonymizer anonymizer = attributeAnonymizers.get( attribute.getAttributeType().getOid() );

            if ( value.isHumanReadable() )
            {
                if ( anonymizer == null )
                {
                    anonymizedAva = new Ava( schemaManager, ava.getType(), value.getString() );
                }
                else
                {
                    Attribute anonymizedAttribute = anonymizer.anonymize( valueMap, valueSet, attribute );
                    anonymizedAva = new Ava( schemaManager, ava.getType(), anonymizedAttribute.getString() );
                }
            }
            else
            {
                if ( anonymizer == null )
                {
                    anonymizedAva = new Ava( schemaManager, ava.getType(), value.getBytes() );
                }
                else
                {
                    Attribute anonymizedAttribute = anonymizer.anonymize( valueMap, valueSet, attribute );

                    anonymizedAva = new Ava( schemaManager, ava.getType(), anonymizedAttribute.getBytes() );
                }
            }
        }
        else
        {
            if ( value.isHumanReadable() )
            {
                anonymizedAva = new Ava( schemaManager, ava.getType(), anonymizedValue.getString() );
            }
            else
            {
                anonymizedAva = new Ava( schemaManager, ava.getType(), anonymizedValue.getBytes() );
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
        
        Rdn[] anonymizedRdns = new Rdn[entryDn.size()];
        int rdnPos = entryDn.size() - 1;

        if ( namingContext != null )
        {
            // Copy the naming contex
            for ( Rdn ncRdn : namingContext )
            {
                anonymizedRdns[rdnPos] = ncRdn;
                rdnPos--;
            }
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
        
        return new Dn( schemaManager, anonymizedRdns );
    }


    /**
     * Anonymize a LDIF 
     * 
     * @param ldifFile The ldif file to anonymize
     * @param writer The Writer to use to write the result
     * @throws LdapException If we got some LDAP related exception
     * @throws IOException If we had some issue during some IO operations
     */
    public void anonymizeFile( String ldifFile, Writer writer ) throws LdapException, IOException
    {
        File inputFile = new File( ldifFile );
        
        if ( !inputFile.exists() )
        {
            println( "Cannot open file " + ldifFile );
            return;
        }
        
        LdifReader ldifReader = new LdifReader( inputFile, schemaManager );
        int count = 0;
        List<LdifEntry> errors = new ArrayList<>();
        List<String> errorTexts = new ArrayList<>();

        try
        {
            for ( LdifEntry ldifEntry : ldifReader )
            {
                count++;
                
                try
                {
                    if ( ldifEntry.isEntry() && !ldifEntry.isChangeAdd() )
                    {
                        // process a full entry. Add changes aren't processed here.
                        Entry newEntry = anonymizeEntry( ldifEntry );
                        
                        writer.write( LdifUtils.convertToLdif( newEntry ) );
                        writer.write( "\n" );
                    }
                    else if ( ldifEntry.isChangeDelete() )
                    {
                        // A Delete operation
                        LdifEntry newLdifEntry = anonymizeChangeDelete( ldifEntry );

                        if ( ldifEntry != null )
                        {
                            writer.write( newLdifEntry.toString() );
                            writer.write( "\n" );
                        }
                    }
                    else if ( ldifEntry.isChangeAdd() )
                    {
                        // A Add operation
                        LdifEntry newLdifEntry = anonymizeChangeAdd( ldifEntry );

                        if ( ldifEntry != null )
                        {
                            writer.write( newLdifEntry.toString() );
                            writer.write( "\n" );
                        }
                    }
                    else if ( ldifEntry.isChangeModify() )
                    {
                        // A Modify operation
                        LdifEntry newLdifEntry = anonymizeChangeModify( ldifEntry );

                        if ( ldifEntry != null )
                        {
                            writer.write( newLdifEntry.toString() );
                            writer.write( "\n" );
                        }
                    }
                    else if ( ldifEntry.isChangeModDn() ||  ldifEntry.isChangeModRdn() )
                    {
                        // A MODDN operation
                        LdifEntry newLdifEntry = anonymizeChangeModDn( ldifEntry );

                        if ( ldifEntry != null )
                        {
                            writer.write( newLdifEntry.toString() );
                            writer.write( "\n" );
                        }
                    }
                    
                    System.out.print( '.' );
                    
                    if ( count % 100  == 0 )
                    {
                        println();
                    }
                }
                catch ( Exception e )
                {
                    e.printStackTrace();
                    System.out.print( '*' );

                    if ( count % 100  == 0 )
                    {
                        println();
                    }
                    
                    errors.add( ldifEntry );
                    errorTexts.add( e.getMessage() );
                }
            }

            println();
            
            if ( !errors.isEmpty() )
            {
                println( "There are " + errors.size() + " bad entries" );
                int i = 0;
                
                for ( LdifEntry ldifEntry : errors )
                {
                    println( "---------------------------------------------------" );
                    println( "error : " + errorTexts.get( i ) );
                    println( ldifEntry.getDn().toString() );
                    i++;
                }
            }
        }
        finally
        {
            println();

            if ( !errors.isEmpty() )
            {
                println( "There are " + errors.size() + " bad entries" );
            }
                
            println( "Nb entries : " + count ); 
            ldifReader.close();
        }
    }
    
    
    /**
     * Anonymize a Modify change
     */
    private LdifEntry anonymizeChangeModify( LdifEntry ldifEntry ) throws LdapException
    {
        Dn entryDn = ldifEntry.getDn();
        LdifEntry newLdifEntry = new LdifEntry( schemaManager );
        newLdifEntry.setChangeType( ChangeType.Modify );

        // Process the DN first
        Dn anonymizedDn = anonymizeDn( entryDn );
        
        newLdifEntry.setDn( anonymizedDn );
        
        // Now, process the entry's attributes
        for ( Modification modification : ldifEntry.getModifications() )
        {
            Attribute attribute = modification.getAttribute();
            AttributeType attributeType = schemaManager.getAttributeType( attribute.getId() );
            
            if ( attributeType == null )
            {
                System.out.println( "\nUnknown AttributeType : " + attribute.getId() + " for entry " + entryDn );
                
                return null;
            }
            
            attribute.apply( attributeType );
            
            // Deal with the special case of a DN syntax
            if ( attributeType.getSyntax().getSyntaxChecker() instanceof DnSyntaxChecker )
            {
                Value<?>[] anonymizedValues = new Value<?>[ attribute.size()];
                int pos = 0;
                
                for ( Value<?> dnValue : modification.getAttribute() )
                {
                    Dn dn = new Dn( schemaManager, dnValue.getString() );
                    Dn newdDn = anonymizeDn( dn );
                    anonymizedValues[pos++] = new StringValue( newdDn.toString() );
                }
                
                Modification anonymizedModification = new DefaultModification( modification.getOperation(), attributeType, anonymizedValues );
                newLdifEntry.addModification( anonymizedModification );
            }
            else
            {
                Anonymizer anonymizer = attributeAnonymizers.get( attributeType.getOid() );

                if ( anonymizer == null )
                {
                    newLdifEntry.addModification( modification );
                }
                else
                {
                    Attribute anonymizedAttribute = anonymizer.anonymize( valueMap, valueSet, attribute );
                    
                    Modification anonymizedModification = new DefaultModification( modification.getOperation(), anonymizedAttribute );
                    newLdifEntry.addModification( anonymizedModification );
                }
            }
        }

        return newLdifEntry;
    }

    
    /**
     * Anonymize a Add change
     */
    private LdifEntry anonymizeChangeAdd( LdifEntry ldifEntry ) throws LdapException
    {
        Dn entryDn = ldifEntry.getDn();
        LdifEntry newLdifEntry = new LdifEntry( schemaManager );
        newLdifEntry.setChangeType( ChangeType.Add );

        // Process the DN first
        Dn anonymizedDn = anonymizeDn( entryDn );
        
        newLdifEntry.setDn( anonymizedDn );
        
        // Now, process the entry's attributes
        for ( Attribute attribute : ldifEntry )
        {
            AttributeType attributeType = attribute.getAttributeType();
            Attribute anonymizedAttribute = new DefaultAttribute( attributeType );
            
            // Deal with the special case of a DN syntax
            
            if ( attributeType.getSyntax().getSyntaxChecker() instanceof DnSyntaxChecker )
            {
                for ( Value<?> dnValue : attribute )
                {
                    Dn dn = new Dn( schemaManager, dnValue.getString() );
                    Dn newdDn = anonymizeDn( dn );
                    anonymizedAttribute.add( newdDn.toString() );
                }
                
                newLdifEntry.addAttribute( attribute );
            }
            else
            {
                Anonymizer anonymizer = attributeAnonymizers.get( attribute.getAttributeType().getOid() );

                if ( anonymizer == null )
                {
                    newLdifEntry.addAttribute( attribute );
                }
                else
                {
                    anonymizedAttribute = anonymizer.anonymize( valueMap, valueSet, attribute );
                    
                    if ( anonymizedAttribute != null )
                    {
                        newLdifEntry.addAttribute( anonymizedAttribute );
                    }
                }
            }
        }

        return newLdifEntry;
    }
    
    
    /**
     * Anonymize a Delete change
     */
    private LdifEntry anonymizeChangeDelete( LdifEntry ldifEntry ) throws LdapException
    {
        Dn entryDn = ldifEntry.getDn();

        // Process the DN, there is nothing more in the entry
        Dn anonymizedDn = anonymizeDn( entryDn );
        
        ldifEntry.setDn( anonymizedDn );
        
        return ldifEntry;
    }
    
    
    /**
     * Anonymize a Delete change
     */
    private LdifEntry anonymizeChangeModDn( LdifEntry ldifEntry ) throws LdapException
    {
        Dn entryDn = ldifEntry.getDn();

        // Process the DN
        Dn anonymizedDn = anonymizeDn( entryDn );
        
        ldifEntry.setDn( anonymizedDn );
        
        // Anonymize the newRdn if any
        String newRdnStr = ldifEntry.getNewRdn();
        
        if ( newRdnStr != null )
        {
            Dn newRdn = new Dn( schemaManager, newRdnStr );
            Dn anonymizedRdn = anonymizeDn( newRdn );
            
            ldifEntry.setNewRdn( anonymizedRdn.toString() );
        }
        
        // Anonymize the neSuperior if any
        String newSuperiorStr = ldifEntry.getNewSuperior();
        
        if ( newSuperiorStr != null )
        {
            Dn newSuperior = new Dn( schemaManager, newSuperiorStr );
            
            Dn anonymizedSuperior = anonymizeDn( newSuperior );
            
            ldifEntry.setNewSuperior( anonymizedSuperior.toString() );
        }

        return ldifEntry;
    }
    
    
    /**
     * Anonymize the full entry
     */
    private Entry anonymizeEntry( LdifEntry ldifEntry ) throws LdapException
    {
        Entry entry = ldifEntry.getEntry();
        Entry newEntry = new DefaultEntry( schemaManager );

        // Process the DN first
        Dn entryDn = entry.getDn();
        
        Dn anonymizedDn = anonymizeDn( entryDn );
        
        // Now, process the entry's attributes
        for ( Attribute attribute : entry )
        {
            AttributeType attributeType = attribute.getAttributeType();
            
            // Deal with the special case of DN
            if ( attributeType.getSyntax().getSyntaxChecker() instanceof DnSyntaxChecker )
            {
                for ( Value<?> dnValue : attribute )
                {
                    Dn dn = new Dn( schemaManager, dnValue.getString() );
                    Dn newdDn = anonymizeDn( dn );
                    newEntry.add( attributeType, newdDn.toString() );
                }
            }
            // Deal with the special case of a NameAndOptionalUID
            else if ( attributeType.getSyntax().getSyntaxChecker() instanceof NameAndOptionalUIDSyntaxChecker )
            {
                for ( Value<?> dnValue : attribute )
                {
                    // Get rid of the # part (UID)
                    String valueStr = dnValue.getString();
                    int uidPos = valueStr.indexOf( '#' );
                    String uid = null;
                    
                    if ( uidPos != -1 )
                    {
                        uid = valueStr.substring( uidPos + 1 );
                        valueStr = valueStr.substring( 0, uidPos ); 
                    }
                    
                    Dn dn = new Dn( schemaManager, valueStr );
                    Dn newDn = anonymizeDn( dn );
                    String newDnStr = newDn.toString();
                    
                    if ( uid != null )
                    {
                        newDnStr = newDnStr + '#' + uid;
                    }
                    
                    newEntry.add( attributeType, newDnStr );
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
                    Attribute anonymizedAttribute = anonymizer.anonymize( valueMap, valueSet, attribute );
                    
                    if ( anonymizedAttribute != null )
                    {
                        newEntry.add( anonymizedAttribute );
                    }
                }
            }
        }

        newEntry.setDn( anonymizedDn );

        return newEntry;
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
                if ( ldifEntry.isEntry() && !ldifEntry.isChangeAdd() )
                {
                    // process a full entry. Add changes aren't preocessed ghere.
                    Entry newEntry = anonymizeEntry( ldifEntry );
                    
                    result.append( LdifUtils.convertToLdif( newEntry ) );
                    result.append( "\n" );
                }
                else if ( ldifEntry.isChangeDelete() )
                {
                    // A Delete operation
                    LdifEntry newLdifEntry = anonymizeChangeDelete( ldifEntry );

                    if ( newLdifEntry != null )
                    {
                        result.append( newLdifEntry );
                        result.append( "\n" );
                    }
                }
                else if ( ldifEntry.isChangeAdd() )
                {
                    // A Add operation
                    LdifEntry newLdifEntry = anonymizeChangeAdd( ldifEntry );

                    if ( newLdifEntry != null )
                    {
                        result.append( newLdifEntry );
                        result.append( "\n" );
                    }
                }
                else if ( ldifEntry.isChangeModify() )
                {
                    // A Modify operation
                    LdifEntry newLdifEntry = anonymizeChangeModify( ldifEntry );

                    if ( newLdifEntry != null )
                    {
                        result.append( newLdifEntry );
                        result.append( "\n" );
                    }
                }
                else if ( ldifEntry.isChangeModDn() ||  ldifEntry.isChangeModRdn() )
                {
                    // A MODDN operation
                    LdifEntry newLdifEntry = anonymizeChangeModDn( ldifEntry );

                    if ( newLdifEntry != null )
                    {
                        result.append( newLdifEntry );
                        result.append( "\n" );
                    }
                }
            }

            return result.toString();
        }
        catch ( Exception e )
        {
            println( "Error :"  + e.getMessage() );
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
     * @return the latest String Value Map
     */
    public Map<Integer, String> getLatestStringMap()
    {
        return latestStringMap;
    }


    /**
     * @param latestStringMap the latest String Value Map to set
     */
    public void setLatestStringMap( Map<Integer, String> latestStringMap )
    {
        this.latestStringMap = latestStringMap;
    }


    /**
     * @return the latest byte[] Value Map
     */
    public Map<Integer, byte[]> getLatestBytesMap()
    {
        return latestBytesMap;
    }


    /**
     * @param latestBytesMap the latest byte[] Value Map to set
     */
    public void setLatestBytesMap( Map<Integer, byte[]> latestBytesMap )
    {
        this.latestBytesMap = latestBytesMap;
    }


    /**
     * The entry point, when used as a standalone application.
     *
     * @param args Contains the arguments : the file to convert. The anonymized 
     * LDIF will be printed on stdout
     * @throws IOException If we had an issue opening the file to anonymise ot writing the result
     * @throws LdapException If we had some issue while processing the LDAP data
     */
    public static void main( String[] args ) throws IOException, LdapException
    {
        if ( ( args == null ) || ( args.length < 1 ) )
        {
            System.out.println( "No file to anonymize" );
            return;
        }

        LdifAnonymizer anonymizer = new LdifAnonymizer();

        String ldifString = null;

        try ( InputStream fis = Files.newInputStream( Paths.get( args[0] ) ) )
        {
    
            try ( BufferedReader br = new BufferedReader( new InputStreamReader( fis, Charset.defaultCharset() ) ) )
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
        }

        String result = anonymizer.anonymize( ldifString );

        System.out.println( result );
    }
}
