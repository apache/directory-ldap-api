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
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.DefaultAttribute;
import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapException;
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
import org.apache.directory.api.ldap.model.schema.SchemaManager;
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
    /** The map of Attributes we want to anonymize. They are all associated with anonymizers */
    Map<AttributeType, Anonymizer> attributeAnonymizers = new HashMap<AttributeType, Anonymizer>();

    /** The schemaManager */
    SchemaManager schemaManager;

    /** The list of CL options */
    //private static Options options = new Options();

    /** The configuration file option shot name */
    private static final String CONFIG_FILE_OPT = "f";

    /** The configuration file option */
    //private static final Option configFileOption = new Option( CONFIG_FILE_OPT, "config", true,
    //    "Anonymizer configuration file" );

    /** the file containing the list of attributes and their anonymizers */
    private static String configFile;


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

        // Load the anonymizers
        attributeAnonymizers.put( schemaManager.getAttributeType( SchemaConstants.CAR_LICENSE_AT ),
            new StringAnonymizer() );
        attributeAnonymizers.put( schemaManager.getAttributeType( SchemaConstants.CN_AT ), new StringAnonymizer() );
        attributeAnonymizers.put( schemaManager.getAttributeType( SchemaConstants.DESCRIPTION_AT ),
            new StringAnonymizer() );
        attributeAnonymizers.put( schemaManager.getAttributeType( SchemaConstants.DISPLAY_NAME_AT ),
            new StringAnonymizer() );
        attributeAnonymizers.put( schemaManager.getAttributeType( SchemaConstants.GECOS_AT ), new StringAnonymizer() );
        attributeAnonymizers.put( schemaManager.getAttributeType( SchemaConstants.GID_NUMBER_AT ),
            new IntegerAnonymizer() );
        attributeAnonymizers.put( schemaManager.getAttributeType( SchemaConstants.GIVENNAME_AT ),
            new StringAnonymizer() );
        attributeAnonymizers.put( schemaManager.getAttributeType( SchemaConstants.HOME_DIRECTORY_AT ),
            new StringAnonymizer() );
        attributeAnonymizers.put( schemaManager.getAttributeType( SchemaConstants.HOME_PHONE_AT ),
            new StringAnonymizer() );
        attributeAnonymizers.put( schemaManager.getAttributeType( SchemaConstants.HOME_POSTAL_ADDRESS_AT ),
            new StringAnonymizer() );
        attributeAnonymizers.put( schemaManager.getAttributeType( SchemaConstants.HOST_AT ), new StringAnonymizer() );
        attributeAnonymizers.put( schemaManager.getAttributeType( SchemaConstants.HOUSE_IDENTIFIER_AT ),
            new StringAnonymizer() );
        attributeAnonymizers.put( schemaManager.getAttributeType( SchemaConstants.JPEG_PHOTO_AT ),
            new BinaryAnonymizer() );
        attributeAnonymizers.put( schemaManager.getAttributeType( SchemaConstants.LABELED_URI_AT ),
            new StringAnonymizer() );
        attributeAnonymizers.put( schemaManager.getAttributeType( SchemaConstants.LOCALITY_NAME_AT ),
            new StringAnonymizer() );
        attributeAnonymizers.put( schemaManager.getAttributeType( SchemaConstants.MAIL_AT ), new StringAnonymizer() );
        attributeAnonymizers.put( schemaManager.getAttributeType( SchemaConstants.MANAGER_AT ), new StringAnonymizer() );
        attributeAnonymizers.put( schemaManager.getAttributeType( SchemaConstants.MEMBER_UID_AT ),
            new StringAnonymizer() );
        attributeAnonymizers.put( schemaManager.getAttributeType( SchemaConstants.MOBILE_AT ), new StringAnonymizer() );
        attributeAnonymizers.put( schemaManager.getAttributeType( SchemaConstants.ORGANIZATION_NAME_AT ),
            new StringAnonymizer() );
        attributeAnonymizers.put( schemaManager.getAttributeType( SchemaConstants.ORGANIZATIONAL_UNIT_NAME_AT ),
            new StringAnonymizer() );
        attributeAnonymizers.put( schemaManager.getAttributeType( SchemaConstants.PAGER_AT ), new StringAnonymizer() );
        attributeAnonymizers.put( schemaManager.getAttributeType( SchemaConstants.POSTAL_ADDRESS_AT ),
            new StringAnonymizer() );
        attributeAnonymizers.put( schemaManager.getAttributeType( SchemaConstants.PHOTO_AT ), new StringAnonymizer() );
        attributeAnonymizers.put( schemaManager.getAttributeType( SchemaConstants.SECRETARY_AT ),
            new StringAnonymizer() );
        attributeAnonymizers
            .put( schemaManager.getAttributeType( SchemaConstants.SEE_ALSO_AT ), new StringAnonymizer() );
        attributeAnonymizers.put( schemaManager.getAttributeType( SchemaConstants.SN_AT ), new StringAnonymizer() );
        attributeAnonymizers.put( schemaManager.getAttributeType( SchemaConstants.TELEPHONE_NUMBER_AT ),
            new StringAnonymizer() );
        attributeAnonymizers.put( schemaManager.getAttributeType( SchemaConstants.UID_AT ), new StringAnonymizer() );
        attributeAnonymizers.put( schemaManager.getAttributeType( SchemaConstants.UID_NUMBER_AT ),
            new IntegerAnonymizer() );
        attributeAnonymizers.put( schemaManager.getAttributeType( SchemaConstants.USER_CERTIFICATE_AT ),
            new StringAnonymizer() );
        attributeAnonymizers.put( schemaManager.getAttributeType( SchemaConstants.USER_PASSWORD_AT ),
            new BinaryAnonymizer() );
        attributeAnonymizers.put( schemaManager.getAttributeType( SchemaConstants.USER_PKCS12_AT ),
            new BinaryAnonymizer() );
        attributeAnonymizers.put( schemaManager.getAttributeType( SchemaConstants.USER_SMIME_CERTIFICATE_AT ),
            new BinaryAnonymizer() );
        attributeAnonymizers.put( schemaManager.getAttributeType( SchemaConstants.X500_UNIQUE_IDENTIFIER_AT ),
            new BinaryAnonymizer() );
    }


    public LdifAnonymizer( Map<String, Anonymizer> attributeAnonymizers )
    {
        for ( String attributeId : attributeAnonymizers.keySet() )
        {

        }
    }


    /**
     * {@inheritDoc}
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
                Dn dn = entry.getDn();
                Rdn rdns = dn.getRdn();
                List<Attribute> rdnAttributes = new ArrayList<Attribute>();

                // Iterate on all the RDN's AVAs
                List<Ava> avas = new ArrayList<Ava>();
                boolean dnAnonymized = false;

                for ( Ava ava : rdns )
                {
                    // Get the entry's attribute that is used in the RDN
                    Attribute rdnAttribute = entry.get( ava.getType() );

                    // Create a new Attribute for this value specifically
                    Attribute newRdnAttribute = new DefaultAttribute( rdnAttribute.getUpId(),
                        rdnAttribute.getAttributeType() );

                    // inject the value we just removed
                    newRdnAttribute.add( rdnAttribute.get() );

                    // Remove the RDN value from the entry's attribute
                    rdnAttribute.remove( rdnAttribute.get() );

                    if ( rdnAttribute.size() == 0 )
                    {
                        // The last value has been removed, remove the attribute from the entry
                        entry.remove( rdnAttribute );
                    }

                    // And anonymize it
                    Anonymizer anonymizer = attributeAnonymizers.get( rdnAttribute.getAttributeType() );

                    if ( anonymizer != null )
                    {
                        Attribute anonymizedAttribute = anonymizer.anonymize( newRdnAttribute );
                        dnAnonymized = true;

                        // Keep it for later, we will reinject this value in the entry
                        rdnAttributes.add( anonymizedAttribute );

                        if ( anonymizedAttribute.isHumanReadable() )
                        {
                            avas.add( new Ava( schemaManager, rdnAttribute.getUpId(), anonymizedAttribute.getString() ) );
                        }
                        else
                        {
                            avas.add( new Ava( schemaManager, rdnAttribute.getUpId(), anonymizedAttribute.getBytes() ) );
                        }
                    }
                    else
                    {
                        avas.add( ava );
                    }
                }

                // Recreate the DN if needed
                if ( dnAnonymized )
                {
                    Rdn newRdn = new Rdn( schemaManager, avas.toArray( new Ava[]
                        {} ) );
                    dn = new Dn( newRdn, dn.getParent() );
                }

                // Now, process the entry
                for ( Attribute attribute : entry )
                {
                    Anonymizer anonymizer = attributeAnonymizers.get( attribute.getAttributeType() );

                    if ( anonymizer == null )
                    {
                        newEntry.add( attribute );
                    }
                    else
                    {
                        Attribute anonymizedAttribute = anonymizer.anonymize( attribute );

                        newEntry.add( anonymizedAttribute );
                    }
                }

                // Last, not least, inject the RDN attributes in the entry, if we have some
                for ( Attribute rdnAttribute : rdnAttributes )
                {
                    Attribute attribute = newEntry.get( rdnAttribute.getAttributeType() );

                    if ( attribute == null )
                    {
                        // It has been completely remove, reinject it
                        newEntry.add( rdnAttribute );
                    }
                    else
                    {
                        // Inject the rdn values in the newEntry attributes
                        for ( Value<?> value : rdnAttribute )
                        {
                            attribute.add( value );
                        }
                    }
                }

                newEntry.setDn( dn );
                result.append( LdifUtils.convertToLdif( newEntry ) );
                result.append( "\n" );
            }

            return result.toString();
        }
        finally
        {
            ldifReader.close();
        }
    }


    public static void main( String[] args ) throws IOException, LdapException
    {
        if ( ( args == null ) || ( args.length < 1 ) )
        {
            System.out.println( "No file to anonymize" );
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
