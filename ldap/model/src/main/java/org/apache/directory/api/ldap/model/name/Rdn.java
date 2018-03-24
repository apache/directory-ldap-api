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
package org.apache.directory.api.ldap.model.name;


import java.io.Externalizable;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.schema.AttributeType;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.api.util.Chars;
import org.apache.directory.api.util.Hex;
import org.apache.directory.api.util.Serialize;
import org.apache.directory.api.util.Strings;
import org.apache.directory.api.util.Unicode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * This class store the name-component part or the following BNF grammar (as of
 * RFC2253, par. 3, and RFC1779, fig. 1) : <br> - &lt;name-component&gt; ::=
 * &lt;attributeType&gt; &lt;spaces&gt; '=' &lt;spaces&gt;
 * &lt;attributeValue&gt; &lt;attributeTypeAndValues&gt; <br> -
 * &lt;attributeTypeAndValues&gt; ::= &lt;spaces&gt; '+' &lt;spaces&gt;
 * &lt;attributeType&gt; &lt;spaces&gt; '=' &lt;spaces&gt;
 * &lt;attributeValue&gt; &lt;attributeTypeAndValues&gt; | e <br> -
 * &lt;attributeType&gt; ::= [a-zA-Z] &lt;keychars&gt; | &lt;oidPrefix&gt; [0-9]
 * &lt;digits&gt; &lt;oids&gt; | [0-9] &lt;digits&gt; &lt;oids&gt; <br> -
 * &lt;keychars&gt; ::= [a-zA-Z] &lt;keychars&gt; | [0-9] &lt;keychars&gt; | '-'
 * &lt;keychars&gt; | e <br> - &lt;oidPrefix&gt; ::= 'OID.' | 'oid.' | e <br> -
 * &lt;oids&gt; ::= '.' [0-9] &lt;digits&gt; &lt;oids&gt; | e <br> -
 * &lt;attributeValue&gt; ::= &lt;pairs-or-strings&gt; | '#' &lt;hexstring&gt;
 * |'"' &lt;quotechar-or-pairs&gt; '"' <br> - &lt;pairs-or-strings&gt; ::= '\'
 * &lt;pairchar&gt; &lt;pairs-or-strings&gt; | &lt;stringchar&gt;
 * &lt;pairs-or-strings&gt; | e <br> - &lt;quotechar-or-pairs&gt; ::=
 * &lt;quotechar&gt; &lt;quotechar-or-pairs&gt; | '\' &lt;pairchar&gt;
 * &lt;quotechar-or-pairs&gt; | e <br> - &lt;pairchar&gt; ::= ',' | '=' | '+' |
 * '&lt;' | '&gt;' | '#' | ';' | '\' | '"' | [0-9a-fA-F] [0-9a-fA-F] <br> -
 * &lt;hexstring&gt; ::= [0-9a-fA-F] [0-9a-fA-F] &lt;hexpairs&gt; <br> -
 * &lt;hexpairs&gt; ::= [0-9a-fA-F] [0-9a-fA-F] &lt;hexpairs&gt; | e <br> -
 * &lt;digits&gt; ::= [0-9] &lt;digits&gt; | e <br> - &lt;stringchar&gt; ::=
 * [0x00-0xFF] - [,=+&lt;&gt;#;\"\n\r] <br> - &lt;quotechar&gt; ::= [0x00-0xFF] -
 * [\"] <br> - &lt;separator&gt; ::= ',' | ';' <br> - &lt;spaces&gt; ::= ' '
 * &lt;spaces&gt; | e <br>
 * <br>
 * A Rdn is a part of a Dn. It can be composed of many types, as in the Rdn
 * following Rdn :<br>
 * ou=value + cn=other value<br>
 * <br>
 * or <br>
 * ou=value + ou=another value<br>
 * <br>
 * In this case, we have to store an 'ou' and a 'cn' in the Rdn.<br>
 * <br>
 * The types are case insensitive. <br>
 * Spaces before and after types and values are not stored.<br>
 * Spaces before and after '+' are not stored.<br>
 * <br>
 * Thus, we can consider that the following RDNs are equals :<br>
 * <br>
 * 'ou=test 1'<br> ' ou=test 1'<br>
 * 'ou =test 1'<br>
 * 'ou= test 1'<br>
 * 'ou=test 1 '<br> ' ou = test 1 '<br>
 * <br>
 * So are the following :<br>
 * <br>
 * 'ou=test 1+cn=test 2'<br>
 * 'ou = test 1 + cn = test 2'<br> ' ou =test 1+ cn =test 2 ' <br>
 * 'cn = test 2 +ou = test 1'<br>
 * <br>
 * but the following are not equal :<br>
 * 'ou=test 1' <br>
 * 'ou=test 1'<br>
 * because we have more than one spaces inside the value.<br>
 * <br>
 * The Rdn is composed of one or more Ava. Those Avas
 * are ordered in the alphabetical natural order : a &lt; b &lt; c ... &lt; z As the type
 * are not case sensitive, we can say that a = A
 * <br>
 * This class is immutable.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class Rdn implements Cloneable, Externalizable, Iterable<Ava>, Comparable<Rdn>
{
    /** The LoggerFactory used by this class */
    protected static final Logger LOG = LoggerFactory.getLogger( Rdn.class );

    /** An empty Rdn */
    public static final Rdn EMPTY_RDN = new Rdn();

    /**
    * Declares the Serial Version Uid.
    *
    * @see <a
    *      href="http://c2.com/cgi/wiki?AlwaysDeclareSerialVersionUid">Always
    *      Declare Serial Version Uid</a>
    */
    private static final long serialVersionUID = 1L;

    /** The User Provided Rdn */
    private String upName = null;
    
    /** The normalized Rdn */
    private String normName;

    /**
     * Stores all couple type = value. We may have more than one type, if the
     * '+' character appears in the Ava. This is a TreeSet,
     * because we want the Avas to be sorted. An Ava may contain more than one
     * value. In this case, the values are String stored in a List.
     */
    private transient List<Ava> avas = null;

    /**
     * We also keep a set of types, in order to use manipulations. A type is
     * connected with the Ava it represents.
     */
    private transient Map<String, List<Ava>> avaTypes;

    /**
     * We keep the type for a single valued Rdn, to avoid the creation of an HashMap
     */
    private String avaType = null;

    /**
     * A simple Ava is used to store the Rdn for the simple
     * case where we only have a single type=value. This will be 99.99% the
     * case. This avoids the creation of a HashMap.
     */
    protected Ava ava = null;

    /**
     * The number of Avas. We store this number here to avoid complex
     * manipulation of Ava and Avas
     */
    private int nbAvas = 0;

    /** CompareTo() results */
    public static final int UNDEFINED = Integer.MAX_VALUE;

    /** Constant used in comparisons */
    public static final int SUPERIOR = 1;

    /** Constant used in comparisons */
    public static final int INFERIOR = -1;

    /** Constant used in comparisons */
    public static final int EQUAL = 0;

    /** A flag used to tell if the Rdn has been normalized */
    private boolean normalized = false;

    /** the schema manager */
    private transient SchemaManager schemaManager;

    /** The computed hashcode */
    private volatile int h;


    /**
     * A empty constructor.
     */
    public Rdn()
    {
        this( ( SchemaManager ) null );
    }


    /**
     *
     * Creates a new schema aware instance of Rdn.
     *
     * @param schemaManager the schema manager
     */
    public Rdn( SchemaManager schemaManager )
    {
        // Don't waste space... This is not so often we have multiple
        // name-components in a Rdn... So we won't initialize the Map and the
        // treeSet.
        this.schemaManager = schemaManager;
        upName = "";
        normName = "";
        normalized = true;
        h = 0;
    }


    /**
     *  A constructor that parse a String representing a schema aware Rdn.
     *
     * @param schemaManager the schema manager
     * @param rdn the String containing the Rdn to parse
     * @throws LdapInvalidDnException if the Rdn is invalid
     */
    public Rdn( SchemaManager schemaManager, String rdn ) throws LdapInvalidDnException
    {
        if ( Strings.isNotEmpty( rdn ) )
        {
            // Parse the string. The Rdn will be updated.
            parse( schemaManager, rdn, this );

            if ( upName.length() < rdn.length() )
            {
                throw new LdapInvalidDnException( I18n.err( I18n.ERR_13625_INVALID_RDN ) );
            }

            upName = rdn;
        }
        else
        {
            upName = "";
            normName = "";
            normalized = true;
        }

        hashCode();
    }


    /**
     * A constructor that parse a String representing a Rdn.
     *
     * @param rdn the String containing the Rdn to parse
     * @throws LdapInvalidDnException if the Rdn is invalid
     */
    public Rdn( String rdn ) throws LdapInvalidDnException
    {
        this( ( SchemaManager ) null, rdn );
    }


    /**
     * A constructor that constructs a schema aware Rdn from a type and a value.
     * <p>
     * The string attribute values are not interpreted as RFC 414 formatted Rdn
     * strings. That is, the values are used literally (not parsed) and assumed
     * to be un-escaped.
      *
     * @param schemaManager the schema manager
     * @param upType the user provided type of the Rdn
     * @param upValue the user provided value of the Rdn
     * @throws LdapInvalidDnException if the Rdn is invalid
     * @throws LdapInvalidAttributeValueException  If the given AttributeType or value are invalid
     */
    public Rdn( SchemaManager schemaManager, String upType, String upValue ) throws LdapInvalidDnException, LdapInvalidAttributeValueException
    {
        if ( schemaManager != null )
        {
            AttributeType attributeType = schemaManager.getAttributeType( upType );
            addAVA( schemaManager, upType, new Value( attributeType, upValue ) );
        }
        else
        {
            addAVA( schemaManager, upType, new Value( upValue ) );
        }

        StringBuilder sb = new StringBuilder();
        sb.append( upType ).append( '=' ).append( upValue );
        upName = sb.toString();
        
        sb.setLength( 0 );
        sb.append( ava.getNormType() ).append( '=' );
        
        Value value = ava.getValue();
        
        if ( value != null )
        {
            sb.append( value.getNormalized() );
        }
        
        normName = sb.toString();
        normalized = true;

        hashCode();
    }


    /**
     * A constructor that constructs a Rdn from a type and a value.
     *
     * @param upType the user provided type of the Rdn
     * @param upValue the user provided value of the Rdn
     * @throws LdapInvalidDnException if the Rdn is invalid
     * @throws LdapInvalidAttributeValueException  If the given AttributeType or Value are incorrect
     * @see #Rdn( SchemaManager, String, String )
     */
    public Rdn( String upType, String upValue ) throws LdapInvalidDnException, LdapInvalidAttributeValueException
    {
        this( null, upType, upValue );
    }


    /**
     * Creates a new schema aware RDN from a list of AVA
     * 
     * @param schemaManager The schemaManager to use
     * @param avas The AVA that will be used
     * @throws LdapInvalidDnException If the RDN is invalid
     */
    public Rdn( SchemaManager schemaManager, Ava... avas ) throws LdapInvalidDnException
    {
        StringBuilder buffer = new StringBuilder();
        
        for ( int i = 0; i < avas.length; i++ )
        {
            if ( i > 0 )
            {
                buffer.append( '+' );
            }
            
            addAVA( schemaManager, avas[i] );
            buffer.append( avas[i].getName() );
        }
        
        setUpName( buffer.toString() );
        hashCode();
    }


    /**
     * Creates a new RDN from a list of AVA
     * 
     * @param avas The AVA that will be used
     * @throws LdapInvalidDnException If the RDN is invalid
     */
    public Rdn( Ava... avas ) throws LdapInvalidDnException
    {
        this( null, avas );
    }


    /**
     * Constructs an Rdn from the given rdn. The content of the rdn is simply
     * copied into the newly created Rdn.
     *
     * @param rdn The non-null Rdn to be copied.
     */
    public Rdn( Rdn rdn )
    {
        nbAvas = rdn.size();
        upName = rdn.getName();
        normName = rdn.getName();
        normalized = rdn.normalized;
        schemaManager = rdn.schemaManager;

        switch ( rdn.size() )
        {
            case 0:
                hashCode();

                return;

            case 1:
                this.ava = rdn.ava.clone();
                hashCode();

                return;

            default:
                // We must duplicate the treeSet and the hashMap
                avas = new ArrayList<>();
                avaTypes = new HashMap<>();

                for ( Ava currentAva : rdn.avas )
                {
                    avas.add( currentAva );
                    
                    List<Ava> avaList = avaTypes.get( currentAva.getNormType() );
                    
                    if ( avaList == null )
                    {
                        avaList = new ArrayList<>();
                        avaList.add( currentAva );
                        avaTypes.put( currentAva.getNormType(), avaList );
                        avas.add( currentAva );
                    }
                    else
                    {
                        if ( !avaList.contains( currentAva ) )
                        {
                            avaList.add( currentAva );
                            avas.add( currentAva );
                        }
                    }
                }

                hashCode();

                return;
        }
    }


    /**
     * Constructs an Rdn from the given rdn. The content of the rdn is simply
     * copied into the newly created Rdn.
     *
     * @param schemaManager The SchemaManager
     * @param rdn The non-null Rdn to be copied.
     * @throws LdapInvalidDnException If the given Rdn is invalid
     */
    public Rdn( SchemaManager schemaManager, Rdn rdn ) throws LdapInvalidDnException
    {
        nbAvas = rdn.size();
        this.upName = rdn.getName();
        this.schemaManager = schemaManager;
        normalized = rdn.normalized;

        switch ( rdn.size() )
        {
            case 0:
                hashCode();

                return;

            case 1:
                ava = new Ava( schemaManager, rdn.ava );
                
                StringBuilder sb = new StringBuilder();
                
                sb.append( ava.getNormType() );
                sb.append( '=' );
                
                if ( ( ava.getValue() != null ) && ( ava.getValue().getNormalized() != null ) )
                {
                    sb.append( ava.getValue().getNormalized() );
                }
                
                normName = sb.toString();
                normalized = true;
                
                hashCode();

                return;

            default:
                // We must duplicate the treeSet and the hashMap
                avas = new ArrayList<>();
                avaTypes = new HashMap<>();
                sb = new StringBuilder();
                boolean isFirst = true;
                
                for ( Ava currentAva : rdn.avas )
                {
                    Ava tmpAva = currentAva;
                    
                    if ( !currentAva.isSchemaAware() && ( schemaManager != null ) )
                    {
                        tmpAva = new Ava( schemaManager, currentAva );
                    }
                    
                    List<Ava> avaList = avaTypes.get( tmpAva.getNormType() );
                    
                    boolean empty = avaList == null;
                    avaList = addOrdered( avaList, tmpAva );
                    
                    if ( empty )
                    {
                        avaTypes.put( tmpAva.getNormType(), avaList );
                    }
                    
                    addOrdered( avas, tmpAva );
                }
                
                for ( Ava ava : avas )
                {
                    if ( isFirst )
                    {
                        isFirst = false;
                    }
                    else
                    {
                        sb.append( '+' );
                    }
                    
                    sb.append( ava.getNormType() );
                    sb.append( '=' );
                    
                    if ( ( ava.getValue() != null ) && ( ava.getValue().getNormalized() != null ) )
                    {
                        sb.append( ava.getValue().getNormalized() );
                    }
                }

                normName = sb.toString();
                normalized = true;

                hashCode();

                return;
        }
    }
    
    
    /**
     * Add an AVA in a List of Ava, at the right place (ordered)
     */
    private List<Ava> addOrdered( List<Ava> avaList, Ava newAva )
    {
        if ( avaList == null )
        {
            avaList = new ArrayList<>();
        }
        
        if ( avaList.isEmpty() )
        {
            avaList.add( newAva );
            return avaList;
        }
        
        // Insert the AVA in the list, ordered.
        int pos = 0;
        boolean found = false;
        
        for ( Ava avaElem : avaList )
        {
            int comp = newAva.compareTo( avaElem );
                
            if ( comp < 0 )
            {
                avaList.add( pos, newAva );
                found = true;
                break;
            }
            else if ( comp == 0 )
            {
                found = true;
                break;
            }
            else 
            {
                pos++;
            }
        }
        
        if ( !found )
        {
            avaList.add( newAva );
        }
        
        return avaList;
    }


    /**
     * Add an Ava to the current Rdn
     *
     * @param upType The user provided type of the added Rdn.
     * @param type The normalized provided type of the added Rdn.
     * @param upValue The user provided value of the added Rdn
     * @param value The normalized provided value of the added Rdn
     * @throws LdapInvalidDnException
     *             If the Rdn is invalid
     */
    private void addAVA( SchemaManager schemaManager, String type, Value value ) throws LdapInvalidDnException
    {
        // First, let's normalize the type
        AttributeType attributeType;
        String normalizedType = Strings.lowerCaseAscii( type );
        this.schemaManager = schemaManager;

        if ( schemaManager != null )
        {
            attributeType = schemaManager.getAttributeType( normalizedType );
            
            if ( !value.isSchemaAware() )
            {
                if ( attributeType != null )
                {
                    try
                    {
                        value = new Value( attributeType, value );
                    }
                    catch ( LdapInvalidAttributeValueException liave )
                    {
                        throw new LdapInvalidDnException( liave.getMessage(), liave );
                    }
                }
            }
            else
            {
                if ( attributeType != null )
                {
                    normalizedType = attributeType.getOid();
                }
            }
        }

        Ava newAva = new Ava( schemaManager, type, normalizedType, value );

        switch ( nbAvas )
        {
            case 0:
                // This is the first Ava. Just stores it.
                ava = newAva;
                nbAvas = 1;
                avaType = normalizedType;
                hashCode();

                return;

            case 1:
                // We already have an Ava. We have to put it in the HashMap
                // before adding a new one, if it's not already present
                if ( ava.equals( newAva ) )
                {
                    return;
                }

                // First, create the List and the HashMap
                avas = new ArrayList<>();
                avaTypes = new HashMap<>();
                List<Ava> avaList = new ArrayList<>();

                // and store the existing Ava into it.
                avas.add( ava );
                avaList.add( ava );
                avaTypes.put( avaType, avaList );
                nbAvas++;

                ava = null;

                // Now, fall down to the commmon case
                // NO BREAK !!!

            default:
                // add a new Ava, if it's not already present
                avaList = avaTypes.get( newAva.getNormType() );
                
                if ( avaList == null )
                {
                    // Not present, we can add it
                    avaList = new ArrayList<>();
                    avaList.add( newAva );
                    avaTypes.put( newAva.getNormType(), avaList );
                    avas.add( newAva );
                    nbAvas++;
                }
                else
                {
                    // We have at least one Ava with the same type, check if it's the same value
                    if ( !avaList.contains( newAva ) )
                    {
                        // Ok, we can add it
                        avaList.add( newAva );
                        avas.add( newAva );
                        nbAvas++;
                    }
                }
        }
    }


    /**
     * Add an Ava to the current schema aware Rdn
     *
     * @param addedAva The added Ava
     */
    // WARNING : The protection level is left unspecified intentionally.
    // We need this method to be visible from the DnParser class, but not
    // from outside this package.
    /* Unspecified protection */void addAVA( SchemaManager schemaManager, Ava addedAva ) throws LdapInvalidDnException
    {
        this.schemaManager = schemaManager;
        
        if ( !addedAva.isSchemaAware() && ( schemaManager != null ) )
        {
            addedAva = new Ava( schemaManager, addedAva );
        }
        
        String normalizedType = addedAva.getNormType();

        switch ( nbAvas )
        {
            case 0:
                // This is the first Ava. Just stores it.
                ava = addedAva;
                nbAvas = 1;
                avaType = normalizedType;
                hashCode();

                return;

            case 1:
                // We already have an Ava. We have to put it in the HashMap
                // before adding a new one.
                // Check that the first AVA is not for the same attribute
                if ( ava.equals( addedAva ) )
                {
                    throw new LdapInvalidDnException( I18n.err( I18n.ERR_13626_INVALID_RDN_DUPLICATE_AVA, normalizedType ) );
                }

                // First, create the List and the hashMap
                avas = new ArrayList<>();
                avaTypes = new HashMap<>();
                List<Ava> avaList = new ArrayList<>();

                // and store the existing Ava into it.
                avas.add( ava );
                avaList.add( ava );
                avaTypes.put( ava.getNormType(), avaList );

                this.ava = null;

                // Now, fall down to the commmon case
                // NO BREAK !!!

            default:
                // Check that the AT is not already present
                avaList = avaTypes.get( addedAva.getNormType() );
                
                if ( avaList == null )
                {
                    // Not present, we can add it
                    avaList = new ArrayList<>();
                    avaList.add( addedAva );
                    avaTypes.put( addedAva.getNormType(), avaList );
                    avas.add( addedAva );
                    nbAvas++;
                }
                else
                {
                    // We have at least one Ava with the same type, check if it's the same value
                    addOrdered( avaList, addedAva );
                    
                    boolean found = false;
                    
                    for ( int pos = 0; pos < avas.size(); pos++ )
                    {
                        int comp = addedAva.compareTo( avas.get( pos ) );
                        
                        if ( comp < 0 )
                        {
                            avas.add( pos, addedAva );
                            found = true;
                            nbAvas++;
                            break;
                        }
                        else if ( comp == 0 )
                        {
                            found = true;
                            break;
                        }
                    }
                    
                    // Ok, we can add it at the end if we haven't already added it
                    if ( !found )
                    {
                        avas.add( addedAva );
                        nbAvas++;
                    }
                }

                break;
        }
    }


    /**
     * Clear the Rdn, removing all the Avas.
     */
    // WARNING : The protection level is left unspecified intentionally.
    // We need this method to be visible from the DnParser class, but not
    // from outside this package.
    /* No protection */void clear()
    {
        ava = null;
        avas = null;
        avaType = null;
        avaTypes = null;
        nbAvas = 0;
        upName = "";
        normalized = false;
        h = 0;
    }


    /**
     * Get the value of the Ava which type is given as an
     * argument.
     *
     * @param type the type of the NameArgument
     * @return the value to be returned, or null if none found.
     * @throws LdapInvalidDnException if the Rdn is invalid
     */
    public Object getValue( String type ) throws LdapInvalidDnException
    {
        // First, let's normalize the type
        String normalizedType = Strings.lowerCaseAscii( Strings.trim( type ) );

        if ( schemaManager != null )
        {
            AttributeType attributeType = schemaManager.getAttributeType( normalizedType );

            if ( attributeType != null )
            {
                normalizedType = attributeType.getOid();
            }
        }

        switch ( nbAvas )
        {
            case 0:
                return "";

            case 1:
                if ( ava.getNormType().equals( normalizedType ) )
                {
                    if ( ava.getValue() != null )
                    {
                        return ava.getValue().getValue();
                    }
                    else
                    {
                        return null;
                    }
                }

                return "";

            default:
                List<Ava> avaList = avaTypes.get( normalizedType );
                
                if ( avaList != null )
                {
                    for ( Ava elem : avaList )
                    {
                        if ( elem.getNormType().equals( normalizedType ) )
                        {
                            if ( elem.getValue() != null )
                            {
                                return elem.getValue().getValue();
                            }
                            else
                            {
                                return null;
                            }
                        }
                    }

                    return null;
                }

                return null;
        }
    }

    
    /**
     * Get the Ava which type is given as an argument. If we
     * have more than one value associated with the type, we will return only
     * the first one.
     *
     * @param type The type of the NameArgument to be returned
     * @return The Ava, of null if none is found.
     */
    public Ava getAva( String type )
    {
        // First, let's normalize the type
        String normalizedType = Strings.lowerCaseAscii( Strings.trim( type ) );

        switch ( nbAvas )
        {
            case 0:
                return null;

            case 1:
                if ( ava.getNormType().equals( normalizedType ) )
                {
                    return ava;
                }

                return null;

            default:
                List<Ava> avaList = avaTypes.get( normalizedType );

                if ( avaList != null )
                {
                    return avaList.get( 0 );
                }

                return null;
        }
    }


    /**
     * Retrieves the components of this Rdn as an iterator of Avas.
     * The effect on the iterator of updates to this Rdn is undefined. If the
     * Rdn has zero components, an empty (non-null) iterator is returned.
     *
     * @return an iterator of the components of this Rdn, each an Ava
     */
    @Override
    public Iterator<Ava> iterator()
    {
        if ( nbAvas < 2 )
        {
            return new Iterator<Ava>()
            {
                private boolean hasMoreElement = nbAvas == 1;


                @Override
                public boolean hasNext()
                {
                    return hasMoreElement;
                }


                @Override
                public Ava next()
                {
                    Ava obj = ava;
                    hasMoreElement = false;
                    return obj;
                }


                @Override
                public void remove()
                {
                    // nothing to do
                }
            };
        }
        else
        {
            return avas.iterator();
        }
    }


    /**
     * Clone the Rdn
     *
     * @return A clone of the current Rdn
     */
    @Override
    public Rdn clone()
    {
        try
        {
            Rdn rdn = ( Rdn ) super.clone();
            rdn.normalized = normalized;

            // The Ava is immutable. We won't clone it

            switch ( rdn.size() )
            {
                case 0:
                    break;

                case 1:
                    rdn.ava = this.ava.clone();
                    rdn.avaTypes = avaTypes;
                    break;

                default:
                    // We must duplicate the treeSet and the hashMap
                    rdn.avaTypes = new HashMap<>();
                    rdn.avas = new ArrayList<>();

                    for ( Ava currentAva : this.avas )
                    {
                        rdn.avas.add( currentAva.clone() );
                        List<Ava> avaList = new ArrayList<>();
                        
                        for ( Ava elem : avaTypes.get( currentAva.getNormType() ) )
                        {
                            avaList.add( elem.clone() );
                        }

                        rdn.avaTypes.put( currentAva.getNormType(), avaList );
                    }

                    break;
            }

            return rdn;
        }
        catch ( CloneNotSupportedException cnse )
        {
            throw new Error( I18n.err( I18n.ERR_13621_ASSERTION_FAILURE ), cnse );
        }
    }


    /**
     * @return the user provided name
     */
    public String getName()
    {
        return upName;
    }


    /**
     * Set the User Provided Name.
     *
     * Package private because Rdn is immutable, only used by the Dn parser.
     *
     * @param upName the User Provided dame
     */
    void setUpName( String upName )
    {
        this.upName = upName;
    }


    /**
     * @return the normalized name
     */
    public String getNormName()
    {
        return normName;
    }


    /**
     * Set the normalized Name.
     *
     * Package private because Rdn is immutable, only used by the Dn parser.
     *
     * @param normName the Normalized dame
     */
    void setNormName( String normName )
    {
        this.normName = normName;
        normalized = true;
    }


    /**
     * Return the unique Ava, or the first one of we have more
     * than one
     *
     * @return The first Ava of this Rdn
     */
    public Ava getAva()
    {
        switch ( nbAvas )
        {
            case 0:
                return null;

            case 1:
                return ava;

            default:
                return avas.get( 0 );
        }
    }


    /**
     * Return the Nth Ava
     * 
     * @param pos The Ava we are looking for
     *
     * @return The Ava at the given position in this Rdn
     */
    public Ava getAva( int pos )
    {
        if ( pos > nbAvas )
        {
            return null;
        }
        
        if ( pos == 0 )
        {
            if ( nbAvas == 1 )
            {
                return ava;
            }
            else
            {
                    return avas.get( 0 );
            }
        }
        else
        {
            return avas.get( pos );
        }
    }


    /**
     * Return the user provided type, or the first one of we have more than one (the lowest)
     *
     * @return The first user provided type of this Rdn
     */
    public String getType()
    {
        switch ( nbAvas )
        {
            case 0:
                return null;

            case 1:
                return ava.getType();

            default:
                return avas.get( 0 ).getType();
        }
    }


    /**
     * Return the normalized type, or the first one of we have more than one (the lowest)
     *
     * @return The first normalized type of this Rdn
     */
    public String getNormType()
    {
        switch ( nbAvas )
        {
            case 0:
                return null;

            case 1:
                return ava.getNormType();

            default:
                return avas.get( 0 ).getNormType();
        }
    }


    /**
     * Return the User Provided value, as a String
     *
     * @return The first User provided value of this Rdn
     */
    public String getValue()
    {
        switch ( nbAvas )
        {
            case 0:
                return null;

            case 1:
                return ava.getValue().getValue();

            default:
                return avas.get( 0 ).getValue().getValue();
        }
    }


    /**
     * Compares the specified Object with this Rdn for equality. Returns true if
     * the given object is also a Rdn and the two Rdns represent the same
     * attribute type and value mappings. The order of components in
     * multi-valued Rdns is not significant.
     *
     * @param that Rdn to be compared for equality with this Rdn
     * @return true if the specified object is equal to this Rdn
     */
    @Override
    public boolean equals( Object that )
    {
        if ( this == that )
        {
            return true;
        }
        
        Rdn rdn;

        if ( that instanceof String )
        {
            try
            {
                rdn = new Rdn( schemaManager, ( String ) that );
            }
            catch ( LdapInvalidDnException e )
            {
                return false;
            }
        }
        else if ( !( that instanceof Rdn ) )
        {
            return false;
        }
        else
        {
            rdn = ( Rdn ) that;
        }
        
        if ( rdn.nbAvas != nbAvas )
        {
            // We don't have the same number of Avas. The Rdn which
            // has the higher number of Ava is the one which is
            // superior
            return false;
        }

        switch ( nbAvas )
        {
            case 0:
                return true;

            case 1:
                return ava.equals( rdn.ava );

            default:
                // We have more than one value. We will
                // go through all of them.

                // the types are already normalized and sorted in the Avas Map
                // so we could compare the first element with all of the second
                // Ava elements, etc.
                for ( Ava paramAva : rdn.avas )
                {
                    List<Ava> avaList = avaTypes.get( paramAva.getNormType() );
                    
                    if ( ( avaList == null ) || !avaList.contains( paramAva ) )
                    {
                        return false;
                    }
                }
                
                return true;
        }
    }


    /**
     * Get the number of Avas of this Rdn
     *
     * @return The number of Avas in this Rdn
     */
    public int size()
    {
        return nbAvas;
    }


    /**
     * Unescape the given string according to RFC 2253 If in &lt;string&gt; form, a
     * LDAP string representation asserted value can be obtained by replacing
     * (left-to-right, non-recursively) each &lt;pair&gt; appearing in the &lt;string&gt; as
     * follows: 
     * <ul>
     * <li>replace &lt;ESC&gt;&lt;ESC&gt; with &lt;ESC&gt;</li>
     * <li>replace &lt;ESC&gt;&lt;special&gt; with &lt;special&gt;</li>
     * <li>replace &lt;ESC&gt;&lt;hexpair&gt; with the octet indicated by the &lt;hexpair&gt;</li>
     * </ul>
     * If in &lt;hexstring&gt; form, a BER representation can be obtained
     * from converting each &lt;hexpair&gt; of the &lt;hexstring&gt; to the octet indicated
     * by the &lt;hexpair&gt;
     *
     * @param value The value to be unescaped
     * @return Returns a string value as a String, and a binary value as a byte
     *         array.
     * @throws IllegalArgumentException When an Illegal value is provided.
     */
    public static Object unescapeValue( String value )
    {
        if ( Strings.isEmpty( value ) )
        {
            return "";
        }

        char[] chars = value.toCharArray();

        // If the value is contained into double quotes, return it as is.
        if ( ( chars[0] == '\"' ) && ( chars[chars.length - 1] == '\"' ) )
        {
            return new String( chars, 1, chars.length - 2 );
        }

        if ( chars[0] == '#' )
        {
            if ( chars.length == 1 )
            {
                // The value is only containing a #
                return Strings.EMPTY_BYTES;
            }

            if ( ( chars.length % 2 ) != 1 )
            {
                throw new IllegalArgumentException( I18n.err( I18n.ERR_13613_VALUE_NOT_IN_HEX_FORM_ODD_NUMBER ) );
            }

            // HexString form
            byte[] hexValue = new byte[( chars.length - 1 ) / 2];
            int pos = 0;

            for ( int i = 1; i < chars.length; i += 2 )
            {
                if ( Chars.isHex( chars, i ) && Chars.isHex( chars, i + 1 ) )
                {
                    hexValue[pos++] = Hex.getHexValue( chars[i], chars[i + 1] );
                }
                else
                {
                    throw new IllegalArgumentException( I18n.err( I18n.ERR_13614_VALUE_NOT_IN_HEX_FORM ) );
                }
            }

            return hexValue;
        }
        else
        {
            boolean escaped = false;
            boolean isHex = false;
            byte pair = -1;
            int pos = 0;

            byte[] bytes = new byte[chars.length * 6];

            for ( int i = 0; i < chars.length; i++ )
            {
                if ( escaped )
                {
                    escaped = false;

                    switch ( chars[i] )
                    {
                        case '\\':
                        case '"':
                        case '+':
                        case ',':
                        case ';':
                        case '<':
                        case '>':
                        case '#':
                        case '=':
                        case ' ':
                            bytes[pos++] = ( byte ) chars[i];
                            break;

                        default:
                            if ( Chars.isHex( chars, i ) )
                            {
                                isHex = true;
                                pair = ( byte ) ( Hex.getHexValue( chars[i] ) << 4 );
                            }

                            break;
                    }
                }
                else
                {
                    if ( isHex )
                    {
                        if ( Chars.isHex( chars, i ) )
                        {
                            pair += Hex.getHexValue( chars[i] );
                            bytes[pos++] = pair;
                            isHex = false;
                            pair = 0;
                        }
                    }
                    else
                    {
                        switch ( chars[i] )
                        {
                            case '\\':
                                escaped = true;
                                break;

                            // We must not have a special char
                            // Specials are : '"', '+', ',', ';', '<', '>', ' ',
                            // '#' and '='
                            case '"':
                            case '+':
                            case ',':
                            case ';':
                            case '<':
                            case '>':
                            case '#':
                                if ( i != 0 )
                                {
                                    // '#' are allowed if not in first position
                                    bytes[pos++] = '#';
                                    break;
                                }

                            case ' ':
                                if ( ( i == 0 ) || ( i == chars.length - 1 ) )
                                {
                                    throw new IllegalArgumentException( I18n.err( I18n.ERR_13615_UNESCAPED_CHARS_NOT_ALLOWED ) );
                                }
                                else
                                {
                                    bytes[pos++] = ' ';
                                    break;
                                }

                            default:
                                if ( chars[i] < 128 )
                                {
                                    bytes[pos++] = ( byte ) chars[i];
                                }
                                else
                                {
                                    byte[] result = Unicode.charToBytes( chars[i] );
                                    System.arraycopy( result, 0, bytes, pos, result.length );
                                    pos += result.length;
                                }

                                break;
                        }
                    }
                }
            }

            return Strings.utf8ToString( bytes, pos );
        }
    }


    /**
     * Transform a value in a String, accordingly to RFC 2253
     *
     * @param value The attribute value to be escaped
     * @return The escaped string value.
     */
    public static String escapeValue( String value )
    {
        if ( Strings.isEmpty( value ) )
        {
            return "";
        }

        char[] chars = value.toCharArray();
        char[] newChars = new char[chars.length * 3];
        int pos = 0;

        for ( int i = 0; i < chars.length; i++ )
        {
            switch ( chars[i] )
            {
                case ' ':
                    if ( ( i > 0 ) && ( i < chars.length - 1 ) )
                    {
                        newChars[pos++] = chars[i];
                    }
                    else
                    {
                        newChars[pos++] = '\\';
                        newChars[pos++] = chars[i];
                    }

                    break;

                case '#':
                    if ( i != 0 )
                    {
                        newChars[pos++] = chars[i];
                    }
                    else
                    {
                        newChars[pos++] = '\\';
                        newChars[pos++] = chars[i];
                    }

                    break;

                case '"':
                case '+':
                case ',':
                case ';':
                case '=':
                case '<':
                case '>':
                case '\\':
                    newChars[pos++] = '\\';
                    newChars[pos++] = chars[i];
                    break;

                case 0x7F:
                    newChars[pos++] = '\\';
                    newChars[pos++] = '7';
                    newChars[pos++] = 'F';
                    break;

                case 0x00:
                case 0x01:
                case 0x02:
                case 0x03:
                case 0x04:
                case 0x05:
                case 0x06:
                case 0x07:
                case 0x08:
                case 0x09:
                case 0x0A:
                case 0x0B:
                case 0x0C:
                case 0x0D:
                case 0x0E:
                case 0x0F:
                    newChars[pos++] = '\\';
                    newChars[pos++] = '0';
                    newChars[pos++] = Strings.dumpHex( ( byte ) ( chars[i] & 0x0F ) );
                    break;

                case 0x10:
                case 0x11:
                case 0x12:
                case 0x13:
                case 0x14:
                case 0x15:
                case 0x16:
                case 0x17:
                case 0x18:
                case 0x19:
                case 0x1A:
                case 0x1B:
                case 0x1C:
                case 0x1D:
                case 0x1E:
                case 0x1F:
                    newChars[pos++] = '\\';
                    newChars[pos++] = '1';
                    newChars[pos++] = Strings.dumpHex( ( byte ) ( chars[i] & 0x0F ) );
                    break;

                default:
                    newChars[pos++] = chars[i];
                    break;
            }
        }

        return new String( newChars, 0, pos );
    }
    
    
    /**
     * @return The RDN as an escaped String
     */
    public String getEscaped()
    {
        StringBuilder sb = new StringBuilder();
        
        switch ( nbAvas )
        {
            case 0:
                return "";

            case 1:
                sb.append( ava.getEscaped() );

                break;

            default:
                boolean isFirst = true;
                
                for ( Ava atav : avas )
                {
                    if ( isFirst )
                    {
                        isFirst = false;
                    }
                    else
                    {
                        sb.append( '+' );
                    }
                    
                    sb.append( atav.getEscaped() );
                }

                break;
        }
        
        return sb.toString();
    }


    /**
     * Transform a value in a String, accordingly to RFC 2253
     *
     * @param attrValue The attribute value to be escaped
     * @return The escaped string value.
     */
    public static String escapeValue( byte[] attrValue )
    {
        if ( Strings.isEmpty( attrValue ) )
        {
            return "";
        }

        String value = Strings.utf8ToString( attrValue );

        return escapeValue( value );
    }


    /**
     * Tells if the Rdn is schema aware.
     *
     * @return <code>true</code> if the Rdn is schema aware
     */
    public boolean isSchemaAware()
    {
        return schemaManager != null;
    }


    /**
     * Validate a NameComponent : <br>
     * <p>
     * &lt;name-component&gt; ::= &lt;attributeType&gt; &lt;spaces&gt; '='
     * &lt;spaces&gt; &lt;attributeValue&gt; &lt;nameComponents&gt;
     * </p>
     *
     * @param dn The string to parse
     * @return <code>true</code> if the Rdn is valid
     */
    public static boolean isValid( String dn )
    {
        Rdn rdn = new Rdn();

        try
        {
            parse( null, dn, rdn );

            return true;
        }
        catch ( LdapInvalidDnException e )
        {
            return false;
        }
    }


    /**
     * Validate a NameComponent : <br>
     * <p>
     * &lt;name-component&gt; ::= &lt;attributeType&gt; &lt;spaces&gt; '='
     * &lt;spaces&gt; &lt;attributeValue&gt; &lt;nameComponents&gt;
     * </p>
     *
     * @param schemaManager The Schemamanager to use
     * @param dn The string to parse
     * @return <code>true</code> if the Rdn is valid
     */
    public static boolean isValid( SchemaManager schemaManager, String dn )
    {
        Rdn rdn = new Rdn( schemaManager );

        try
        {
            parse( schemaManager, dn, rdn );

            return true;
        }
        catch ( LdapInvalidDnException e )
        {
            return false;
        }
    }


    /**
     * Parse a NameComponent : <br>
     * <p>
     * &lt;name-component&gt; ::= &lt;attributeType&gt; &lt;spaces&gt; '='
     * &lt;spaces&gt; &lt;attributeValue&gt; &lt;nameComponents&gt;
     * </p>
     *
     * @param dn The String to parse
     * @param rdn The Rdn to fill. Beware that if the Rdn is not empty, the new
     *            AttributeTypeAndValue will be added.
     * @throws LdapInvalidDnException If the NameComponent is invalid
     */
    private static void parse( SchemaManager schemaManager, String dn, Rdn rdn ) throws LdapInvalidDnException
    {
        try
        {
            FastDnParser.parseRdn( schemaManager, dn, rdn );
        }
        catch ( TooComplexDnException e )
        {
            rdn.clear();
            new ComplexDnParser().parseRdn( schemaManager, dn, rdn );
        }
    }


    /**
      * Gets the hashcode of this rdn.
      *
      * @see java.lang.Object#hashCode()
      * @return the instance's hash code
      */
    @Override
    public int hashCode()
    {
        if ( h == 0 )
        {
            h = 37;

            switch ( nbAvas )
            {
                case 0:
                    // An empty Rdn
                    break;

                case 1:
                    // We have a single Ava
                    h = h * 17 + ava.hashCode();
                    break;

                default:
                    // We have more than one Ava

                    for ( Ava ata : avas )
                    {
                        h = h * 17 + ata.hashCode();
                    }

                    break;
            }
        }

        return h;
    }


    /**
     * Serialize a RDN into a byte[]
     * 
     * @param buffer The buffer which will contain the serilaized form of this RDN
     * @param pos The position in the buffer where to store the RDN
     * @return The new position in the byte[]
     * @throws IOException If the serialization failed
     */
    public int serialize( byte[] buffer, int pos ) throws IOException
    {
        // The nbAvas and the HashCode length
        int length = 4 + 4;

        // The NnbAvas
        pos = Serialize.serialize( nbAvas, buffer, pos );

        // The upName
        byte[] upNameBytes = Strings.getBytesUtf8( upName );
        length += 4 + upNameBytes.length;

        // Check that we will be able to store the data in the buffer
        if ( buffer.length - pos < length )
        {
            throw new ArrayIndexOutOfBoundsException();
        }

        // Write the upName
        pos = Serialize.serialize( upNameBytes, buffer, pos );

        // Write the AVAs
        switch ( nbAvas )
        {
            case 0:
                break;

            case 1:
                pos = ava.serialize( buffer, pos );

                break;

            default:
                for ( Ava localAva : avas )
                {
                    pos = localAva.serialize( buffer, pos );
                }

                break;
        }

        // The hash code
        pos = Serialize.serialize( h, buffer, pos );

        return pos;
    }


    /**
     * Deserialize a RDN from a byte[], starting at a given position
     * 
     * @param buffer The buffer containing the RDN
     * @param pos The position in the buffer
     * @return The new position
     * @throws IOException If the serialized value is not a RDN
     * @throws LdapInvalidAttributeValueException If the serialized RDN is invalid
     */
    public int deserialize( byte[] buffer, int pos ) throws IOException, LdapInvalidAttributeValueException
    {
        if ( ( pos < 0 ) || ( pos >= buffer.length ) )
        {
            throw new ArrayIndexOutOfBoundsException();
        }

        // Read the nbAvas
        nbAvas = Serialize.deserializeInt( buffer, pos );
        pos += 4;

        // Read the upName
        byte[] upNameBytes = Serialize.deserializeBytes( buffer, pos );
        pos += 4 + upNameBytes.length;
        upName = Strings.utf8ToString( upNameBytes );

        // Read the AVAs
        switch ( nbAvas )
        {
            case 0:
                break;

            case 1:
                ava = new Ava( schemaManager );
                pos = ava.deserialize( buffer, pos );
                avaType = ava.getNormType();

                break;

            default:
                avas = new ArrayList<>();
                avaTypes = new HashMap<>();

                for ( int i = 0; i < nbAvas; i++ )
                {
                    Ava newAva = new Ava( schemaManager );
                    pos = newAva.deserialize( buffer, pos );
                    avas.add( newAva );
                    
                    List<Ava> avaList = avaTypes.get( newAva.getNormType() );
                    
                    if ( avaList == null )
                    {
                        avaList = new ArrayList<>();
                        avaTypes.put( newAva.getNormType(), avaList );
                    }
                    
                    avaList.add( newAva );
                }

                ava = null;
                avaType = null;

                break;
        }

        // Read the hashCode
        h = Serialize.deserializeInt( buffer, pos );
        pos += 4;

        return pos;
    }


    /**
     * A Rdn is composed of on to many Avas (AttributeType And Value).
     * We should write all those Avas sequencially, following the
     * structure :
     * <ul>
     *   <li>
     *     <b>parentId</b> The parent entry's Id
     *   </li>
     *   <li>
     *     <b>nbAvas</b> The number of Avas to write. Can't be 0.
     *   </li>
     *   <li>
     *     <b>upName</b> The User provided Rdn
     *   </li>
     *   <li>
     *     <b>Avas</b>
     *   </li>
     * </ul>
     * <br>
     * For each Ava :
     * <ul>
     *   <li>
     *     <b>start</b> The position of this Ava in the upName string
     *   </li>
     *   <li>
     *     <b>length</b> The Ava user provided length
     *   </li>
     *   <li>
     *     <b>Call the Ava write method</b> The Ava itself
     *   </li>
     * </ul>
     *
     * @see Externalizable#readExternal(ObjectInput)
     * @param out The stream into which the serialized Rdn will be put
     * @throws IOException If the stream can't be written
     */
    @Override
    public void writeExternal( ObjectOutput out ) throws IOException
    {
        out.writeInt( nbAvas );
        out.writeUTF( upName );

        switch ( nbAvas )
        {
            case 0:
                break;

            case 1:
                ava.writeExternal( out );
                break;

            default:
                for ( Ava localAva : avas )
                {
                    localAva.writeExternal( out );
                }

                break;
        }

        out.writeInt( h );

        out.flush();
    }


    /**
     * We read back the data to create a new RDB. The structure
     * read is exposed in the {@link Rdn#writeExternal(ObjectOutput)}
     * method
     *
     * @see Externalizable#readExternal(ObjectInput)
     * @param in The input stream from which the Rdn will be read
     * @throws IOException If we can't read from the input stream
     * @throws ClassNotFoundException If we can't create a new Rdn
     */
    @Override
    public void readExternal( ObjectInput in ) throws IOException, ClassNotFoundException
    {
        StringBuilder sb = new StringBuilder();
        
        // Read the Ava number
        nbAvas = in.readInt();

        // Read the UPName
        upName = in.readUTF();

        switch ( nbAvas )
        {
            case 0:
                ava = null;
                normName = "";
                break;

            case 1:
                ava = new Ava( schemaManager );
                ava.readExternal( in );
                avaType = ava.getNormType();
                
                buildNormRdn( sb, ava );
                normName = sb.toString();

                break;

            default:
                avas = new ArrayList<>();
                avaTypes = new HashMap<>();
                boolean isFirst = true;

                for ( int i = 0; i < nbAvas; i++ )
                {
                    Ava newAva = new Ava( schemaManager );
                    newAva.readExternal( in );
                    avas.add( newAva );

                    List<Ava> avaList = avaTypes.get( newAva.getNormType() );
                    
                    if ( avaList == null )
                    {
                        avaList = new ArrayList<>();
                        avaTypes.put( newAva.getNormType(), avaList );
                    }

                    if ( isFirst )
                    {
                        isFirst = false;
                    }
                    else
                    {
                        sb.append( '+' );
                    }
                    
                    buildNormRdn( sb, newAva );

                    avaList.add( newAva );
                }

                ava = null;
                avaType = null;
                normName = sb.toString();

                break;
        }

        h = in.readInt();
    }


    private void buildNormRdn( StringBuilder sb, Ava ava )
    {
        sb.append( ava.getNormType() );
        
        sb.append( '=' );
        
        Value val = ava.getValue();
        
        if ( ( val != null ) && ( val.getNormalized() != null ) ) 
        {
            sb.append( ava.getValue().getNormalized() );
        }
    }
    

    /**
     * Compare the current RDN with the provided one. 
     * 
     * @param otherRdn The RDN we want to compare to
     * @return a negative value if the current RDN is below the provided one, a positive value
     * if it's above and 0 if they are equal. 
     */
    @Override
    public int compareTo( Rdn otherRdn )
    {
        if ( otherRdn == null )
        {
            return 1;
        }
        
        if ( nbAvas < otherRdn.nbAvas )
        {
            return -1;
        }
        else if ( nbAvas > otherRdn.nbAvas )
        {
            return 1;
        }
        
        switch ( nbAvas )
        {
            case 0 :
                return 0;
                
            case 1 :
                int comp = ava.compareTo( otherRdn.ava );
                
                if ( comp < 0 )
                {
                    return -1;
                }
                else if ( comp > 0 )
                {
                    return 1;
                }
                else
                {
                    return 0;
                }
                
            default :
                // Loop on all the Avas. We expect the Ava to be ordered
                if ( isSchemaAware() )
                {
                    return normName.compareTo( otherRdn.normName );
                }
                
                int pos = 0;
                
                for ( Ava atav : avas )
                {
                    Ava otherAva = otherRdn.avas.get( pos );
                    
                    comp = atav.compareTo( otherAva );
                    
                    if ( comp != 0 )
                    {
                        if ( comp < 0 )
                        {
                            return -1;
                        }
                        else
                        {
                            return 1;
                        }
                    }
                    
                    pos++;
                }
                
                return 0;
        }
    }


    /**
     * @return a String representation of the Rdn. The caller will get back the user
     * provided Rdn
     */
    @Override
    public String toString()
    {
        return upName == null ? "" : upName;
    }
}
