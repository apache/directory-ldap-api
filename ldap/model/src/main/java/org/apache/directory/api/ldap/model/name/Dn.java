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
import java.util.Iterator;
import java.util.List;

import org.apache.commons.collections.list.UnmodifiableList;
import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.api.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * The Dn class contains a Dn (Distinguished Name). This class is immutable.
 * <br>
 * Its specification can be found in RFC 2253,
 * "UTF-8 String Representation of Distinguished Names".
 * <br>
 * We will store two representation of a Dn :
 * <ul>
 * <li>a user Provider representation, which is the parsed String given by a user</li>
 * <li>an internal representation.</li>
 * </ul>
 *
 * A Dn is formed of RDNs, in a specific order :<br>
 *  Rdn[n], Rdn[n-1], ... Rdn[1], Rdn[0]<br>
 *
 * It represents a position in a hierarchy, in which the root is the last Rdn (Rdn[0]) and the leaf
 * is the first Rdn (Rdn[n]).
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class Dn implements Iterable<Rdn>, Externalizable
{
    /** The LoggerFactory used by this class */
    protected static final Logger LOG = LoggerFactory.getLogger( Dn.class );

    /**
     * Declares the Serial Version Uid.
     *
     * @see <a
     *      href="http://c2.com/cgi/wiki?AlwaysDeclareSerialVersionUid">Always
     *      Declare Serial Version Uid</a>
     */
    private static final long serialVersionUID = 1L;

    /** Value returned by the compareTo method if values are not equals */
    public static final int NOT_EQUAL = -1;

    /** Value returned by the compareTo method if values are equals */
    public static final int EQUAL = 0;

    /**
     *  The RDNs that are elements of the Dn<br>
     * NOTE THAT THESE ARE IN THE OPPOSITE ORDER FROM THAT IMPLIED BY THE JAVADOC!<br>
     * Rdn[0] is rdns.get(n) and Rdn[n] is rdns.get(0)
     * <br>
     * For instance,if the Dn is "dc=c, dc=b, dc=a", then the RDNs are stored as :
     * <ul>
     * <li>[0] : dc=c</li>
     * <li>[1] : dc=b</li>
     * <li>[2] : dc=a</li>
     * </ul>
     */
    protected transient List<Rdn> rdns = new ArrayList<>( 5 );

    /** The user provided name */
    private String upName;

    /** The normalized name */
    private String normName;

    /** A null Dn */
    public static final Dn EMPTY_DN = new Dn();

    /** The rootDSE */
    public static final Dn ROOT_DSE = new Dn();

    /** the schema manager */
    private transient SchemaManager schemaManager;

    /**
     * An iterator over RDNs
     */
    private final class RdnIterator implements Iterator<Rdn>
    {
        // The current index
        int index;


        private RdnIterator()
        {
            index = rdns != null ? rdns.size() - 1 : -1;
        }


        /**
         * {@inheritDoc}
         */
        @Override
        public boolean hasNext()
        {
            return index >= 0;
        }


        /**
         * {@inheritDoc}
         */
        @Override
        public Rdn next()
        {
            return index >= 0 ? rdns.get( index-- ) : null;
        }


        /**
         * {@inheritDoc}
         */
        @Override
        public void remove()
        {
            // Not implemented
        }
    }


    /**
     * Construct an empty Dn object
     */
    public Dn()
    {
        this( ( SchemaManager ) null );
    }


    /**
     * Construct an empty Schema aware Dn object
     * 
     *  @param schemaManager The SchemaManager to use
     */
    public Dn( SchemaManager schemaManager )
    {
        this.schemaManager = schemaManager;
        upName = "";
        normName = "";
    }


    /**
     * Construct an empty Schema aware Dn object
     * 
     *  @param schemaManager The SchemaManager to use
     *  @param dn The Dn to use
     *  @throws LdapInvalidDnException If the Dn is invalid
     */
    public Dn( SchemaManager schemaManager, Dn dn ) throws LdapInvalidDnException
    {
        this.schemaManager = schemaManager;

        if ( dn == null )
        {
            return;
        }

        for ( Rdn rdn : dn.rdns )
        {
            this.rdns.add( new Rdn( schemaManager, rdn ) );
        }

        toUpName();
    }


    /**
     * Creates a new instance of Dn, using varargs to declare the RDNs. Each
     * String is either a full Rdn, or a couple of AttributeType DI and a value.
     * If the String contains a '=' symbol, the the constructor will assume that
     * the String arg contains afull Rdn, otherwise, it will consider that the
     * following arg is the value.<br>
     * The created Dn is Schema aware.
     * <br><br>
     * An example of usage would be :
     * <pre>
     * String exampleName = "example";
     * String baseDn = "dc=apache,dc=org";
     *
     * Dn dn = new Dn( DefaultSchemaManager.INSTANCE,
     *     "cn=Test",
     *     "ou", exampleName,
     *     baseDn);
     * </pre>
     * 
     * @param upRdns The list of String composing the Dn
     * @throws LdapInvalidDnException If the resulting Dn is invalid
     */
    public Dn( String... upRdns ) throws LdapInvalidDnException
    {
        this( null, upRdns );
    }


    /**
     * Creates a new instance of schema aware Dn, using varargs to declare the RDNs. Each
     * String is either a full Rdn, or a couple of AttributeType DI and a value.
     * If the String contains a '=' symbol, the the constructor will assume that
     * the String arg contains afull Rdn, otherwise, it will consider that the
     * following arg is the value.<br>
     * The created Dn is Schema aware.
     * <br><br>
     * An example of usage would be :
     * <pre>
     * String exampleName = "example";
     * String baseDn = "dc=apache,dc=org";
     *
     * Dn dn = new Dn( DefaultSchemaManager.INSTANCE,
     *     "cn=Test",
     *     "ou", exampleName,
     *     baseDn);
     * </pre>
     * 
     * @param schemaManager the schema manager
     * @param upRdns The list of String composing the Dn
     * @throws LdapInvalidDnException If the resulting Dn is invalid
     */
    public Dn( SchemaManager schemaManager, String... upRdns ) throws LdapInvalidDnException
    {
        StringBuilder sbUpName = new StringBuilder();
        boolean valueExpected = false;
        boolean isFirst = true;
        this.schemaManager = schemaManager;

        for ( String upRdn : upRdns )
        {
            if ( Strings.isEmpty( upRdn ) )
            {
                continue;
            }

            if ( isFirst )
            {
                isFirst = false;
            }
            else if ( !valueExpected )
            {
                sbUpName.append( ',' );
            }

            if ( !valueExpected )
            {
                sbUpName.append( upRdn );

                if ( upRdn.indexOf( '=' ) == -1 )
                {
                    valueExpected = true;
                }
            }
            else
            {
                sbUpName.append( "=" ).append( upRdn );

                valueExpected = false;
            }
        }

        if ( !isFirst && valueExpected )
        {
            throw new LdapInvalidDnException( ResultCodeEnum.INVALID_DN_SYNTAX, I18n.err( I18n.ERR_13611_VALUE_MISSING_ON_RDN ) );
        }

        // Stores the representations of a Dn : internal (as a string and as a
        // byte[]) and external.
        upName = sbUpName.toString();
        
        try
        {
            normName = parseInternal( schemaManager, upName, rdns );
        }
        catch ( LdapInvalidDnException e )
        {
            if ( schemaManager == null || !schemaManager.isRelaxed() )
            {
                throw e;
            }
            // Ignore invalid DN formats in relaxed mode.
            // This is needed to support unbelievably insane
            // DN formats such as <GUI=abcd...> format used by
            // Active Directory
        }
    }


    /**
     * Creates a Dn from a list of Rdns.
     *
     * @param rdns the list of Rdns to be used for the Dn
     * @throws LdapInvalidDnException If the resulting Dn is invalid
     */
    public Dn( Rdn... rdns ) throws LdapInvalidDnException
    {
        if ( rdns == null )
        {
            return;
        }

        for ( Rdn rdn : rdns )
        {
            this.rdns.add( rdn );
        }

        toUpName();
    }


    /**
     * Creates a Dn concatenating a Rdn and a Dn.
     *
     * @param rdn the Rdn to add to the Dn
     * @param dn the Dn
     * @throws LdapInvalidDnException If the resulting Dn is invalid
     */
    public Dn( Rdn rdn, Dn dn ) throws LdapInvalidDnException
    {
        if ( ( dn == null ) || ( rdn == null ) )
        {
            throw new IllegalArgumentException( I18n.err( I18n.ERR_13622_DN_OR_RDN_NULL ) );
        }

        for ( Rdn rdnParent : dn )
        {
            rdns.add( 0, rdnParent );
        }

        rdns.add( 0, rdn );

        toUpName();
    }


    /**
     * Creates a Schema aware Dn from a list of Rdns.
     *
     * @param schemaManager The SchemaManager to use
     * @param rdns the list of Rdns to be used for the Dn
     * @throws LdapInvalidDnException If the resulting Dn is invalid
     */
    public Dn( SchemaManager schemaManager, Rdn... rdns ) throws LdapInvalidDnException
    {
        this.schemaManager = schemaManager;
        
        if ( rdns == null )
        {
            return;
        }

        for ( Rdn rdn : rdns )
        {
            if ( rdn.isSchemaAware() )
            {
                this.rdns.add( rdn );
            }
            else
            {
                this.rdns.add( new Rdn( schemaManager, rdn ) );
            }
        }

        toUpName();
    }


    /**
     * Get the associated SchemaManager if any.
     * 
     * @return The SchemaManager
     */
    public SchemaManager getSchemaManager()
    {
        return schemaManager;
    }


    /**
     * Return the User Provided Dn as a String,
     *
     * @return A String representing the User Provided Dn
     */
    private String toUpName()
    {
        if ( rdns.isEmpty() )
        {
            upName = "";
            normName = "";
        }
        else
        {
            StringBuilder sbUpName = new StringBuilder();
            StringBuilder sbNormName = new StringBuilder();
            boolean isFirst = true;

            for ( Rdn rdn : rdns )
            {
                if ( isFirst )
                {
                    isFirst = false;
                }
                else
                {
                    sbUpName.append( ',' );
                    sbNormName.append( ',' );
                }

                sbUpName.append( rdn.getName() );
                sbNormName.append( rdn.getNormName() );
            }

            upName = sbUpName.toString();
            normName = sbNormName.toString();
        }

        return upName;
    }


    /**
     * Gets the hash code of this Dn.
     *
     * @see java.lang.Object#hashCode()
     * @return the instance hash code
     */
    @Override
    public int hashCode()
    {
        int result = 37;

        for ( Rdn rdn : rdns )
        {
            result = result * 17 + rdn.hashCode();
        }

        return result;
    }


    /**
     * Get the user provided Dn
     *
     * @return The user provided Dn as a String
     */
    public String getName()
    {
        return upName == null ? "" : upName;
    }


    /**
     * Get the normalized Dn
     *
     * @return The normalized Dn as a String
     */
    public String getNormName()
    {
        return normName == null ? "" : normName;
    }
    
    
    /**
     * @return The RDN as an escaped String
     */
    public String getEscaped()
    {
        StringBuilder sb = new StringBuilder();
        
        boolean isFirst = true;
        
        for ( Rdn rdn : rdns )
        {
            if ( isFirst )
            {
                isFirst = false;
            }
            else
            {
                sb.append( ',' );
            }
            
            sb.append( rdn.getEscaped() );
        }
        
        return sb.toString();
    }


    /**
     * Sets the up name.
     *
     * Package private because Dn is immutable, only used by the Dn parser.
     *
     * @param upName the new up name
     */
    /* No qualifier */void setUpName( String upName )
    {
        this.upName = upName;
    }


    /**
     * Sets the normalized name.
     *
     * Package private because Dn is immutable, only used by the Dn parser.
     *
     * @param normName the new normalized name
     */
    /* No qualifier */void setNormName( String normName )
    {
        this.normName = normName;
    }


    /**
     * Get the number of RDNs present in the DN
     * @return The umber of RDNs in the DN
     */
    public int size()
    {
        return rdns.size();
    }


    /**
     * Tells if the current Dn is a parent of another Dn.<br>
     * For instance, <b>dc=com</b> is a ancestor
     * of <b>dc=example, dc=com</b>
     *
     * @param dn The child
     * @return true if the current Dn is a parent of the given Dn
     */
    public boolean isAncestorOf( String dn )
    {
        try
        {
            return isAncestorOf( new Dn( dn ) );
        }
        catch ( LdapInvalidDnException lide )
        {
            return false;
        }
    }


    /**
     * Tells if the current Dn is a parent of another Dn.<br>
     * For instance, <b>dc=com</b> is a ancestor
     * of <b>dc=example, dc=com</b>
     *
     * @param dn The child
     * @return true if the current Dn is a parent of the given Dn
     */
    public boolean isAncestorOf( Dn dn )
    {
        if ( dn == null )
        {
            return false;
        }

        return dn.isDescendantOf( this );
    }


    /**
     * Tells if a Dn is a child of another Dn.<br>
     * For instance, <b>dc=example, dc=com</b> is a descendant
     * of <b>dc=com</b>
     *
     * @param dn The parent
     * @return true if the current Dn is a child of the given Dn
     */
    public boolean isDescendantOf( String dn )
    {
        try
        {
            return isDescendantOf( new Dn( schemaManager, dn ) );
        }
        catch ( LdapInvalidDnException lide )
        {
            return false;
        }
    }


    /**
     * Tells if a Dn is a child of another Dn.<br>
     * For instance, <b>dc=example, dc=apache, dc=com</b> is a descendant
     * of <b>dc=com</b>
     *
     * @param dn The parent
     * @return true if the current Dn is a child of the given Dn
     */
    public boolean isDescendantOf( Dn dn )
    {
        if ( ( dn == null ) || dn.isRootDse() )
        {
            return true;
        }

        if ( dn.size() > size() )
        {
            // The name is longer than the current Dn.
            return false;
        }

        // Ok, iterate through all the Rdn of the name,
        // starting a the end of the current list.

        for ( int i = dn.size() - 1; i >= 0; i-- )
        {
            Rdn nameRdn = dn.rdns.get( dn.rdns.size() - i - 1 );
            Rdn ldapRdn = rdns.get( rdns.size() - i - 1 );

            if ( !nameRdn.equals( ldapRdn ) )
            {
                return false;
            }
        }

        return true;
    }


    /**
     * Tells if the Dn contains no Rdn
     *
     * @return <code>true</code> if the Dn is empty
     */
    public boolean isEmpty()
    {
        return rdns.isEmpty();
    }


    /**
     * Tells if the Dn is the RootDSE Dn (ie, an empty Dn)
     *
     * @return <code>true</code> if the Dn is the RootDSE's Dn
     */
    public boolean isRootDse()
    {
        return rdns.isEmpty();
    }


    /**
     * Retrieves a component of this name.
     *
     * @param posn the 0-based index of the component to retrieve. Must be in the
     *            range [0,size()).
     * @return the component at index posn
     * @throws ArrayIndexOutOfBoundsException
     *             if posn is outside the specified range
     */
    public Rdn getRdn( int posn )
    {
        if ( rdns.isEmpty() )
        {
            return null;
        }

        if ( ( posn < 0 ) || ( posn >= rdns.size() ) )
        {
            throw new IllegalArgumentException( I18n.err( I18n.ERR_13623_INVALID_POSITION, posn ) );
        }

        return rdns.get( posn );
    }


    /**
     * Retrieves the last (leaf) component of this name.
     *
     * @return the last component of this Dn
     */
    public Rdn getRdn()
    {
        if ( isNullOrEmpty( this ) )
        {
            return Rdn.EMPTY_RDN;
        }

        return rdns.get( 0 );
    }


    /**
     * Retrieves all the components of this name.
     *
     * @return All the components
     */
    @SuppressWarnings("unchecked")
    public List<Rdn> getRdns()
    {
        return UnmodifiableList.decorate( rdns );
    }


    /**
     * Get the descendant of a given DN, using the ancestr DN. Assuming that
     * a DN has two parts :<br>
     * DN = [descendant DN][ancestor DN]<br>
     * To get back the descendant from the full DN, you just pass the ancestor DN
     * as a parameter. Here is a working example :
     * <pre>
     * Dn dn = new Dn( "cn=test, dc=server, dc=directory, dc=apache, dc=org" );
     * 
     * Dn descendant = dn.getDescendantOf( "dc=apache, dc=org" );
     * 
     * // At this point, the descendant contains cn=test, dc=server, dc=directory"
     * </pre>
     * 
     * @param ancestor The parent DN
     * @return The part of the DN that is the descendant
     * @throws LdapInvalidDnException If the Dn is invalid
     */
    public Dn getDescendantOf( String ancestor ) throws LdapInvalidDnException
    {
        return getDescendantOf( new Dn( schemaManager, ancestor ) );
    }


    /**
     * Get the descendant of a given DN, using the ancestr DN. Assuming that
     * a DN has two parts :<br>
     * DN = [descendant DN][ancestor DN]<br>
     * To get back the descendant from the full DN, you just pass the ancestor DN
     * as a parameter. Here is a working example :
     * <pre>
     * Dn dn = new Dn( "cn=test, dc=server, dc=directory, dc=apache, dc=org" );
     * 
     * Dn descendant = dn.getDescendantOf( "dc=apache, dc=org" );
     * 
     * // At this point, the descendant contains cn=test, dc=server, dc=directory"
     * </pre>
     * 
     * @param ancestor The parent DN
     * @return The part of the DN that is the descendant
     * @throws LdapInvalidDnException If the Dn is invalid
     */
    public Dn getDescendantOf( Dn ancestor ) throws LdapInvalidDnException
    {
        if ( ( ancestor == null ) || ( ancestor.size() == 0 ) )
        {
            return this;
        }

        if ( rdns.isEmpty() )
        {
            return EMPTY_DN;
        }

        int length = ancestor.size();

        if ( length > rdns.size() )
        {
            String message = I18n.err( I18n.ERR_13612_POSITION_NOT_IN_RANGE, length, rdns.size() );
            LOG.error( message );
            throw new ArrayIndexOutOfBoundsException( message );
        }

        Dn newDn = new Dn( schemaManager );
        List<Rdn> rdnsAncestor = ancestor.getRdns();

        for ( int i = 0; i < ancestor.size(); i++ )
        {
            Rdn rdn = rdns.get( size() - 1 - i );
            Rdn rdnDescendant = rdnsAncestor.get( ancestor.size() - 1 - i );

            if ( !rdn.equals( rdnDescendant ) )
            {
                throw new LdapInvalidDnException( ResultCodeEnum.INVALID_DN_SYNTAX );
            }
        }

        for ( int i = 0; i < rdns.size() - length; i++ )
        {
            newDn.rdns.add( rdns.get( i ) );
        }

        newDn.toUpName();

        return newDn;
    }


    /**
     * Get the ancestor of a given DN, using the descendant DN. Assuming that
     * a DN has two parts :<br>
     * DN = [descendant DN][ancestor DN]<br>
     * To get back the ancestor from the full DN, you just pass the descendant DN
     * as a parameter. Here is a working example :
     * <pre>
     * Dn dn = new Dn( "cn=test, dc=server, dc=directory, dc=apache, dc=org" );
     * 
     * Dn ancestor = dn.getAncestorOf( "cn=test, dc=server, dc=directory" );
     * 
     * // At this point, the ancestor contains "dc=apache, dc=org"
     * </pre>
     * 
     * @param descendant The child DN
     * @return The part of the DN that is the ancestor
     * @throws LdapInvalidDnException If the Dn is invalid
     */
    public Dn getAncestorOf( String descendant ) throws LdapInvalidDnException
    {
        return getAncestorOf( new Dn( schemaManager, descendant ) );
    }


    /**
     * Get the ancestor of a given DN, using the descendant DN. Assuming that
     * a DN has two parts :<br>
     * DN = [descendant DN][ancestor DN]<br>
     * To get back the ancestor from the full DN, you just pass the descendant DN
     * as a parameter. Here is a working example :
     * <pre>
     * Dn dn = new Dn( "cn=test, dc=server, dc=directory, dc=apache, dc=org" );
     * 
     * Dn ancestor = dn.getAncestorOf( new Dn( "cn=test, dc=server, dc=directory" ) );
     * 
     * // At this point, the ancestor contains "dc=apache, dc=org"
     * </pre>
     * 
     * @param descendant The child DN
     * @return The part of the DN that is the ancestor
     * @throws LdapInvalidDnException If the Dn is invalid
     */
    public Dn getAncestorOf( Dn descendant ) throws LdapInvalidDnException
    {
        if ( ( descendant == null ) || ( descendant.size() == 0 ) )
        {
            return this;
        }

        if ( rdns.isEmpty() )
        {
            return EMPTY_DN;
        }

        int length = descendant.size();

        if ( length > rdns.size() )
        {
            String message = I18n.err( I18n.ERR_13612_POSITION_NOT_IN_RANGE, length, rdns.size() );
            LOG.error( message );
            throw new ArrayIndexOutOfBoundsException( message );
        }

        Dn newDn = new Dn( schemaManager );
        List<Rdn> rdnsDescendant = descendant.getRdns();

        for ( int i = 0; i < descendant.size(); i++ )
        {
            Rdn rdn = rdns.get( i );
            Rdn rdnDescendant = rdnsDescendant.get( i );

            if ( !rdn.equals( rdnDescendant ) )
            {
                throw new LdapInvalidDnException( ResultCodeEnum.INVALID_DN_SYNTAX );
            }
        }

        for ( int i = length; i < rdns.size(); i++ )
        {
            newDn.rdns.add( rdns.get( i ) );
        }

        newDn.toUpName();

        return newDn;
    }


    /**
     * Add a suffix to the Dn. For instance, if the current Dn is "ou=people",
     * and the suffix "dc=example,dc=com", then the resulting Dn will be 
     * "ou=people,dc=example,dc=com" 
     * 
     * @param suffix the suffix to add
     * @return The resulting Dn with the additional suffix
     * @throws LdapInvalidDnException If the resulting Dn is not valid 
     */
    public Dn add( Dn suffix ) throws LdapInvalidDnException
    {
        if ( ( suffix == null ) || ( suffix.size() == 0 ) )
        {
            return this;
        }

        Dn clonedDn = copy();

        // Concatenate the rdns
        clonedDn.rdns.addAll( 0, suffix.rdns );

        // Regenerate the normalized name and the original string
        if ( clonedDn.isSchemaAware() && suffix.isSchemaAware() )
        {
            if ( clonedDn.size() != 0 )
            {
                clonedDn.upName = suffix.getName() + "," + upName;
            }
        }
        else
        {
            clonedDn.toUpName();
        }

        return clonedDn;
    }


    /**
     * Add a suffix to the Dn. For instance, if the current Dn is "ou=people",
     * and the suffix "dc=example,dc=com", then the resulting Dn will be 
     * "ou=people,dc=example,dc=com" 
     * 
     * @param comp the suffix to add
     * @return The resulting Dn with the additional suffix
     * @throws LdapInvalidDnException If the resulting Dn is not valid 
     */
    public Dn add( String comp ) throws LdapInvalidDnException
    {
        if ( comp.length() == 0 )
        {
            return this;
        }

        Dn clonedDn = copy();

        // We have to parse the nameComponent which is given as an argument
        Rdn newRdn = new Rdn( schemaManager, comp );

        clonedDn.rdns.add( 0, newRdn );

        clonedDn.toUpName();

        return clonedDn;
    }


    /**
     * Adds a single Rdn to the (leaf) end of this name.
     *
     * @param newRdn the Rdn to add
     * @return the updated cloned Dn
     * @throws LdapInvalidDnException If the Dn is invalid
     */
    public Dn add( Rdn newRdn ) throws LdapInvalidDnException
    {
        if ( ( newRdn == null ) || ( newRdn.size() == 0 ) )
        {
            return this;
        }

        Dn clonedDn = copy();

        clonedDn.rdns.add( 0, new Rdn( schemaManager, newRdn ) );
        clonedDn.toUpName();

        return clonedDn;
    }


    /**
     * Gets the parent Dn of this Dn. Null if this Dn doesn't have a parent, i.e. because it
     * is the empty Dn.<br>
     * The Parent is the right part of the Dn, when the Rdn has been removed.
     *
     * @return the parent Dn of this Dn
     */
    public Dn getParent()
    {
        if ( isNullOrEmpty( this ) )
        {
            return this;
        }

        int posn = rdns.size() - 1;

        Dn newDn = new Dn( schemaManager );

        for ( int i = rdns.size() - posn; i < rdns.size(); i++ )
        {
            newDn.rdns.add( rdns.get( i ) );
        }

        newDn.toUpName();

        return newDn;
    }


    /**
     * Create a copy of the current Dn
     */
    private Dn copy()
    {
        Dn dn = new Dn( schemaManager );
        dn.rdns = new ArrayList<>();

        for ( Rdn rdn : rdns )
        {
            dn.rdns.add( rdn );
        }

        return dn;
    }


    /**
     * @see java.lang.Object#equals(java.lang.Object)
     * @return <code>true</code> if the two instances are equals
     */
    @Override
    public boolean equals( Object obj )
    {
        Dn other;
        
        if ( obj instanceof String )
        {
            try
            {
                other = new Dn( schemaManager, ( String ) obj );
            }
            catch ( LdapInvalidDnException e )
            {
                return false;
            }
        }
        else if ( obj instanceof Dn )
        {
            other = ( Dn ) obj;
        }
        else
        {
            return false;
        }
        
        if ( other.size() != this.size() )
        {
            return false;
        }

        // Shortcut if the Dn is normalized
        if ( isSchemaAware() )
        {
            return normName.equals( other.normName );
        }
        
        for ( int i = 0; i < this.size(); i++ )
        {
            if ( !other.rdns.get( i ).equals( rdns.get( i ) ) )
            {
                return false;
            }
        }

        // All components matched so we return true
        return true;
    }

    
    /**
     * Tells if the Dn is schema aware
     *
     * @return <code>true</code> if the Dn is schema aware.
     */
    public boolean isSchemaAware()
    {
        return schemaManager != null;
    }


    /**
     * Iterate over the inner Rdn. The Rdn are returned from
     * the rightmost to the leftmost. For instance, the following code :<br>
     * <pre>
     * Dn dn = new Dn( "sn=test, dc=apache, dc=org );
     * 
     * for ( Rdn rdn : dn )
     * {
     *     System.out.println( rdn.toString() );
     * }
     * </pre>
     * will produce this output : <br>
     * <pre>
     * dc=org
     * dc=apache
     * sn=test
     * </pre>
     * 
     */
    @Override
    public Iterator<Rdn> iterator()
    {
        return new RdnIterator();
    }


    /**
     * Check if a DistinguishedName is null or empty.
     *
     * @param dn The Dn to check
     * @return <code>true</code> if the Dn is null or empty, <code>false</code>
     * otherwise
     */
    public static boolean isNullOrEmpty( Dn dn )
    {
        return ( dn == null ) || dn.isEmpty();
    }


    /**
     * Check if a DistinguishedName is syntactically valid.
     *
     * @param name The Dn to validate
     * @return <code>true</code> if the Dn is valid, <code>false</code>
     * otherwise
     */
    public static boolean isValid( String name )
    {
        Dn dn = new Dn();

        try
        {
            parseInternal( null, name, dn.rdns );
            return true;
        }
        catch ( LdapInvalidDnException e )
        {
            return false;
        }
    }


    /**
     * Check if a DistinguishedName is syntactically valid.
     *
     * @param schemaManager The SchemaManager to use
     * @param name The Dn to validate
     * @return <code>true</code> if the Dn is valid, <code>false</code>
     * otherwise
     */
    public static boolean isValid( SchemaManager schemaManager, String name )
    {
        Dn dn = new Dn();

        try
        {
            parseInternal( schemaManager, name, dn.rdns );
            return true;
        }
        catch ( LdapInvalidDnException e )
        {
            return false;
        }
    }


    /**
     * Parse a Dn.
     *
     * @param name The Dn to be parsed
     * @param rdns The list that will contain the RDNs
     * @throws LdapInvalidDnException If the Dn is invalid
     */
    private static String parseInternal( SchemaManager schemaManager, String name, List<Rdn> rdns ) throws LdapInvalidDnException
    {
        try
        {
            return FastDnParser.parseDn( schemaManager, name, rdns );
        }
        catch ( TooComplexDnException e )
        {
            rdns.clear();
            return new ComplexDnParser().parseDn( schemaManager, name, rdns );
        }
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void readExternal( ObjectInput in ) throws IOException, ClassNotFoundException
    {
        // Read the UPName
        upName = in.readUTF();

        // Read the RDNs. Is it's null, the number will be -1.
        int nbRdns = in.readInt();

        rdns = new ArrayList<>( nbRdns );

        for ( int i = 0; i < nbRdns; i++ )
        {
            Rdn rdn = new Rdn( schemaManager );
            rdn.readExternal( in );
            rdns.add( rdn );
        }
        
        toUpName();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void writeExternal( ObjectOutput out ) throws IOException
    {
        if ( upName == null )
        {
            String message = I18n.err( I18n.ERR_13624_CANNOT_SERIALIZE_NULL_DN );
            LOG.error( message );
            throw new IOException( message );
        }

        // Write the UPName
        out.writeUTF( upName );

        // Write the RDNs.
        // First the number of RDNs
        out.writeInt( size() );

        // Loop on the RDNs
        for ( Rdn rdn : rdns )
        {
            rdn.writeExternal( out );
        }

        out.flush();
    }


    /**
     * Return the user provided Dn as a String. It returns the same value as the
     * getName method
     *
     * @return A String representing the user provided Dn
     */
    @Override
    public String toString()
    {
        return getName();
    }
}
