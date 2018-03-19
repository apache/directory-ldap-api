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
package org.apache.directory.api.ldap.model.entry;


import java.text.ParseException;
import java.util.Arrays;
import java.util.Iterator;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;

import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeTypeException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.util.Chars;
import org.apache.directory.api.util.Position;
import org.apache.directory.api.util.Strings;


/**
 * A set of utility fuctions for working with Attributes.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public final class AttributeUtils
{
    private AttributeUtils()
    {
    }


    /**
     * Check if an attribute contains a value. The test is case insensitive,
     * and the value is supposed to be a String. If the value is a byte[],
     * then the case sensitivity is useless.
     *
     * @param attr The attribute to check
     * @param value The value to look for
     * @return true if the value is present in the attribute
     */
    public static boolean containsValueCaseIgnore( javax.naming.directory.Attribute attr, Object value )
    {
        // quick bypass test
        if ( attr.contains( value ) )
        {
            return true;
        }

        try
        {
            if ( value instanceof String )
            {
                String strVal = ( String ) value;

                NamingEnumeration<?> attrVals = attr.getAll();

                while ( attrVals.hasMoreElements() )
                {
                    Object attrVal = attrVals.nextElement();

                    if ( attrVal instanceof String && strVal.equalsIgnoreCase( ( String ) attrVal ) )
                    {
                        return true;
                    }
                }
            }
            else
            {
                byte[] valueBytes = ( byte[] ) value;

                NamingEnumeration<?> attrVals = attr.getAll();

                while ( attrVals.hasMoreElements() )
                {
                    Object attrVal = attrVals.nextElement();

                    if ( attrVal instanceof byte[] && Arrays.equals( ( byte[] ) attrVal, valueBytes ) )
                    {
                        return true;
                    }
                }
            }
        }
        catch ( NamingException ne )
        {
            return false;
        }

        return false;
    }


    /**
     * Check if the attributes is a BasicAttributes, and if so, switch
     * the case sensitivity to false to avoid tricky problems in the server.
     * (Ldap attributeTypes are *always* case insensitive)
     * 
     * @param attributes The Attributes to check
     * @return The modified Attributes
     */
    public static Attributes toCaseInsensitive( Attributes attributes )
    {
        if ( attributes == null )
        {
            return attributes;
        }

        if ( attributes instanceof BasicAttributes )
        {
            if ( attributes.isCaseIgnored() )
            {
                // Just do nothing if the Attributes is already case insensitive
                return attributes;
            }
            else
            {
                // Ok, bad news : we have to create a new BasicAttributes
                // which will be case insensitive
                Attributes newAttrs = new BasicAttributes( true );

                NamingEnumeration<?> attrs = attributes.getAll();

                if ( attrs != null )
                {
                    // Iterate through the attributes now
                    while ( attrs.hasMoreElements() )
                    {
                        newAttrs.put( ( javax.naming.directory.Attribute ) attrs.nextElement() );
                    }
                }

                return newAttrs;
            }
        }
        else
        {
            // we can safely return the attributes if it's not a BasicAttributes
            return attributes;
        }
    }


    /**
     * Parse attribute's options :
     * 
     * options = *( ';' option )
     * option = 1*keychar
     * keychar = 'a'-z' | 'A'-'Z' / '0'-'9' / '-'
     */
    private static void parseOptions( char[] str, Position pos ) throws ParseException
    {
        while ( Strings.isCharASCII( str, pos.start, ';' ) )
        {
            pos.start++;

            // We have an option
            if ( !Chars.isAlphaDigitMinus( str, pos.start ) )
            {
                // We must have at least one keychar
                throw new ParseException( I18n.err( I18n.ERR_13201_EMPTY_OPTION_NOT_ALLOWED ), pos.start );
            }

            pos.start++;

            while ( Chars.isAlphaDigitMinus( str, pos.start ) )
            {
                pos.start++;
            }
        }
    }




    /**
     * Parse attribute's options :
     * 
     * options = *( ';' option )
     * option = 1*keychar
     * keychar = 'a'-z' | 'A'-'Z' / '0'-'9' / '-'
     */
    private static void parseOptions( byte[] bytes, Position pos ) throws ParseException
    {
        while ( Strings.isCharASCII( bytes, pos.start, ';' ) )
        {
            pos.start++;

            // We have an option
            if ( !Chars.isAlphaDigitMinus( bytes, pos.start ) )
            {
                // We must have at least one keychar
                throw new ParseException( I18n.err( I18n.ERR_13201_EMPTY_OPTION_NOT_ALLOWED ), pos.start );
            }

            pos.start++;

            while ( Chars.isAlphaDigitMinus( bytes, pos.start ) )
            {
                pos.start++;
            }
        }
    }


    /**
     * Parse a number :
     * 
     * number = '0' | '1'..'9' digits
     * digits = '0'..'9'*
     * 
     * @return true if a number has been found
     */
    private static boolean parseNumber( char[] filter, Position pos )
    {
        char c = Strings.charAt( filter, pos.start );

        switch ( c )
        {
            case '0':
                // If we get a starting '0', we should get out
                pos.start++;
                return true;

            case '1':
            case '2':
            case '3':
            case '4':
            case '5':
            case '6':
            case '7':
            case '8':
            case '9':
                pos.start++;
                break;

            default:
                // Not a number.
                return false;
        }

        while ( Chars.isDigit( filter, pos.start ) )
        {
            pos.start++;
        }

        return true;
    }




    /**
     * Parse a number :
     * 
     * number = '0' | '1'..'9' digits
     * digits = '0'..'9'*
     * 
     * @return true if a number has been found
     */
    private static boolean parseNumber( byte[] bytes, Position pos )
    {
        byte b = Strings.byteAt( bytes, pos.start );

        switch ( b )
        {
            case '0':
                // If we get a starting '0', we should get out
                pos.start++;
                return true;

            case '1':
            case '2':
            case '3':
            case '4':
            case '5':
            case '6':
            case '7':
            case '8':
            case '9':
                pos.start++;
                break;

            default:
                // Not a number.
                return false;
        }

        while ( Chars.isDigit( bytes, pos.start ) )
        {
            pos.start++;
        }

        return true;
    }


    /**
     * Parse an OID.
     *
     * numericoid = number 1*( '.' number )
     * number = '0'-'9' / ( '1'-'9' 1*'0'-'9' )
     *
     * @param str The OID to parse
     * @param pos The current position in the string
     * @throws ParseException If we don't have a valid OID
     */
    private static void parseOID( char[] str, Position pos ) throws ParseException
    {
        // We have an OID
        parseNumber( str, pos );

        // We must have at least one '.' number
        if ( !Strings.isCharASCII( str, pos.start, '.' ) )
        {
            throw new ParseException( I18n.err( I18n.ERR_13221_INVALID_OID_MISSING_DOT ), pos.start );
        }

        pos.start++;

        if ( !parseNumber( str, pos ) )
        {
            throw new ParseException( I18n.err( I18n.ERR_13202_INVALID_OID_MISSING_NUMBER ), pos.start );
        }

        while ( true )
        {
            // Break if we get something which is not a '.'
            if ( !Strings.isCharASCII( str, pos.start, '.' ) )
            {
                break;
            }

            pos.start++;

            if ( !parseNumber( str, pos ) )
            {
                throw new ParseException( I18n.err( I18n.ERR_13202_INVALID_OID_MISSING_NUMBER ), pos.start );
            }
        }
    }




    /**
     * Parse an OID.
     *
     * numericoid = number 1*( '.' number )
     * number = '0'-'9' / ( '1'-'9' 1*'0'-'9' )
     *
     * @param bytes The OID to parse
     * @param pos The current position in the string
     * @throws ParseException If we don't have a valid OID
     */
    private static void parseOID( byte[] bytes, Position pos ) throws ParseException
    {
        // We have an OID
        parseNumber( bytes, pos );

        // We must have at least one '.' number
        if ( !Strings.isCharASCII( bytes, pos.start, '.' ) )
        {
            throw new ParseException( I18n.err( I18n.ERR_13221_INVALID_OID_MISSING_DOT ), pos.start );
        }

        pos.start++;

        if ( !parseNumber( bytes, pos ) )
        {
            throw new ParseException( I18n.err( I18n.ERR_13202_INVALID_OID_MISSING_NUMBER ), pos.start );
        }

        while ( true )
        {
            // Break if we get something which is not a '.'
            if ( !Strings.isCharASCII( bytes, pos.start, '.' ) )
            {
                break;
            }

            pos.start++;

            if ( !parseNumber( bytes, pos ) )
            {
                throw new ParseException( I18n.err( I18n.ERR_13202_INVALID_OID_MISSING_NUMBER ), pos.start );
            }
        }
    }


    /**
     * Parse an attribute. The grammar is :
     * attributedescription = attributetype options
     * attributetype = oid
     * oid = descr / numericoid
     * descr = keystring
     * numericoid = number 1*( '.' number )
     * options = *( ';' option )
     * option = 1*keychar
     * keystring = leadkeychar *keychar
     * leadkeychar = 'a'-z' | 'A'-'Z'
     * keychar = 'a'-z' | 'A'-'Z' / '0'-'9' / '-'
     * number = '0'-'9' / ( '1'-'9' 1*'0'-'9' )
     *
     * @param str The parsed attribute,
     * @param pos The position of the attribute in the current string
     * @param withOption A flag set if we want to parse the options
     * @param relaxed A flag set if we want to parse without being too strict
     * @return The parsed attribute if valid
     * @throws ParseException If we had an issue while parsing the attribute
     */
    public static String parseAttribute( char[] str, Position pos, boolean withOption, boolean relaxed )
        throws ParseException
    {
        // We must have an OID or an DESCR first
        char c = Strings.charAt( str, pos.start );

        if ( c == '\0' )
        {
            throw new ParseException( I18n.err( I18n.ERR_13222_EMPTY_ATTRIBUTE ), pos.start );
        }

        int start = pos.start;

        if ( Chars.isAlpha( c ) )
        {
            // A DESCR
            pos.start++;

            while ( Chars.isAlphaDigitMinus( str, pos.start ) || ( relaxed && Chars.isCharASCII( str, pos.start, '_' ) ) )
            {
                pos.start++;
            }

            // Parse the options if needed
            if ( withOption )
            {
                parseOptions( str, pos );
            }

            return new String( str, start, pos.start - start );
        }
        else if ( Chars.isDigit( c ) )
        {
            // An OID
            pos.start++;

            // Parse the OID
            parseOID( str, pos );

            // Parse the options
            if ( withOption )
            {
                parseOptions( str, pos );
            }

            return new String( str,  start, pos.start - start );
        }
        else
        {
            throw new ParseException( I18n.err( I18n.ERR_13223_BAD_CHAR_IN_ATTRIBUTE ), pos.start );
        }
    }




    /**
     * Parse an attribute. The grammar is :
     * attributedescription = attributetype options
     * attributetype = oid
     * oid = descr / numericoid
     * descr = keystring
     * numericoid = number 1*( '.' number )
     * options = *( ';' option )
     * option = 1*keychar
     * keystring = leadkeychar *keychar
     * leadkeychar = 'a'-z' | 'A'-'Z'
     * keychar = 'a'-z' | 'A'-'Z' / '0'-'9' / '-'
     * number = '0'-'9' / ( '1'-'9' 1*'0'-'9' )
     *
     * @param bytes The parsed attribute,
     * @param pos The position of the attribute in the current string
     * @param withOption A flag set if we want to parse the options
     * @param relaxed A flag set if we want to parse without being too strict
     * @return The parsed attribute if valid
     * @throws ParseException If we had an issue while parsing the attribute
     */
    public static String parseAttribute( byte[] bytes, Position pos, boolean withOption, boolean relaxed )
        throws ParseException
    {
        // We must have an OID or an DESCR first
        byte b = Strings.byteAt( bytes, pos.start );

        if ( b == '\0' )
        {
            throw new ParseException( I18n.err( I18n.ERR_13222_EMPTY_ATTRIBUTE ), pos.start );
        }

        int start = pos.start;

        if ( Chars.isAlpha( b ) )
        {
            // A DESCR
            while ( Chars.isAlphaDigitMinus( bytes, pos.start ) || ( relaxed && Strings.isCharASCII( bytes, pos.start, '_' ) ) )
            {
                pos.start++;
            }

            // Parse the options if needed
            if ( withOption )
            {
                parseOptions( bytes, pos );
            }

            return Strings.utf8ToString( bytes, start, pos.start - start );
        }
        else if ( Chars.isDigit( b ) )
        {
            // Parse the OID
            parseOID( bytes, pos );

            // Parse the options
            if ( withOption )
            {
                parseOptions( bytes, pos );
            }

            return Strings.utf8ToString( bytes, start, pos.start - start );
        }
        else
        {
            throw new ParseException( I18n.err( I18n.ERR_13223_BAD_CHAR_IN_ATTRIBUTE ), pos.start );
        }
    }


    /**
     * A method to apply a modification to an existing entry.
     * 
     * @param entry The entry on which we want to apply a modification
     * @param modification the Modification to be applied
     * @throws LdapException if some operation fails.
     */
    public static void applyModification( Entry entry, Modification modification ) throws LdapException
    {
        Attribute modAttr = modification.getAttribute();
        String modificationId = modAttr.getUpId();

        switch ( modification.getOperation() )
        {
            case ADD_ATTRIBUTE:
                Attribute modifiedAttr = entry.get( modificationId );

                if ( modifiedAttr == null )
                {
                    // The attribute should be added.
                    entry.put( modAttr );
                }
                else
                {
                    // The attribute exists : the values can be different,
                    // so we will just add the new values to the existing ones.
                    for ( Value value : modAttr )
                    {
                        // If the value already exist, nothing is done.
                        // Note that the attribute *must* have been
                        // normalized before.
                        modifiedAttr.add( value );
                    }
                }

                break;

            case REMOVE_ATTRIBUTE:
                if ( modAttr.get() == null )
                {
                    // We have no value in the ModificationItem attribute :
                    // we have to remove the whole attribute from the initial
                    // entry
                    entry.removeAttributes( modificationId );
                }
                else
                {
                    // We just have to remove the values from the original
                    // entry, if they exist.
                    modifiedAttr = entry.get( modificationId );

                    if ( modifiedAttr == null )
                    {
                        break;
                    }

                    for ( Value value : modAttr )
                    {
                        // If the value does not exist, nothing is done.
                        // Note that the attribute *must* have been
                        // normalized before.
                        modifiedAttr.remove( value );
                    }

                    if ( modifiedAttr.size() == 0 )
                    {
                        // If this was the last value, remove the attribute
                        entry.removeAttributes( modifiedAttr.getUpId() );
                    }
                }

                break;

            case REPLACE_ATTRIBUTE:
                if ( modAttr.get() == null )
                {
                    // If the modification does not have any value, we have
                    // to delete the attribute from the entry.
                    entry.removeAttributes( modificationId );
                }
                else
                {
                    // otherwise, just substitute the existing attribute.
                    entry.put( modAttr );
                }

                break;
            default:
                break;
        }
    }


    /**
     * Convert a BasicAttributes or a AttributesImpl to an Entry
     *
     * @param attributes the BasicAttributes or AttributesImpl instance to convert
     * @param dn The Dn which is needed by the Entry
     * @return An instance of a Entry object
     * 
     * @throws LdapException If we get an invalid attribute
     */
    public static Entry toEntry( Attributes attributes, Dn dn ) throws LdapException
    {
        if ( attributes instanceof BasicAttributes )
        {
            try
            {
                Entry entry = new DefaultEntry( dn );

                for ( NamingEnumeration<? extends javax.naming.directory.Attribute> attrs = attributes.getAll(); attrs
                    .hasMoreElements(); )
                {
                    javax.naming.directory.Attribute attr = attrs.nextElement();

                    Attribute entryAttribute = toApiAttribute( attr );

                    if ( entryAttribute != null )
                    {
                        entry.put( entryAttribute );
                    }
                }

                return entry;
            }
            catch ( LdapException ne )
            {
                throw new LdapInvalidAttributeTypeException( ne.getMessage(), ne );
            }
        }
        else
        {
            return null;
        }
    }


    /**
     * Converts an {@link Entry} to an {@link Attributes}.
     *
     * @param entry
     *      the {@link Entry} to convert
     * @return
     *      the equivalent {@link Attributes}
     */
    public static Attributes toAttributes( Entry entry )
    {
        if ( entry != null )
        {
            Attributes attributes = new BasicAttributes( true );

            // Looping on attributes
            for ( Iterator<Attribute> attributeIterator = entry.iterator(); attributeIterator.hasNext(); )
            {
                Attribute entryAttribute = attributeIterator.next();

                attributes.put( toJndiAttribute( entryAttribute ) );
            }

            return attributes;
        }

        return null;
    }


    /**
     * Converts an {@link Attribute} to a JNDI Attribute.
     *
     * @param attribute the {@link Attribute} to convert
     * @return the equivalent JNDI Attribute
     */
    public static javax.naming.directory.Attribute toJndiAttribute( Attribute attribute )
    {
        if ( attribute != null )
        {
            javax.naming.directory.Attribute jndiAttribute = new BasicAttribute( attribute.getUpId() );

            // Looping on values
            for ( Iterator<Value> valueIterator = attribute.iterator(); valueIterator.hasNext(); )
            {
                Value value = valueIterator.next();
                jndiAttribute.add( value.getValue() );
            }

            return jndiAttribute;
        }

        return null;
    }


    /**
     * Convert a JNDI Attribute to an LDAP API Attribute
     *
     * @param jndiAttribute the JNDI Attribute instance to convert
     * @return An instance of a LDAP API Attribute object
     * @throws LdapInvalidAttributeValueException If the attribute is invalid
     */
    public static Attribute toApiAttribute( javax.naming.directory.Attribute jndiAttribute )
        throws LdapInvalidAttributeValueException
    {
        if ( jndiAttribute == null )
        {
            return null;
        }

        try
        {
            Attribute attribute = new DefaultAttribute( jndiAttribute.getID() );

            for ( NamingEnumeration<?> values = jndiAttribute.getAll(); values.hasMoreElements(); )
            {
                Object value = values.nextElement();

                if ( value instanceof String )
                {
                    attribute.add( ( String ) value );
                }
                else if ( value instanceof byte[] )
                {
                    attribute.add( ( byte[] ) value );
                }
                else
                {
                    attribute.add( ( String ) null );
                }
            }

            return attribute;
        }
        catch ( NamingException ne )
        {
            return null;
        }
    }
}
