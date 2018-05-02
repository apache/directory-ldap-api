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
package org.apache.directory.api.ldap.model.schema.parsers;


import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.StringReader;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.exception.LdapSchemaException;
import org.apache.directory.api.ldap.model.ldif.LdapLdifException;
import org.apache.directory.api.ldap.model.schema.AttributeType;
import org.apache.directory.api.ldap.model.schema.MutableAttributeType;
import org.apache.directory.api.ldap.model.schema.MutableObjectClass;
import org.apache.directory.api.ldap.model.schema.ObjectClass;
import org.apache.directory.api.ldap.model.schema.ObjectClassTypeEnum;
import org.apache.directory.api.ldap.model.schema.SchemaObject;
import org.apache.directory.api.ldap.model.schema.UsageEnum;
import org.apache.directory.api.ldap.model.schema.syntaxCheckers.OpenLdapObjectIdentifierMacro;
import org.apache.directory.api.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A reusable wrapper for hand parser OpenLDAP schema.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class FastOpenLdapSchemaParser
{
    /** The LoggerFactory used by this class */
    protected static final Logger LOG = LoggerFactory.getLogger( FastOpenLdapSchemaParser.class );

    /** the monitor to use for this parser */
    protected ParserMonitor monitor = new ParserMonitorAdapter();

    /** A flag used to tell the parser if it should be strict or not */
    private boolean isQuirksModeEnabled = false;

    /** the number of the current line being parsed by the reader */
    protected int lineNumber;

    /** The list of parsed schema descriptions */
    private List<Object> schemaDescriptions = new ArrayList<>();

    /** The list of attribute type, initialized by splitParsedSchemaDescriptions() */
    private List<MutableAttributeType> attributeTypes;

    /** The list of object classes, initialized by splitParsedSchemaDescriptions()*/
    private List<ObjectClass> objectClasses;

    /** The map of object identifier macros, initialized by splitParsedSchemaDescriptions()*/
    private Map<String, OpenLdapObjectIdentifierMacro> objectIdentifierMacros = new HashMap<>();

    /** Flag whether object identifier macros should be resolved. */
    private boolean isResolveObjectIdentifierMacros;
    
    private static final boolean QUOTED = true;
    private static final boolean UN_QUOTED = false;
    
    
    private class Extension
    {
        /** The extension key */
        String key;
        
        /** The extension values */
        List<String> values = new ArrayList<>();
        
        /**
         * {@inheritDoc} 
         */
        @Override
        public String toString()
        {
            StringBuilder sb = new StringBuilder();
            
            sb.append( key );
            
            if ( values.size() > 1 )
            {
                boolean isFirst = true;
                sb.append( "( " );
                
                for ( String value : values )
                {
                    if ( isFirst )
                    {
                        isFirst = false;
                    }
                    else
                    {
                        sb.append( ' ' );
                    }
                    
                    sb.append( '\'' ) .append( value ).append( '\'' );
                }

                sb.append( " )" );
            }
            else
            {
                sb.append( ' ' ).append( '\'' ) .append( values.get( 0 ) ).append( '\'' );
            }
            
            return sb.toString();
        }
    }
    
    private class NoidLen
    {
        /** The syntax OID */
        String noid;
        
        /** The syntax length */
        long len = 0;
        
        /**
         * {@inheritDoc} 
         */
        @Override
        public String toString()
        {
            if ( len > 0 )
            {
                return noid + '{' + len + '}';
            }
            else
            {
                return noid;
            }
        }
    }
    
    
    private class PosSchema
    {
        /** The line number in the file */
        int lineNumber;
        
        /** The position in the current line */
        int start;
        
        /** The line being processed */
        String line;
        
        /**
         * {@inheritDoc} 
         */
        @Override
        public String toString()
        {
            if ( line == null )
            {
                return "null";
            }
            else if ( line.length() < start )
            {
                return "EOL";
            }
            else
            {
                return line.substring( start ); 
            }
        }
    }

    
    /**
     * The list of AttributeTypeDescription elements that can be seen 
     */
    private enum AttributeTypeElements
    {
        NAME(1),
        DESC(2),
        OBSOLETE(4),
        SUP(8),
        EQUALITY(16),
        ORDERING(32),
        SUBSTR(64),
        SYNTAX(128),
        SINGLE_VALUE(256),
        COLLECTIVE(512),
        NO_USER_MODIFICATION(1024),
        USAGE(2048);
        
        private int value;
        
        AttributeTypeElements( int value )
        {
            this.value = value;
        }
    }

    
    /**
     * The list of ObjectClassDescription elements that can be seen 
     */
    private enum ObjectClassElements
    {
        NAME(1),
        DESC(2),
        OBSOLETE(4),
        SUP(8),
        MUST(16),
        MAY(32),
        ABSTRACT(64),
        STRUCTURAL(64),
        AUXILIARY(64);
        
        private int value;
        
        ObjectClassElements( int value )
        {
            this.value = value;
        }
    }

    /**
     * Creates a reusable instance of an OpenLdapSchemaParser.
     *
     * @throws IOException if the pipe cannot be formed
     */
    public FastOpenLdapSchemaParser() throws IOException
    {
        isResolveObjectIdentifierMacros = true;
        isQuirksModeEnabled = true;
    }


    /**
     * Reset the parser
     */
    public void clear()
    {
        if ( attributeTypes != null )
        {
            attributeTypes.clear();
        }
        
        if ( objectClasses != null )
        {
            objectClasses.clear();
        }
        
        if ( schemaDescriptions != null )
        {
            schemaDescriptions.clear();
        }
    
        if ( objectIdentifierMacros != null )
        {
            objectIdentifierMacros.clear();
        }
    }


    /**
     * Gets the attribute types.
     * 
     * @return the attribute types
     */
    public List<MutableAttributeType> getAttributeTypes()
    {
        return attributeTypes;
    }


    /**
     * Gets the object class types.
     * 
     * @return the object class types
     */
    public List<ObjectClass> getObjectClassTypes()
    {
        return objectClasses;
    }


    /**
     * Gets the object identifier macros.
     * 
     * @return the object identifier macros
     */
    public Map<String, OpenLdapObjectIdentifierMacro> getObjectIdentifierMacros()
    {
        return objectIdentifierMacros;
    }


    /**
     * Splits parsed schema descriptions and resolved
     * object identifier macros.
     * 
     * @throws ParseException the parse exception
     */
    private void afterParse() throws ParseException
    {
        objectClasses = new ArrayList<>();
        attributeTypes = new ArrayList<>();

        // split parsed schema descriptions
        for ( Object obj : schemaDescriptions )
        {
            if ( obj instanceof OpenLdapObjectIdentifierMacro )
            {
                OpenLdapObjectIdentifierMacro oid = ( OpenLdapObjectIdentifierMacro ) obj;
                objectIdentifierMacros.put( oid.getName(), oid );
            }
            else if ( obj instanceof AttributeType )
            {
                MutableAttributeType attributeType = ( MutableAttributeType ) obj;

                attributeTypes.add( attributeType );
            }
            else if ( obj instanceof ObjectClass )
            {
                ObjectClass objectClass = ( ObjectClass ) obj;

                objectClasses.add( objectClass );
            }
        }

        if ( isResolveObjectIdentifierMacros() )
        {
            // resolve object identifier macros
            for ( OpenLdapObjectIdentifierMacro oid : objectIdentifierMacros.values() )
            {
                resolveObjectIdentifierMacro( oid );
            }

            // apply object identifier macros to object classes
            for ( ObjectClass objectClass : objectClasses )
            {
                objectClass.setOid( getResolveOid( objectClass.getOid() ) );
            }

            // apply object identifier macros to attribute types
            for ( MutableAttributeType attributeType : attributeTypes )
            {
                attributeType.setOid( getResolveOid( attributeType.getOid() ) );
                attributeType.setSyntaxOid( getResolveOid( attributeType.getSyntaxOid() ) );
            }

        }
    }


    private String getResolveOid( String oid )
    {
        if ( oid != null && oid.indexOf( ':' ) != -1 )
        {
            // resolve OID
            String[] nameAndSuffix = oid.split( ":" );
            
            if ( objectIdentifierMacros.containsKey( nameAndSuffix[0] ) )
            {
                OpenLdapObjectIdentifierMacro macro = objectIdentifierMacros.get( nameAndSuffix[0] );
                
                return macro.getResolvedOid() + "." + nameAndSuffix[1];
            }
        }
        
        return oid;
    }


    private void resolveObjectIdentifierMacro( OpenLdapObjectIdentifierMacro macro ) throws ParseException
    {
        String rawOidOrNameSuffix = macro.getRawOidOrNameSuffix();

        if ( macro.isResolved() )
        {
            // finished
            return;
        }
        else if ( rawOidOrNameSuffix.indexOf( ':' ) != -1 )
        {
            // resolve OID
            String[] nameAndSuffix = rawOidOrNameSuffix.split( ":" );
            
            if ( objectIdentifierMacros.containsKey( nameAndSuffix[0] ) )
            {
                OpenLdapObjectIdentifierMacro parentMacro = objectIdentifierMacros.get( nameAndSuffix[0] );
                resolveObjectIdentifierMacro( parentMacro );
                macro.setResolvedOid( parentMacro.getResolvedOid() + "." + nameAndSuffix[1] );
            }
            else
            {
                throw new ParseException( I18n.err( I18n.ERR_13726_NO_OBJECT_IDENTIFIER_MACRO, nameAndSuffix[0] ), 0 );
            }

        }
        else
        {
            // no :suffix,
            if ( objectIdentifierMacros.containsKey( rawOidOrNameSuffix ) )
            {
                OpenLdapObjectIdentifierMacro parentMacro = objectIdentifierMacros.get( rawOidOrNameSuffix );
                resolveObjectIdentifierMacro( parentMacro );
                macro.setResolvedOid( parentMacro.getResolvedOid() );
            }
            else
            {
                macro.setResolvedOid( rawOidOrNameSuffix );
            }
        }
    }


    /**
     * Parses an OpenLDAP schemaObject element/object.
     *
     * @param schemaObject the String image of a complete schema object
     * @return the schema object
     * @throws ParseException If the schemaObject can't be parsed
     */
    public SchemaObject parse( String schemaObject ) throws ParseException
    {
        if ( ( schemaObject == null ) || Strings.isEmpty( schemaObject.trim() ) )
        {
            throw new ParseException( I18n.err( I18n.ERR_13716_NULL_OR_EMPTY_STRING_SCHEMA_OBJECT ), 0 );
        }
        
        try ( Reader reader = new BufferedReader( new StringReader( schemaObject ) ) )
        {
            parse( reader );
            afterParse();
        }
        catch ( IOException | LdapSchemaException e )
        {
            throw new ParseException( e.getMessage(), 0 );
        }

        if ( !schemaDescriptions.isEmpty() )
        {
            for ( Object obj : schemaDescriptions )
            {
                if ( obj instanceof SchemaObject )
                {
                    return ( SchemaObject ) obj;
                }
            }
        }
        
        return null;
    }


    /**
     * Parses a stream of OpenLDAP schemaObject elements/objects. Default charset is used.
     *
     * @param schemaIn a stream of schema objects
     * @throws Exception 
     */
    public void parse( InputStream schemaIn ) throws Exception
    {
        try ( InputStreamReader in = new InputStreamReader( schemaIn, Charset.defaultCharset() ) )
        {
            try ( Reader reader = new BufferedReader( in ) )
            {
                parse( reader );
                afterParse();
            }
        }
    }
    
    
    private void skipWhites( Reader reader, PosSchema pos, boolean mandatory ) throws IOException, LdapSchemaException
    {
        boolean hasSpace = false;
        
        while ( true )
        {
            if ( isEmpty( pos ) )
            {
                getLine( reader, pos );
                
                if ( pos.line == null )
                {
                    return;
                }
                
                hasSpace = true;
                continue;
            }
            
            if ( pos.line == null )
            {
                throw new LdapSchemaException( I18n.err( I18n.ERR_13782_END_OF_FILE, pos.lineNumber, pos.start ) );
            }
            
            while ( Character.isWhitespace( pos.line.charAt( pos.start ) ) )
            {
                hasSpace = true;
                pos.start++;
                
                if ( isEmpty( pos ) )
                {
                    getLine( reader, pos );

                    if ( pos.line == null )
                    {
                        return;
                    }
                    
                    continue;
                }
            }
            
            if ( pos.line.charAt( pos.start ) == '#' )
            {
                getLine( reader, pos );

                if ( pos.line == null )
                {
                    return;
                }
                
                hasSpace = true;
                continue;
            }
            else
            {
                if ( mandatory && !hasSpace )
                {
                    throw new LdapSchemaException( I18n.err( I18n.ERR_13783_SPACE_EXPECTED, pos.lineNumber, pos.start ) );
                }
                else
                {
                    return;
                }
            }
        }
    }
    
    
    private boolean isComment( PosSchema pos )
    {
        if ( isEmpty( pos ) )
        {
            return true;
        }
        
        return pos.line.charAt( pos.start ) == '#';
    }
    
    
    private boolean isEmpty( PosSchema pos )
    {
        return ( pos.line == null ) || ( pos.start >= pos.line.length() );
    }
    
    
    private boolean startsWith( PosSchema pos, String text )
    {
        if ( ( pos.line == null ) || ( pos.line.length() - pos.start < text.length() ) )
        {
            return false;
        }
        
        return text.equalsIgnoreCase( pos.line.substring( pos.start, pos.start + text.length() ) );
    }
    
    
    private boolean startsWith( Reader reader, PosSchema pos, char c ) throws IOException, LdapSchemaException
    {
        return startsWith( reader, pos, c, UN_QUOTED );
    }
    
    
    private boolean startsWith( Reader reader, PosSchema pos, char c, boolean quoted ) throws IOException, LdapSchemaException
    {
        if ( ( pos.line == null ) || ( pos.line.length() - pos.start < 1 ) )
        {
            return false;
        }
        
        if ( quoted )
        {
            // Don't read a new line when we are within quotes
            return pos.line.charAt( pos.start ) == c;
        }

        while ( isEmpty( pos ) || ( isComment( pos ) ) )
        {
            getLine( reader, pos );
            
            if ( pos.line == null )
            {
                return false;
            }
            
            skipWhites( reader, pos, false );
            
            if ( isComment( pos ) )
            {
                continue;
            }
        }
        
        return pos.line.charAt( pos.start ) == c;
    }
    
    
    private boolean isAlpha( PosSchema pos )
    {
        if ( ( pos.line == null ) || ( pos.line.length() - pos.start < 1 ) )
        {
            return false;
        }
        
        return Character.isAlphabetic( pos.line.charAt( pos.start ) );
    }
    
    
    private boolean isDigit( PosSchema pos )
    {
        if ( ( pos.line == null ) || ( pos.line.length() - pos.start < 1 ) )
        {
            return false;
        }
        
        return Character.isDigit( pos.line.charAt( pos.start ) );
    }

    
    private void getLine( Reader reader, PosSchema pos ) throws IOException
    {
        pos.line = ( ( BufferedReader ) reader ).readLine();
        pos.start = 0;
        
        if ( pos.line != null )
        {
            pos.lineNumber++;
        }
    }
    
    
    /**
     * numericoid   ::= number ( DOT number )+ |
     * number       ::= DIGIT | LDIGIT DIGIT+
     * DIGIT        ::= %x30 | LDIGIT       ; "0"-"9"
     * LDIGIT       ::= %x31-39             ; "1"-"9"
     * DOT          ::= %x2E                ; period (".")
     */
    private String getNumericOid( Reader reader, PosSchema pos ) throws IOException, LdapSchemaException
    {
        boolean isDot = true;
        int start = pos.start;
        int numberStart = start;
        boolean firstIsZero = false;
        boolean isFirstDigit = true;
        
        while ( true )
        {
            if ( isDigit( pos ) )
            {
                if ( firstIsZero )
                {
                    throw new LdapSchemaException( I18n.err( I18n.ERR_13784_BAD_OID_TWO_ZEROES, pos.lineNumber, pos.start ) );
                }
                    
                if ( ( pos.line.charAt( pos.start ) == '0' ) && isFirstDigit )
                {
                    firstIsZero = true;
                }
                
                isDot = false;
                pos.start++;
                isFirstDigit = false;
            }
            else if ( startsWith( reader, pos, '.' ) )
            {
                if ( isDot )
                {
                    // We can't have two consecutive dots or a dot at the beginning
                    throw new LdapSchemaException( I18n.err( I18n.ERR_13785_BAD_OID_CONSECUTIVE_DOTS, pos.lineNumber, pos.start ) );
                }
                
                firstIsZero = false;
                isFirstDigit = true;
                pos.start++;
                isDot = true;
            }
            else
            {
                break;
            }
        }
        
        if ( isDot )
        {
            // We can't have two consecutive dots or a dot at the beginning
            throw new LdapSchemaException( I18n.err( I18n.ERR_13786_BAD_OID_DOT_AT_THE_END, pos.lineNumber, pos.start ) );
        }
        
        return pos.line.substring( start, pos.start );
    }

    
    /**
     * In normal mode :
     * <pre>
     * oid          ::= descr | numericoid
     * descr        ::= keystring
     * keystring    ::= leadkeychar keychar*
     * leadkeychar  ::= ALPHA
     * keychar      ::= ALPHA | DIGIT | HYPHEN
     * numericoid   ::= number ( DOT number )+ |
     * number       ::= DIGIT | LDIGIT DIGIT+
     * ALPHA        ::= %x41-5A | %x61-7A   ; "A"-"Z" / "a"-"z"
     * DIGIT        ::= %x30 | LDIGIT       ; "0"-"9"
     * LDIGIT       ::= %x31-39             ; "1"-"9"
     * DOT          ::= %x2E                ; period (".")
     * HYPHEN       ::= %x2D                ; hyphen ("-")
     * </pre>
     * 
     * In quirks mode :
     * <pre>
     * oid          ::= descr | numericoid
     * descr        ::= descrQ (COLON numericoid)
     * descrQ       ::= keystringQ
     * keystringQ   ::= LkeycharQ keycharQ*
     * LkeycharQ    ::= ALPHA | HYPHEN | UNDERSCORE | SEMI_COLON | DOT | COLON | SHARP 
     * keycharQ     ::= ALPHA | DIGIT | HYPHEN | UNDERSCORE | SEMI_COLON | DOT | COLON | SHARP 
     * numericoid   ::= number ( DOT number )+
     * number       ::= DIGIT | LDIGIT DIGIT+
     * ALPHA        ::= %x41-5A | %x61-7A   ; "A"-"Z" / "a"-"z"
     * DIGIT        ::= %x30 | LDIGIT       ; "0"-"9"
     * LDIGIT       ::= %x31-39             ; "1"-"9"
     * HYPHEN       ::= %x2D                ; hyphen ("-")
     * UNDERSCORE   ::= %x5F                ; underscore ("_")
     * DOT          ::= %x2E                ; period (".")
     * COLON        ::= %x3A                ; colon (":")
     * SEMI_COLON   ::= %x3B                ; semi-colon(";")
     * SHARP        ::= %x23                ; octothorpe (or sharp sign) ("#")
     * </pre>
     */
    private String getOidAndMacro( Reader reader, PosSchema pos ) throws IOException, LdapSchemaException
    {
        if ( isAlpha( pos ) )
        {
            // A descr (likely)
            if ( isQuirksModeEnabled )
            {
                // This is a OID name
                int start = pos.start;
                char c = pos.line.charAt( pos.start );
                
                while ( Character.isDigit( c ) || Character.isAlphabetic( c ) || ( c == '-' ) || ( c == '_' )
                    || ( c == ';' ) || ( c == '.' ) || ( c == '#' ) )
                {
                    pos.start++;
                    
                    if ( isEmpty( pos ) )
                    {
                        break;
                    }
                }
                
                String oidName = pos.line.substring( start, pos.start  );
                
                // We may have a ':' followed by an OID
                if ( startsWith( reader, pos, ':' ) )
                {
                    pos.start++;
                    
                    String oid = getNumericOid( reader, pos );
                    
                    return objectIdentifierMacros.get( oidName ).getRawOidOrNameSuffix() + '.' + oid;
                }
                else
                {
                    // Ok, we may just have an oidName
                    OpenLdapObjectIdentifierMacro macro = objectIdentifierMacros.get( oidName );
                    
                    if ( macro == null )
                    {
                        return oidName;
                    }
                    else
                    {
                        return macro.getRawOidOrNameSuffix();
                    }
                }
            }
            else
            {
                // A simple descr
                return getDescr( reader, pos );
            }
        }
        else if ( isDigit( pos ) )
        {
            // This is a numeric oid
            return getNumericOid( reader, pos );
        }
        else
        {
            // This is an error
            throw new LdapSchemaException( I18n.err( I18n.ERR_13787_OID_EXPECTED, pos.lineNumber, pos.start ) );
        }
    }

    
    /**
     * In normal mode :
     * <pre>
     * oid          ::= descr | numericoid
     * descr        ::= keystring
     * keystring    ::= leadkeychar keychar*
     * leadkeychar  ::= ALPHA
     * keychar      ::= ALPHA | DIGIT | HYPHEN
     * numericoid   ::= number ( DOT number )+ |
     * number       ::= DIGIT | LDIGIT DIGIT+
     * ALPHA        ::= %x41-5A | %x61-7A   ; "A"-"Z" / "a"-"z"
     * DIGIT        ::= %x30 | LDIGIT       ; "0"-"9"
     * LDIGIT       ::= %x31-39             ; "1"-"9"
     * DOT          ::= %x2E                ; period (".")
     * HYPHEN       ::= %x2D                ; hyphen ("-")
     * </pre>
     * 
     * In quirks mode :
     * <pre>
     * oid          ::= descr | numericoid
     * descr        ::= descrQ (COLON numericoid)
     * descrQ       ::= keystringQ
     * keystringQ   ::= LkeycharQ keycharQ*
     * LkeycharQ    ::= ALPHA | HYPHEN | UNDERSCORE | SEMI_COLON | DOT | COLON | SHARP 
     * keycharQ     ::= ALPHA | DIGIT | HYPHEN | UNDERSCORE | SEMI_COLON | DOT | COLON | SHARP 
     * numericoid   ::= number ( DOT number )+
     * number       ::= DIGIT | LDIGIT DIGIT+
     * ALPHA        ::= %x41-5A | %x61-7A   ; "A"-"Z" / "a"-"z"
     * DIGIT        ::= %x30 | LDIGIT       ; "0"-"9"
     * LDIGIT       ::= %x31-39             ; "1"-"9"
     * HYPHEN       ::= %x2D                ; hyphen ("-")
     * UNDERSCORE   ::= %x5F                ; underscore ("_")
     * DOT          ::= %x2E                ; period (".")
     * COLON        ::= %x3A                ; colon (":")
     * SEMI_COLON   ::= %x3B                ; semi-colon(";")
     * SHARP        ::= %x23                ; octothorpe (or sharp sign) ("#")
     * </pre>
     */
    private String getOid( Reader reader, PosSchema pos ) throws IOException, LdapSchemaException
    {
        if ( isAlpha( pos ) )
        {
            // A descr (likely)
            if ( isQuirksModeEnabled )
            {
                // This is a OID name
                int start = pos.start;
                char c = pos.line.charAt( pos.start );
                
                while ( Character.isAlphabetic( c ) || Character.isDigit( c ) || ( c == '-' )
                    || ( c == '_' ) || ( c == ';' ) || ( c == '.' ) || ( c == ':' ) || ( c == '#' ) )
                {
                    pos.start++;
                    
                    if ( isEmpty( pos ) )
                    {
                        break;
                    }
                    
                    c = pos.line.charAt( pos.start );
                }
                
                return pos.line.substring( start, pos.start  );
            }
            else
            {
                // A simple descr
                return getDescr( reader, pos );
            }
        }
        else if ( isDigit( pos ) )
        {
            // This is a numeric oid
            return getNumericOid( reader, pos );
        }
        else
        {
            // This is an error
            throw new LdapSchemaException( I18n.err( I18n.ERR_13787_OID_EXPECTED, pos.lineNumber, pos.start ) );
        }
    }
    
    
    /**
     * In normal mode :
     * 
     * <pre>
     * descr        ::= keystring
     * keystring    ::= leadkeychar keychar*
     * leadkeychar  ::= ALPHA
     * keychar      ::= ALPHA | DIGIT | HYPHEN
     * numericoid   ::= number ( DOT number )+ |
     * number       ::= DIGIT | LDIGIT DIGIT+
     * ALPHA        ::= %x41-5A | %x61-7A   ; "A"-"Z" / "a"-"z"
     * DIGIT        ::= %x30 | LDIGIT       ; "0"-"9"
     * LDIGIT       ::= %x31-39             ; "1"-"9"
     * DOT          ::= %x2E                ; period (".")
     * HYPHEN       ::= %x2D                ; hyphen ("-")
     * </pre>
     * 
     * In quirksMode :
     * 
     * <pre>
     * descr        ::= descrQ (COLON numericoid)
     * descrQ       ::= keystringQ
     * keystringQ   ::= LkeycharQ keycharQ*
     * LkeycharQ    ::= ALPHA | HYPHEN | UNDERSCORE | SEMI_COLON | DOT | COLON | SHARP 
     * keycharQ     ::= ALPHA | DIGIT | HYPHEN | UNDERSCORE | SEMI_COLON | DOT | COLON | SHARP 
     * numericoid   ::= number ( DOT number )+
     * number       ::= DIGIT | LDIGIT DIGIT+
     * ALPHA        ::= %x41-5A | %x61-7A   ; "A"-"Z" / "a"-"z"
     * DIGIT        ::= %x30 | LDIGIT       ; "0"-"9"
     * LDIGIT       ::= %x31-39             ; "1"-"9"
     * HYPHEN       ::= %x2D                ; hyphen ("-")
     * UNDERSCORE   ::= %x5F                ; underscore ("_")
     * DOT          ::= %x2E                ; period (".")
     * COLON        ::= %x3A                ; colon (":")
     * SEMI_COLON   ::= %x3B                ; semi-colon(";")
     * SHARP        ::= %x23                ; octothorpe (or sharp sign) ("#")
     * </pre
     * @throws IOException 
     */
    private String getDescr( Reader reader, PosSchema pos ) throws LdapSchemaException, IOException
    {
        if ( isQuirksModeEnabled )
        {
            int start = pos.start;
            boolean isFirst = true;
            
            while ( !isEmpty( pos ) )
            {
                if ( isFirst )
                {
                    isFirst = false;
                    
                    char c = pos.line.charAt( pos.start );
                    
                    if ( Character.isAlphabetic( c ) || ( c == '-' ) || ( c == '_' )
                        || ( c == ';' ) || ( c == '.' ) || ( c == ':' ) || ( c == '#' ) ) 
                    {
                        // leadkeycharQ
                        pos.start++;
                    }
                    else
                    {
                        // Error, we are expecting a leadKeychar
                        throw new LdapSchemaException( I18n.err( I18n.ERR_13788_LEAD_KEY_CHAR_EXPECTED, 
                            pos.lineNumber, pos.start ) );
                    }
                }
                else
                {
                    char c = pos.line.charAt( pos.start );
                    
                    if ( Character.isAlphabetic( c ) || Character.isDigit( c ) || ( c == '-' )
                        || ( c == '_' ) || ( c == ';' ) || ( c == '.' ) || ( c == ':' ) || ( c == '#' ) ) 
                    {
                        pos.start++;
                    }
                    else
                    {
                        // We are done 
                        return pos.line.substring( start, pos.start );
                    }
                }
            }
            
            return pos.line.substring( start, pos.start );
        }
        else
        {
            int start = pos.start;
            boolean isFirst = true;
            
            while ( !isEmpty( pos ) )
            {
                if ( isFirst )
                {
                    isFirst = false;
                    
                    if ( isAlpha( pos ) ) 
                    {
                        // leadkeychar
                        pos.start++;
                    }
                    else
                    {
                        // Error, we are expecting a leadKeychar
                        throw new LdapSchemaException( I18n.err( I18n.ERR_13788_LEAD_KEY_CHAR_EXPECTED, 
                            pos.lineNumber, pos.start ) );
                    }
                }
                else
                {
                    char c = pos.line.charAt( pos.start );
                    
                    if ( Character.isAlphabetic( c ) || Character.isDigit( c ) || ( c == '-' ) )
                    {
                        pos.start++;
                    }
                    else
                    {
                        // We are done 
                        return pos.line.substring( start, pos.start );
                    }
                }
            }

            return pos.line.substring( start, pos.start );
        }
    }
    
    
    private String getMacro( Reader reader, PosSchema pos ) throws LdapSchemaException, IOException
    {
        if ( isQuirksModeEnabled )
        {
            int start = pos.start;
            boolean isFirst = true;
            
            while ( !isEmpty( pos ) )
            {
                if ( isFirst )
                {
                    isFirst = false;
                    
                    char c = pos.line.charAt( pos.start );
                    
                    if ( Character.isAlphabetic( c ) || ( c == '-' ) || ( c == '_' ) 
                        || ( c == ';' ) || ( c == '.' ) || ( c == '#' ) ) 
                    {
                        // leadkeycharQ
                        pos.start++;
                    }
                    else
                    {
                        // Error, we are expecting a leadKeychar
                        throw new LdapSchemaException( I18n.err( I18n.ERR_13788_LEAD_KEY_CHAR_EXPECTED, 
                            pos.lineNumber, pos.start ) );
                    }
                }
                else
                {
                    char c = pos.line.charAt( pos.start );
                    
                    if ( Character.isAlphabetic( c ) || Character.isDigit( c ) || ( c == '-' ) 
                        || ( c == '_' ) || ( c == ';' ) || ( c == '.' ) || ( c == '#' ) ) 
                    {
                        pos.start++;
                    }
                    else
                    {
                        // We are done 
                        return pos.line.substring( start, pos.start );
                    }
                }
            }
            
            return pos.line.substring( start, pos.start );
        }
        else
        {
            int start = pos.start;
            boolean isFirst = true;
            
            while ( !isEmpty( pos ) )
            {
                if ( isFirst )
                {
                    isFirst = false;
                    
                    if ( isAlpha( pos ) ) 
                    {
                        // leadkeychar
                        pos.start++;
                    }
                    else
                    {
                        // Error, we are expecting a leadKeychar
                        throw new LdapSchemaException( I18n.err( I18n.ERR_13788_LEAD_KEY_CHAR_EXPECTED, 
                            pos.lineNumber, pos.start ) );
                    }
                }
                else
                {
                    char c = pos.line.charAt( pos.start );
                    
                    if ( Character.isAlphabetic( c ) || Character.isDigit( c ) || ( c == '-' ) )
                    {
                        pos.start++;
                    }
                    else
                    {
                        // We are done 
                        return pos.line.substring( start, pos.start );
                    }
                }
            }

            return pos.line.substring( start, pos.start );
        }
    }

    
    
    /**
     * <pre>
     * qdescr ::== SQUOTE descr SQUOTE
     * descr ::= keystring
     * keystring ::= leadkeychar *keychar
     * leadkeychar ::= ALPHA
     * keychar ::= ALPHA | DIGIT | HYPHEN
     * </pre>
     * 
     * In quirksMode :
     * 
     * <pre>
     * qdescr ::== SQUOTE descr SQUOTE | descr | SQUOTE numericoid SQUOTE
     * descr ::= keystring
     * keystring ::= keychar+
     * keychar ::= ALPHA | DIGIT | HYPHEN | UNDERSCORE | SEMI_COLON | DOT | COLON | SHARP 
     * </pre>
     * @throws IOException 
     */
    private String getQDescr( Reader reader, PosSchema pos ) throws LdapSchemaException, IOException
    {
        if ( isQuirksModeEnabled )
        {
            if ( startsWith( reader, pos, '\'' ) )
            {
                pos.start++;
                int start = pos.start;
                
                while ( !startsWith( reader, pos, '\'' ) )
                {
                    if ( isEmpty( pos ) )
                    {
                        throw new LdapSchemaException( I18n.err( I18n.ERR_13789_SIMPLE_QUOTE_EXPECTED_AT_START, 
                            pos.lineNumber, pos.start ) );
                    }
                    
                    char c = pos.line.charAt( pos.start );
                    
                    if ( Character.isDigit( c ) || Character.isAlphabetic( c ) || ( c == '-' ) || ( c == '_' )
                        || ( c == ';' ) || ( c == '.' ) || ( c == ':' ) || ( c == '#' ) )
                    {
                        pos.start++;
                    }
                    else if ( c != '\'' )
                    {
                        throw new LdapSchemaException( I18n.err( I18n.ERR_13790_NOT_A_KEYSTRING, pos.lineNumber, pos.start ) );
                    }
                }
                
                pos.start++;
                
                return pos.line.substring( start, pos.start - 1 );
            }
            else
            {
                int start = pos.start;
                while ( !isEmpty( pos ) )
                {
                    char c = pos.line.charAt( pos.start );

                    if ( Character.isDigit( c ) || Character.isAlphabetic( c ) || ( c == '-' ) || ( c == '_' )
                        || ( c == ';' ) || ( c == '.' ) || ( c == ':' ) || ( c == '#' ) )
                    {
                        pos.start++;
                    }
                    else
                    {
                        break;
                    }
                }

                return pos.line.substring( start, pos.start );
            }
        }
        else
        {
            // The first quote
            if ( !startsWith( reader, pos, '\'' ) )
            {
                throw new LdapSchemaException( I18n.err( I18n.ERR_13789_SIMPLE_QUOTE_EXPECTED_AT_START, 
                    pos.lineNumber, pos.start ) );
            }
            
            pos.start++;
            int start = pos.start;
            boolean isFirst = true;
            
            while ( !startsWith( reader, pos, '\'' ) )
            {
                if ( isFirst )
                {
                    isFirst = false;
                    
                    if ( isAlpha( pos ) ) 
                    {
                        // leadkeychar
                        pos.start++;
                    }
                    else
                    {
                        // Error, we are expecting a leadKeychar
                        throw new LdapSchemaException( I18n.err( I18n.ERR_13788_LEAD_KEY_CHAR_EXPECTED, 
                            pos.lineNumber, pos.start ) );
                    }
                }
                else
                {
                    char c = pos.line.charAt( pos.start );
                    
                    if ( Character.isAlphabetic( c ) || Character.isDigit( c ) || ( c == '-' ) )
                    {
                        pos.start++;
                    }
                    else
                    {
                        // This is an error
                        throw new LdapSchemaException( I18n.err( I18n.ERR_13791_KEYCHAR_EXPECTED, c, 
                            pos.lineNumber, pos.start ) );
                    }
                }
            }
            
            if ( startsWith( reader, pos, '\'' ) )
            {
                // We are done, move one char forward to eliminate the simple quote
                pos.start++;
                
                return pos.line.substring( start, pos.start - 1 );
            }
            else
            {
                // No closing simple quote, this is an error
                throw new LdapSchemaException( I18n.err( I18n.ERR_13792_SIMPLE_QUOTE_EXPECTED_AT_END, 
                    pos.lineNumber, pos.start ) );
            }
        }
    }
    
    
    /**
     * <pre>
     * qdstring ::== SQUOTE dstring SQUOTE
     * dstring  ::= ( QS | QQ | QUTF8 )+            ; escaped UTF-8 string
     * QS       ::= ESC %x35 ( %x43 | %x63 )        ; "\5C" | "\5c", escape char
     * QQ       ::= ESC %x32 %x37                   ; "\27", simple quote char
     * QUTF8    ::= QUTF1 | UTFMB
     * QUTF1    ::= %x00-26 | %x28-5B | %x5D-7F     ; All ascii but ' and \
     * UTFMB    ::= UTF2 | UTF3 | UTF4
     * UTF0     ::= %x80-BF
     * UTF2     ::= %xC2-DF UTF0
     * UTF3     ::= %xE0 %xA0-BF UTF0 | %xE1-EC UTF0 UTF0 | %xED %x80-9F UTF0 | %xEE-EF UTF0 UTF0
     * UTF4     ::= %xF0 %x90-BF UTF0 UTF0 | %xF1-F3 UTF0 UTF0 UTF0 | %xF4 %x80-8F UTF0 UTF0
     * ESC      ::= %x5C                            ; backslash ("\")
     * </pre>
     */
    private String getQDString( Reader reader, PosSchema pos ) throws LdapSchemaException, IOException
    {
        // The first quote
        if ( !startsWith( reader, pos, '\'' ) )
        {
            throw new LdapSchemaException( I18n.err( I18n.ERR_13789_SIMPLE_QUOTE_EXPECTED_AT_START, 
                pos.lineNumber, pos.start ) );
        }
        
        pos.start++;
        int start = pos.start;
        
        while ( !startsWith( reader, pos, '\'', QUOTED ) )
        {
            // At the moment, just swallow anything
            pos.start++;
        }
        
        if ( startsWith( reader, pos, '\'' ) )
        {
            // We are done, move one char forward to eliminate the simple quote
            pos.start++;
            
            return pos.line.substring( start, pos.start - 1 );
        }
        else
        {
            // No closing simple quote, this is an error
            throw new LdapSchemaException( I18n.err( I18n.ERR_13792_SIMPLE_QUOTE_EXPECTED_AT_END, 
                pos.lineNumber, pos.start ) );
        }
    }


    /**
     * qdescrs ::= qdescr | LPAREN WSP qdescrlist WSP RPAREN
     * qdescrlist ::= [ qdescr *( SP qdescr ) ]
     * qdescr ::== SQUOTE descr SQUOTE
     * descr ::= keystring
     * keystring ::= leadkeychar *keychar
     * leadkeychar ::= ALPHA
     * keychar ::= ALPHA / DIGIT / HYPHEN
     * @throws LdapSchemaException 
     * @throws IOException 
     */
    private List<String> getQDescrs( Reader reader, PosSchema pos ) throws LdapSchemaException, IOException
    {
        List<String> qdescrs = new ArrayList<>();
        
        // It may start with a '('
        if ( startsWith( reader, pos, '(' ) )
        {
            pos.start++;
            
            // We have more than a name
            skipWhites( reader, pos, false );
            
            while ( !startsWith( reader, pos, ')' ) )
            {
                qdescrs.add( getQDescr( reader, pos ) );
                
                if ( startsWith( reader, pos, ')' ) )
                {
                    break;
                }
                
                skipWhites( reader, pos, true );
            }
            
            if ( !startsWith( reader, pos, ')' ) )
            {
                throw new LdapSchemaException( I18n.err( I18n.ERR_13793_NO_CLOSING_PAREN, 
                    pos.lineNumber, pos.start ) );
            }
            
            pos.start++;
        }
        else
        {
            // Only one name, read it
            qdescrs.add( getQDescr( reader, pos ) );
        }
        
        return qdescrs;
    }


    /**
     * <pre>
     * qdstrings    ::= qdstring | ( LPAREN WSP qdstringlist WSP RPAREN )
     * qdstringlist ::= qdstring *( SP qdstring )*
     * qdstring     ::= SQUOTE dstring SQUOTE
     * dstring      ::= 1*( QS / QQ / QUTF8 )   ; escaped UTF-8 string
     * </pre>
     * @throws LdapSchemaException 
     * @throws IOException 
     */
    private List<String> getQDStrings( Reader reader, PosSchema pos ) throws LdapSchemaException, IOException
    {
        List<String> qdStrings = new ArrayList<>();
        
        // It may start with a '('
        if ( startsWith( reader, pos, '(' ) )
        {
            pos.start++;
            
            // We have more than a name
            skipWhites( reader, pos, false );
            
            while ( !startsWith( reader, pos, ')' ) )
            {
                qdStrings.add( getQDString( reader, pos ) );
                
                if ( startsWith( reader, pos, ')' ) )
                {
                    break;
                }
                
                skipWhites( reader, pos, true );
            }
            
            if ( !startsWith( reader, pos, ')' ) )
            {
                throw new LdapSchemaException( I18n.err( I18n.ERR_13793_NO_CLOSING_PAREN, 
                    pos.lineNumber, pos.start ) );
            }
            
            pos.start++;
        }
        else
        {
            // Only one name, read it
            qdStrings.add( getQDString( reader, pos ) );
        }
        
        return qdStrings;
    }

    

    
    /**
     * <pre>
     * oids     ::= oid | ( LPAREN WSP oidlist WSP RPAREN )
     * oidlist  ::= oid *( WSP DOLLAR WSP oid )
     * </pre>
     */
    private List<String> getOids( Reader reader, PosSchema pos ) throws LdapSchemaException, IOException
    {
        List<String> oids = new ArrayList<>();
        
        // It may start with a '('
        if ( startsWith( reader, pos, '(' ) )
        {
            pos.start++;
            
            // We have more than a name
            skipWhites( reader, pos, false );
            boolean moreExpected = false;
            
            while ( !startsWith( reader, pos, ')' ) )
            {
                moreExpected = false;
                
                oids.add( getOid( reader, pos ) );
                
                if ( startsWith( reader, pos, ')' ) )
                {
                    break;
                }
                
                skipWhites( reader, pos, false );
                
                if ( startsWith( reader, pos, '$' ) )
                {
                    pos.start++;
                    moreExpected = true;
                }

                skipWhites( reader, pos, false );
            }
            
            if ( !startsWith( reader, pos, ')' ) )
            {
                throw new LdapSchemaException( I18n.err( I18n.ERR_13793_NO_CLOSING_PAREN, 
                    pos.lineNumber, pos.start ) );
            }
            
            if ( moreExpected )
            {
                throw new LdapSchemaException( I18n.err( I18n.ERR_13794_MORE_OIDS_EXPECTED, 
                    pos.lineNumber, pos.start ) );
            }
            
            pos.start++;
        }
        else
        {
            // Only one name, read it
            oids.add( getOid( reader, pos ) );
        }
        
        return oids;
    }

    
    /**
     * noidlen = numericoid [ LCURLY len RCURLY ]
     */
    private NoidLen getNoidLen( Reader reader, PosSchema pos ) throws LdapSchemaException, IOException
    {
        // Get the numericOid
        String numericOid = getNumericOid( reader, pos );
        NoidLen noidLen = new NoidLen();
        noidLen.noid = numericOid;

        // Then the len, if any
        if ( startsWith( reader, pos, '{' ) )
        {
            pos.start++;
            int start = pos.start;
            
            while ( isDigit( pos ) )
            {
                pos.start++;
            }
            
            if ( startsWith( reader, pos, '}' ) )
            {
                String lenStr = pos.line.substring( start, pos.start );
                
                pos.start++;
                
                if ( Strings.isEmpty( lenStr ) )
                {
                    noidLen.len = -1;
                }
                else
                {
                    noidLen.len = Integer.parseInt( lenStr );
                }
            }
            else
            {
                // The opening curly hasn't been closed
                throw new LdapSchemaException( I18n.err( I18n.ERR_13795_OPENED_BRACKET_NOT_CLOSED, 
                    pos.lineNumber, pos.start ) );
            }
        }

        return noidLen;
    }
    
    
    private UsageEnum getUsage( Reader reader, PosSchema pos ) throws LdapSchemaException
    {
        if ( isEmpty( pos ) )
        {
            throw new LdapSchemaException( I18n.err( I18n.ERR_13796_USAGE_EXPECTED, 
                pos.lineNumber, pos.start ) );
        }
        
        if ( startsWith( pos, "userApplications" ) )
        { 
            return UsageEnum.USER_APPLICATIONS;
        }
        else if ( startsWith( pos, "directoryOperation" ) )
        { 
            return UsageEnum.DIRECTORY_OPERATION;
        } 
        else if ( startsWith( pos, "distributedOperation" ) )
        { 
            return UsageEnum.DISTRIBUTED_OPERATION;
        } 
        else if ( startsWith( pos, "dSAOperation" ) )
        { 
            return UsageEnum.DSA_OPERATION;
        } 
        else
        {
            throw new LdapSchemaException( I18n.err( I18n.ERR_13797_USAGE_UNKNOWN, 
                pos.lineNumber, pos.start ) );
        }
    }

    
    /**
     * Production for matching attribute type descriptions. It is fault-tolerant
     * against element ordering.
     *
     * <pre>
     * AttributeTypeDescription = LPAREN WSP
     *     numericoid                    ; object identifier
     *     [ SP "NAME" SP qdescrs ]      ; short names (descriptors)
     *     [ SP "DESC" SP qdstring ]     ; description
     *     [ SP "OBSOLETE" ]             ; not active
     *     [ SP "SUP" SP oid ]           ; supertype
     *     [ SP "EQUALITY" SP oid ]      ; equality matching rule
     *     [ SP "ORDERING" SP oid ]      ; ordering matching rule
     *     [ SP "SUBSTR" SP oid ]        ; substrings matching rule
     *     [ SP "SYNTAX" SP noidlen ]    ; value syntax
     *     [ SP "SINGLE-VALUE" ]         ; single-value
     *     [ SP "COLLECTIVE" ]           ; collective
     *     [ SP "NO-USER-MODIFICATION" ] ; not user modifiable
     *     [ SP "USAGE" SP usage ]       ; usage
     *     extensions WSP RPAREN         ; extensions
     * 
     * usage = "userApplications"     /  ; user
     *         "directoryOperation"   /  ; directory operational
     *         "distributedOperation" /  ; DSA-shared operational
     *         "dSAOperation"            ; DSA-specific operational     
     * 
     * extensions = *( SP xstring SP qdstrings )
     * xstring = "X" HYPHEN 1*( ALPHA / HYPHEN / USCORE ) 
     * </pre>
     * @throws IOException 
     * @throws LdapSchemaException 
     */
    private MutableAttributeType parseAttributeType( Reader reader, PosSchema pos ) throws IOException, LdapSchemaException
    {
        // Get rid of whites, comments end empty lines
        skipWhites( reader, pos, false );
        
        // we must have a '('
        if ( pos.line.charAt( pos.start ) != '(' )
        {
            return null;
        }
        else
        {
            pos.start++;
        }
        
        // Get rid of whites, comments end empty lines
        skipWhites( reader, pos, false );
        
        // Now, the OID. 
        String oid = getOidAndMacro( reader, pos );
        
        MutableAttributeType attributeType = new MutableAttributeType( oid );
        boolean hasSup = false;
        boolean hasSyntax = false;
        int elementsSeen = 0;
        
        while ( !startsWith( reader, pos, ')' ) )
        {
            skipWhites( reader, pos, true );

            if ( startsWith( pos, "NAME" ) )
            {
                elementsSeen = check( elementsSeen, AttributeTypeElements.NAME, pos );
                
                pos.start += "NAME".length();
                
                skipWhites( reader, pos, true );

                attributeType.setNames( getQDescrs( reader, pos ) );
            }
            else if ( startsWith( pos, "DESC" ) )
            {
                elementsSeen = check( elementsSeen, AttributeTypeElements.DESC, pos );

                pos.start += "DESC".length();
                
                skipWhites( reader, pos, true );

                attributeType.setDescription( getQDString( reader, pos ) );
            }
            else if ( startsWith( pos, "OBSOLETE" ) )
            {
                elementsSeen = check( elementsSeen, AttributeTypeElements.OBSOLETE, pos );
                
                pos.start += "OBSOLETE".length();
                
                attributeType.setObsolete( true );
            }
            else if ( startsWith( pos, "SUP" ) )
            {
                elementsSeen = check( elementsSeen, AttributeTypeElements.SUP, pos );
                
                pos.start += "SUP".length();
                
                skipWhites( reader, pos, true );
                
                String superiorOid = getOid( reader, pos );

                attributeType.setSuperiorOid( superiorOid );
                hasSup = true;
            }
            else if ( startsWith( pos, "EQUALITY" ) )
            {
                elementsSeen = check( elementsSeen, AttributeTypeElements.EQUALITY, pos );
                
                pos.start += "EQUALITY".length();
                
                skipWhites( reader, pos, true );
                
                String equalityOid = getOid( reader, pos );

                attributeType.setEqualityOid( equalityOid );
            }
            else if ( startsWith( pos, "ORDERING" ) )
            {
                elementsSeen = check( elementsSeen, AttributeTypeElements.ORDERING, pos );
                
                pos.start += "ORDERING".length();
                
                skipWhites( reader, pos, true );
                
                String orderingOid = getOid( reader, pos );

                attributeType.setOrderingOid( orderingOid );
            }
            else if ( startsWith( pos, "SUBSTR" ) )
            {
                elementsSeen = check( elementsSeen, AttributeTypeElements.SUBSTR, pos );

                pos.start += "SUBSTR".length();
                
                skipWhites( reader, pos, true );
                
                String substrOid = getOid( reader, pos );

                attributeType.setSubstringOid( substrOid );
            }
            else if ( startsWith( pos, "SYNTAX" ) )
            {
                elementsSeen = check( elementsSeen, AttributeTypeElements.SYNTAX, pos );
                
                pos.start += "SYNTAX".length();
                
                skipWhites( reader, pos, true );
                
                NoidLen noidLen = getNoidLen( reader, pos );

                attributeType.setSyntaxOid( noidLen.noid );
                attributeType.setSyntaxLength( noidLen.len );
                hasSyntax = true;
            }
            else if ( startsWith( pos, "SINGLE-VALUE" ) )
            {
                elementsSeen = check( elementsSeen, AttributeTypeElements.SINGLE_VALUE, pos );
                
                pos.start += "SINGLE-VALUE".length();
                
                attributeType.setSingleValued( true );
            }
            else if ( startsWith( pos, "COLLECTIVE" ) )
            {
                elementsSeen = check( elementsSeen, AttributeTypeElements.COLLECTIVE, pos );
                
                pos.start += "COLLECTIVE".length();
                
                attributeType.setCollective( true );
            }
            else if ( startsWith( pos, "NO-USER-MODIFICATION\"" ) )
            {
                elementsSeen = check( elementsSeen, AttributeTypeElements.NO_USER_MODIFICATION, pos );
                
                pos.start += "NO-USER-MODIFICATION\"".length();
                
                attributeType.setUserModifiable( false );
            }
            else if ( startsWith( pos, "USAGE" ) )
            {
                elementsSeen = check( elementsSeen, AttributeTypeElements.USAGE, pos );
                
                pos.start += "USAGE".length();
                
                skipWhites( reader, pos, true );
                
                UsageEnum usage = getUsage( reader, pos );

                attributeType.setUsage( usage );
            }
            else if ( startsWith( pos, "X-" ) )
            {
                Extension extension = getExtension( reader, pos );
                attributeType.addExtension( extension.key, extension.values );
            }
            else if ( startsWith( reader, pos, ')' ) )
            {
                pos.start++;
                
                return attributeType;
            }
            else
            {
                // This is an error
                throw new LdapSchemaException( I18n.err( I18n.ERR_13798_AT_DESCRIPTION_INVALID, 
                    pos.lineNumber, pos.start ) );
            }
        }
        
        if ( startsWith( reader, pos, ')' ) )
        {
            pos.start++;
            
            // Semantic checks
            if ( !isQuirksModeEnabled )
            {
                if ( !hasSup && !hasSyntax )
                {
                    throw new LdapSchemaException( I18n.err( I18n.ERR_13799_SYNTAX_OR_SUP_REQUIRED, 
                        pos.lineNumber, pos.start ) );
                }

                if ( attributeType.isCollective() && ( attributeType.getUsage() != UsageEnum.USER_APPLICATIONS ) )
                {
                    throw new LdapSchemaException( I18n.err( I18n.ERR_13800_COLLECTIVE_REQUIRES_USER_APPLICATION, 
                        pos.lineNumber, pos.start ) );
                }
            
                // NO-USER-MODIFICATION requires an operational USAGE.
                if ( !attributeType.isUserModifiable() && ( attributeType.getUsage() == UsageEnum.USER_APPLICATIONS ) )
                {
                    throw new LdapSchemaException( I18n.err( I18n.ERR_13801_NO_USER_MOD_REQUIRE_OPERATIONAL, 
                        pos.lineNumber, pos.start ) );
                }
            }
            
            return attributeType;
        }
        
        throw new LdapSchemaException( I18n.err( I18n.ERR_13798_AT_DESCRIPTION_INVALID, 
            pos.lineNumber, pos.start ) );
    }
    
    
    private int check( int elementsSeen, AttributeTypeElements element, PosSchema pos ) throws LdapSchemaException
    {
        if ( ( elementsSeen & element.value ) != 0 )
        {
            throw new LdapSchemaException( I18n.err( I18n.ERR_13780_AT_DESCRIPTION_HAS_ELEMENT_TWICE, element, pos.lineNumber, pos.start ) );
        }
        
        elementsSeen |= element.value;
        
        return elementsSeen;
    }
    
    
    /**
     * <pre>
     * extension    ::= xstring SP qdstrings
     * xstring      ::= "X" HYPHEN ( ALPHA | HYPHEN | USCORE )+
     * qdstrings    ::= qdstring | ( LPAREN WSP qdstringlist WSP RPAREN )
     * qdstringlist ::= qdstring *( SP qdstring )*
     * qdstring     ::= SQUOTE dstring SQUOTE
     * dstring      ::= 1*( QS / QQ / QUTF8 )   ; escaped UTF-8 string
     * </pre>
     * @throws IOException 
     * @throws LdapSchemaException 
     */
    private Extension getExtension( Reader reader, PosSchema pos ) throws LdapSchemaException, IOException
    {
        Extension extension = new Extension();
        
        // The xstring first
        extension.key = getXString( reader, pos );
        
        skipWhites( reader, pos, true );
        
        extension.values = getQDStrings( reader, pos );
        
        return extension;
    }
    
    
    /**
     * <pre>
     * xstring      ::= "X" HYPHEN ( ALPHA | HYPHEN | USCORE )+
     * </pre>
     */
    private String getXString( Reader reader, PosSchema pos ) throws LdapSchemaException, IOException
    {
        int start = pos.start;
        
        if ( startsWith( pos, "X-" ) )
        {
            pos.start += 2;
            
            // Now parse the remaining string
            while ( isAlpha( pos ) || startsWith( reader, pos, '-' ) || startsWith( reader, pos, '_' ) )
            {
                pos.start++;
            }
            
            return pos.line.substring( start, pos.start );
        }
        else
        {
            throw new LdapSchemaException( I18n.err( I18n.ERR_13802_EXTENSION_SHOULD_START_WITH_X, 
                pos.lineNumber, pos.start ) );
        }
    }
    
    
    /**
     * Production for matching ObjectClass descriptions. It is fault-tolerant
     * against element ordering.
     * <pre>
     * ObjectClassDescription = LPAREN WSP
     *   numericoid                 ; object identifier
     *   [ SP "NAME" SP qdescrs ]   ; short names (descriptors)
     *   [ SP "DESC" SP qdstring ]  ; description
     *   [ SP "OBSOLETE" ]          ; not active
     *   [ SP "SUP" SP oids ]       ; superior object classes
     *   [ SP kind ]                ; kind of class
     *   [ SP "MUST" SP oids ]      ; attribute types
     *   [ SP "MAY" SP oids ]       ; attribute types
     *   extensions WSP RPAREN
     *
     *   kind = "ABSTRACT" / "STRUCTURAL" / "AUXILIARY"
     * </pre>
     */
    private MutableObjectClass parseObjectClass( Reader reader, PosSchema pos ) throws IOException, LdapSchemaException
    {
        // Get rid of whites, comments end empty lines
        skipWhites( reader, pos, false );
        
        // we must have a '('
        if ( pos.line.charAt( pos.start ) != '(' )
        {
            return null;
        }
        else
        {
            pos.start++;
        }
        
        // Get rid of whites, comments end empty lines
        skipWhites( reader, pos, false );
        
        // Now, the numeric OID
        String oid = getOid( reader, pos );
        
        MutableObjectClass objectClass = new MutableObjectClass( oid );
        int elementsSeen = 0;
        
        while ( !startsWith( reader, pos, ')' ) )
        {
            skipWhites( reader, pos, true );

            if ( startsWith( pos, "NAME" ) )
            {
                elementsSeen = check( elementsSeen, ObjectClassElements.NAME, pos );

                pos.start += "NAME".length();
                
                skipWhites( reader, pos, true );

                List<String> names = getQDescrs( reader, pos );
                objectClass.setNames( names );
            }
            else if ( startsWith( pos, "DESC" ) )
            {
                elementsSeen = check( elementsSeen, ObjectClassElements.DESC, pos );
                
                pos.start += "DESC".length();
                
                skipWhites( reader, pos, true );

                objectClass.setDescription( getQDString( reader, pos ) );
            }
            else if ( startsWith( pos, "OBSOLETE" ) )
            {
                elementsSeen = check( elementsSeen, ObjectClassElements.OBSOLETE, pos );
                
                pos.start += "OBSOLETE".length();
                
                objectClass.setObsolete( true );
            }
            else if ( startsWith( pos, "SUP" ) )
            {
                elementsSeen = check( elementsSeen, ObjectClassElements.SUP, pos );
                
                pos.start += "SUP".length();
                
                skipWhites( reader, pos, true );
                
                List<String> superiorOids = getOids( reader, pos );

                objectClass.setSuperiorOids( superiorOids );
            }
            else if ( startsWith( pos, "ABSTRACT" ) )
            {
                elementsSeen = check( elementsSeen, ObjectClassElements.ABSTRACT, pos );
                
                pos.start += "ABSTRACT".length();
                
                objectClass.setType( ObjectClassTypeEnum.ABSTRACT );
            }
            else if ( startsWith( pos, "STRUCTURAL" ) )
            {
                elementsSeen = check( elementsSeen, ObjectClassElements.STRUCTURAL, pos );
                
                pos.start += "STRUCTURAL".length();
                
                objectClass.setType( ObjectClassTypeEnum.STRUCTURAL );
            }
            else if ( startsWith( pos, "AUXILIARY" ) )
            {
                elementsSeen = check( elementsSeen, ObjectClassElements.AUXILIARY, pos );
                
                pos.start += "AUXILIARY".length();
                
                objectClass.setType( ObjectClassTypeEnum.AUXILIARY );
            }
            else if ( startsWith( pos, "MUST" ) )
            {
                elementsSeen = check( elementsSeen, ObjectClassElements.MUST, pos );
                
                pos.start += "MUST".length();
                
                skipWhites( reader, pos, true );
                
                List<String> mustAttributeTypes = getOids( reader, pos );
                objectClass.setMustAttributeTypeOids( mustAttributeTypes );
            }
            else if ( startsWith( pos, "MAY" ) )
            {
                elementsSeen = check( elementsSeen, ObjectClassElements.MAY, pos );
                
                pos.start += "MAY".length();
                
                skipWhites( reader, pos, true );
                
                List<String> mayAttributeTypes = getOids( reader, pos );
                objectClass.setMayAttributeTypeOids( mayAttributeTypes );
            }
            else if ( startsWith( pos, "X-" ) )
            {
                Extension extension = getExtension( reader, pos );
                objectClass.addExtension( extension.key, extension.values );
            }
            else if ( startsWith( reader, pos, ')' ) )
            {
                pos.start++;
                
                return objectClass;
            }
            else
            {
                // This is an error
                throw new LdapSchemaException( I18n.err( I18n.ERR_13803_OC_DESCRIPTION_INVALID, 
                    pos.lineNumber, pos.start ) );
            }
        }
        
        return objectClass;
    }
    
    
    private int check( int elementsSeen, ObjectClassElements element, PosSchema pos ) throws LdapSchemaException
    {
        if ( ( elementsSeen & element.value ) != 0 )
        {
            throw new LdapSchemaException( I18n.err( I18n.ERR_13781_OC_DESCRIPTION_HAS_ELEMENT_TWICE, element, pos.lineNumber, pos.start ) );
        }
        
        elementsSeen |= element.value;
        
        return elementsSeen;
    }

    
    /**
     * Process OpenLDAP macros, like : objectidentifier DUAConfSchemaOID 1.3.6.1.4.1.11.1.3.1.
     * 
     * <pre>
     * objectidentifier ::= 'objectidentifier' descr SP+ macroOid
     * descr             ::= ALPHA ( ALPHA | DIGIT | HYPHEN )*
     * macroOid         ::= (descr ':')? oid
     * </pre>
     */
    private void processObjectIdentifier( Reader reader, PosSchema pos ) throws IOException, LdapSchemaException
    {
        // Get rid of whites, comments end empty lines
        skipWhites( reader, pos, false );
        
        // Now, the name
        String name = getDescr( reader, pos );
        
        OpenLdapObjectIdentifierMacro macro = new OpenLdapObjectIdentifierMacro();
        
        skipWhites( reader, pos, true );

        if ( isEmpty( pos ) )
        {
            throw new LdapSchemaException( I18n.err( I18n.ERR_13804_OBJECT_IDENTIFIER_HAS_NO_OID, 
                pos.lineNumber, pos.start ) );
        }
        
        // Get the descr, if any
        if ( isAlpha( pos ) )
        {
            // A macro
            String descr = getMacro( reader, pos );
            
            if ( isEmpty( pos ) )
            {
                throw new LdapSchemaException( I18n.err( I18n.ERR_13804_OBJECT_IDENTIFIER_HAS_NO_OID, 
                    pos.lineNumber, pos.start ) );
            }
            
            if ( startsWith( reader, pos, ':' ) )
            {
                pos.start++;
                
                // Now, the OID
                String numericOid = getNumericOid( reader, pos );
                String realOid = objectIdentifierMacros.get( descr ).getRawOidOrNameSuffix() + '.' + numericOid;
                macro.setName( name );
                macro.setRawOidOrNameSuffix( realOid );
                
                objectIdentifierMacros.put( name, macro );
                
                return;
            }
        }
        else if ( isDigit( pos ) )
        {
            // An oid
            String numericOid = getNumericOid( reader, pos );
            macro.setRawOidOrNameSuffix( numericOid );
            macro.setName( name );
            
            objectIdentifierMacros.put( name, macro );
            
            return;
        }
        else
        {
            throw new LdapSchemaException( I18n.err( I18n.ERR_13805_OBJECT_IDENTIFIER_INVALID_OID, 
                pos.lineNumber, pos.start ) );
        }
    }
    
    
    /**
     * Reads an entry in a ldif buffer, and returns the resulting lines, without
     * comments, and unfolded.
     *
     * The lines represent *one* entry.
     *
     * @throws LdapLdifException If something went wrong
     */
    private void parse( Reader reader ) throws LdapSchemaException, IOException
    {
        PosSchema pos = new PosSchema();

        while ( true )
        {
            // Always move forward to the next element, skipping whites, NL and comments
            skipWhites( reader, pos, false );
            
            if ( pos.line == null )
            {
                // The end, get out
                break;
            }
            
            // Ok, we have something which must be one of openLdapObjectIdentifier( "objectidentifier" ), 
            // openLdapAttributeType ( "attributetype" )  or openLdapObjectClass ( "objectclass" )
            if ( startsWith( pos, "objectidentifier" ) )
            {
                pos.start += "objectidentifier".length();
                
                processObjectIdentifier( reader, pos );
            }
            else if ( startsWith( pos, "attributetype" ) )
            {
                pos.start += "attributetype".length();
                
                MutableAttributeType attributeType = parseAttributeType( reader, pos );
                schemaDescriptions.add( attributeType );
            }
            else if ( startsWith( pos, "objectclass" ) )
            {
                pos.start += "objectclass".length();
                
                MutableObjectClass objectClass = parseObjectClass( reader, pos );
                schemaDescriptions.add( objectClass );
            }
            else
            {
                // This is an error
                throw new LdapSchemaException( I18n.err( I18n.ERR_13806_UNEXPECTED_ELEMENT_READ, 
                    pos.line.substring( pos.start ), pos.lineNumber, pos.start ) );
            }
        }
    }


    /**
     * Parses a file of OpenLDAP schemaObject elements/objects. Default charset is used.
     *
     * @param schemaFile a file of schema objects
     * @throws IOException If the schemaObject can't be transformed to a byteArrayInputStream
     * @throws ParseException If the schemaObject can't be parsed
     */
    public void parse( File schemaFile ) throws ParseException
    {
        try ( InputStream is = Files.newInputStream( Paths.get( schemaFile.getPath() ) ) )
        {
            try ( Reader reader = new BufferedReader( new InputStreamReader( is, Charset.defaultCharset() ) ) )
            {
                parse( reader );
                afterParse();
            }
            catch ( LdapSchemaException | IOException e )
            {
                throw new ParseException( e.getMessage(), 0 );
            }
        }
        catch ( IOException e )
        {
            String msg = I18n.err( I18n.ERR_13443_CANNOT_FIND_FILE, schemaFile.getAbsoluteFile() );
            LOG.error( msg );
            throw new ParseException( e.getMessage(), 0 );
        }
    }


    /**
     * Checks if object identifier macros should be resolved.
     * 
     * @return true, object identifier macros should be resolved.
     */
    public boolean isResolveObjectIdentifierMacros()
    {
        return isResolveObjectIdentifierMacros;
    }


    /**
     * Sets if object identifier macros should be resolved.
     * 
     * @param resolveObjectIdentifierMacros true if object identifier macros should be resolved
     */
    public void setResolveObjectIdentifierMacros( boolean resolveObjectIdentifierMacros )
    {
        this.isResolveObjectIdentifierMacros = resolveObjectIdentifierMacros;
    }

    /**
     * Checks if quirks mode is enabled.
     * 
     * @return true, if is quirks mode is enabled
     */
    public boolean isQuirksMode()
    {
        return isQuirksModeEnabled;
    }


    /**
     * Sets the quirks mode. 
     * 
     * If enabled the parser accepts non-numeric OIDs and some 
     * special characters in descriptions.
     * 
     * @param enabled the new quirks mode
     */
    public void setQuirksMode( boolean enabled )
    {
        isQuirksModeEnabled = enabled;
    }
}