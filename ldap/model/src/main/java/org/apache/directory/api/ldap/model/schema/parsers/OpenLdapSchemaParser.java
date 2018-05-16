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

import org.apache.directory.api.asn1.util.Oid;
import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.exception.LdapSchemaException;
import org.apache.directory.api.ldap.model.ldif.LdapLdifException;
import org.apache.directory.api.ldap.model.schema.AttributeType;
import org.apache.directory.api.ldap.model.schema.DitContentRule;
import org.apache.directory.api.ldap.model.schema.DitStructureRule;
import org.apache.directory.api.ldap.model.schema.LdapSyntax;
import org.apache.directory.api.ldap.model.schema.MatchingRule;
import org.apache.directory.api.ldap.model.schema.MatchingRuleUse;
import org.apache.directory.api.ldap.model.schema.MutableAttributeType;
import org.apache.directory.api.ldap.model.schema.MutableMatchingRule;
import org.apache.directory.api.ldap.model.schema.MutableObjectClass;
import org.apache.directory.api.ldap.model.schema.NameForm;
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
public class OpenLdapSchemaParser
{
    /** The LoggerFactory used by this class */
    protected static final Logger LOG = LoggerFactory.getLogger( OpenLdapSchemaParser.class );

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
    
    /** Some contant strings used in descriptions */
    private static final String APPLIES_STR                 = "APPLIES";
    private static final String ABSTRACT_STR                = "ABSTRACT";
    private static final String AUX_STR                     = "AUX";
    private static final String AUXILIARY_STR               = "AUXILIARY";
    private static final String BYTECODE_STR                = "BYTECODE";
    private static final String COLLECTIVE_STR              = "COLLECTIVE";
    private static final String DESC_STR                    = "DESC";
    private static final String EQUALITY_STR                = "EQUALITY";
    private static final String FORM_STR                    = "FORM";
    private static final String FQCN_STR                    = "FQCN";
    private static final String MAY_STR                     = "MAY";
    private static final String MUST_STR                    = "MUST";
    private static final String NAME_STR                    = "NAME";
    private static final String NO_USER_MODIFICATION_STR    = "NO-USER-MODIFICATION";
    private static final String NOT_STR                     = "NOT";
    private static final String OBSOLETE_STR                = "OBSOLETE";
    private static final String OC_STR                      = "OC";
    private static final String ORDERING_STR                = "ORDERING";
    private static final String SINGLE_VALUE_STR            = "SINGLE-VALUE";
    private static final String STRUCTURAL_STR              = "STRUCTURAL";
    private static final String SUBSTR_STR                  = "SUBSTR";
    private static final String SUP_STR                     = "SUP";
    private static final String SYNTAX_STR                  = "SYNTAX";
    private static final String USAGE_STR                   = "USAGE";
    private static final String EXTENSION_PREFIX            = "X-";
    
    /** Usage */
    private static final String DIRECTORY_OPERATION_STR     = "directoryOperation";
    private static final String DISTRIBUTED_OPERATION_STR   = "distributedOperation";
    private static final String DSA_OPERATION_STR           = "dSAOperation";
    private static final String USER_APPLICATIONS_STR       = "userApplications";

    /** Tokens */
    private static final char COLON         = ':';
    private static final char DOLLAR        = '$';
    private static final char DOT           = '.';
    private static final char EQUAL         = '=';
    private static final char ESCAPE        = '\\';
    private static final char HYPHEN        = '-';
    private static final char LBRACE        = '{';
    private static final char LPAREN        = '(';
    private static final char PLUS          = '+';
    private static final char RBRACE        = '}';
    private static final char RPAREN        = ')';
    private static final char SEMI_COLON    = ';';
    private static final char SHARP         = '#';
    private static final char SLASH         = '/';
    private static final char SQUOTE        = '\'';
    private static final char UNDERSCORE    = '_';
    private static final char DQUOTE        = '"';


    /** Flag whether object identifier macros should be resolved. */
    private boolean isResolveObjectIdentifierMacros;
    
    private static final boolean UN_QUOTED = false;
    
    /** Flag for strict or relaxed mode */
    private static final boolean STRICT = false;
    private static final boolean RELAXED = true;
    
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


    private interface SchemaObjectElements
    {
        int getValue();
    }

    
    /**
     * The list of AttributeTypeDescription elements that can be seen 
     */
    private enum AttributeTypeElements implements SchemaObjectElements
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
        
        
        public int getValue()
        {
            return value;
        }
    }
    
    
    /**
     * The list of DitContentRuleDescription elements that can be seen 
     */
    private enum DitContentRuleElements implements SchemaObjectElements
    {
        NAME(1),
        DESC(2),
        OBSOLETE(4),
        AUX(8),
        MUST(16),
        MAY(32),
        NOT(64);
        
        private int value;
        
        DitContentRuleElements( int value )
        {
            this.value = value;
        }
        
        
        public int getValue()
        {
            return value;
        }
    }


    /**
     * The list of DitStructureRuleDescription elements that can be seen 
     */
    private enum DitStructureRuleElements implements SchemaObjectElements
    {
        NAME(1),
        DESC(2),
        OBSOLETE(4),
        FORM(8),
        SUP(16);
        
        private int value;
        
        DitStructureRuleElements( int value )
        {
            this.value = value;
        }
        
        
        public int getValue()
        {
            return value;
        }
    }

    
    /**
     * The list of LdapComparatorDescription elements that can be seen 
     */
    private enum LdapComparatorElements implements SchemaObjectElements
    {
        DESC(1),
        FQCN(2),
        BYTECODE(4);
        
        private int value;
        
        LdapComparatorElements( int value )
        {
            this.value = value;
        }
        
        
        public int getValue()
        {
            return value;
        }
    }

    
    /**
     * The list of LdapSyntaxDescription elements that can be seen 
     */
    private enum LdapSyntaxElements implements SchemaObjectElements
    {
        DESC(1);
        
        private int value;
        
        LdapSyntaxElements( int value )
        {
            this.value = value;
        }
        
        
        public int getValue()
        {
            return value;
        }
    }


    /**
     * The list of MatchingRuleDescription elements that can be seen 
     */
    private enum MatchingRuleElements implements SchemaObjectElements
    {
        NAME(1),
        DESC(2),
        OBSOLETE(4),
        SYNTAX(8);
        
        private int value;
        
        MatchingRuleElements( int value )
        {
            this.value = value;
        }
        
        
        public int getValue()
        {
            return value;
        }
    }

    
    /**
     * The list of MatchingRuleUseDescription elements that can be seen 
     */
    private enum MatchingRuleUseElements implements SchemaObjectElements
    {
        NAME(1),
        DESC(2),
        OBSOLETE(4),
        APPLIES(8);
        
        private int value;
        
        MatchingRuleUseElements( int value )
        {
            this.value = value;
        }
        
        
        public int getValue()
        {
            return value;
        }
    }

    
    /**
     * The list of NameFormDescription elements that can be seen 
     */
    private enum NameFormElements implements SchemaObjectElements
    {
        NAME(1),
        DESC(2),
        OBSOLETE(4),
        OC(8),
        MUST(16),
        MAY(32);
        
        private int value;
        
        NameFormElements( int value )
        {
            this.value = value;
        }
        
        
        public int getValue()
        {
            return value;
        }
    }


    /**
     * The list of NormalizerDescription elements that can be seen 
     */
    private enum NormalizerElements implements SchemaObjectElements
    {
        DESC(1),
        FQCN(2),
        BYTECODE(4);
        
        private int value;
        
        NormalizerElements( int value )
        {
            this.value = value;
        }
        
        
        public int getValue()
        {
            return value;
        }
    }


    /**
     * The list of ObjectClassDescription elements that can be seen 
     */
    private enum ObjectClassElements implements SchemaObjectElements
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
        
        
        public int getValue()
        {
            return value;
        }
    }


    /**
     * The list of SyntaxCheckerDescription elements that can be seen 
     */
    private enum SyntaxCheckerElements implements SchemaObjectElements
    {
        DESC(1),
        FQCN(2),
        BYTECODE(4);
        
        private int value;
        
        SyntaxCheckerElements( int value )
        {
            this.value = value;
        }
        
        
        public int getValue()
        {
            return value;
        }
    }


    /**
     * Creates a reusable instance of an OpenLdapSchemaParser.
     *
     * @throws IOException if the pipe cannot be formed
     */
    public OpenLdapSchemaParser()
    {
        isResolveObjectIdentifierMacros = true;
        isQuirksModeEnabled = false;
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
    public List<ObjectClass> getObjectClasses()
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
        if ( oid != null && oid.indexOf( COLON ) != -1 )
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
        else if ( rawOidOrNameSuffix.indexOf( COLON ) != -1 )
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
    public void parse( InputStream schemaIn ) throws ParseException, LdapSchemaException, IOException
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
    
    
    private static void skipWhites( Reader reader, PosSchema pos, boolean mandatory ) throws IOException, LdapSchemaException
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
            
            if ( pos.line.charAt( pos.start ) == SHARP )
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
    
    
    private static boolean isComment( PosSchema pos )
    {
        if ( isEmpty( pos ) )
        {
            return true;
        }
        
        return pos.line.charAt( pos.start ) == SHARP;
    }
    
    
    private static boolean isEmpty( PosSchema pos )
    {
        return ( pos.line == null ) || ( pos.start >= pos.line.length() );
    }
    
    
    private static boolean startsWith( PosSchema pos, String text )
    {
        if ( ( pos.line == null ) || ( pos.line.length() - pos.start < text.length() ) )
        {
            return false;
        }
        
        return text.equalsIgnoreCase( pos.line.substring( pos.start, pos.start + text.length() ) );
    }
    
    
    private static boolean startsWith( Reader reader, PosSchema pos, char c ) throws IOException, LdapSchemaException
    {
        return startsWith( reader, pos, c, UN_QUOTED );
    }
    
    
    private static boolean startsWith( Reader reader, PosSchema pos, char c, boolean quoted ) throws IOException, LdapSchemaException
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
    
    
    private static boolean startsWith( PosSchema pos, char c )
    {
        if ( ( pos.line == null ) || ( pos.line.length() - pos.start < 1 ) )
        {
            return false;
        }
        
        return pos.line.charAt( pos.start ) == c;
    }

    
    private static boolean isAlpha( PosSchema pos )
    {
        return Character.isAlphabetic( pos.line.charAt( pos.start ) );
    }
    
    
    private static boolean isDigit( PosSchema pos )
    {
        return Character.isDigit( pos.line.charAt( pos.start ) );
    }

    
    private static void getLine( Reader reader, PosSchema pos ) throws IOException
    {
        pos.line = ( ( BufferedReader ) reader ).readLine();
        pos.start = 0;
        
        if ( pos.line != null )
        {
            pos.lineNumber++;
        }
    }
    
    
    /**
     * numericoid   ::= number ( DOT number )+
     * number       ::= DIGIT | LDIGIT DIGIT+
     * DIGIT        ::= %x30 | LDIGIT       ; "0"-"9"
     * LDIGIT       ::= %x31-39             ; "1"-"9"
     * DOT          ::= %x2E                ; period (".")
     */
    private static String getNumericOid( PosSchema pos ) throws LdapSchemaException
    {
        int start = pos.start;
        boolean isDot = false;
        boolean isFirstZero = false;
        boolean isFirstDigit = true; 
        
        while ( !isEmpty( pos ) )
        {
            char c = pos.line.charAt( pos.start );
            
            if ( Character.isDigit( c ) )
            {
                if ( isFirstZero )
                {
                    throw new LdapSchemaException( I18n.err( I18n.ERR_13784_BAD_OID_TWO_ZEROES, pos.lineNumber, pos.start ) );
                }
                    
                if ( ( pos.line.charAt( pos.start ) == '0' ) && isFirstDigit )
                {
                    isFirstZero = true;
                }
                
                isDot = false;
                pos.start++;
                isFirstDigit = false;
            }
            else if ( c == DOT )
            {
                if ( isDot )
                {
                    // We can't have two consecutive dots or a dot at the beginning
                    throw new LdapSchemaException( I18n.err( I18n.ERR_13785_BAD_OID_CONSECUTIVE_DOTS, pos.lineNumber, pos.start ) );
                }
                
                isFirstZero = false;
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

        String oidStr = pos.line.substring( start, pos.start );

        if ( Oid.isOid( oidStr ) )
        {
            return oidStr;
        }
        else
        {
            throw new LdapSchemaException( I18n.err( I18n.ERR_13787_OID_EXPECTED, pos.line, pos.start ) );
        }
    }
    
    
    /**
     * partialNumericoid   ::= number ( DOT number )*
     * number              ::= DIGIT | LDIGIT DIGIT+
     * DIGIT               ::= %x30 | LDIGIT       ; "0"-"9"
     * LDIGIT              ::= %x31-39             ; "1"-"9"
     * DOT                 ::= %x2E                ; period (".")
     */
    private static String getPartialNumericOid( PosSchema pos ) throws LdapSchemaException
    {
        int start = pos.start;
        boolean isDot = false;
        boolean isFirstZero = false;
        boolean isFirstDigit = true; 
        
        while ( !isEmpty( pos ) )
        {
            if ( isDigit( pos ) )
            {
                if ( isFirstZero )
                {
                    throw new LdapSchemaException( I18n.err( I18n.ERR_13784_BAD_OID_TWO_ZEROES, pos.lineNumber, pos.start ) );
                }
                    
                if ( ( pos.line.charAt( pos.start ) == '0' ) && isFirstDigit )
                {
                    isFirstZero = true;
                }
                
                isDot = false;
                pos.start++;
                isFirstDigit = false;
            }
            else if ( startsWith( pos, DOT ) )
            {
                if ( isDot )
                {
                    // We can't have two consecutive dots or a dot at the beginning
                    throw new LdapSchemaException( I18n.err( I18n.ERR_13785_BAD_OID_CONSECUTIVE_DOTS, pos.lineNumber, pos.start ) );
                }
                
                isFirstZero = false;
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
     * In relaxed mode :
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
    private static String getOidAndMacroRelaxed( PosSchema pos, 
        Map<String, OpenLdapObjectIdentifierMacro> objectIdentifierMacros ) throws LdapSchemaException
    {
        if ( isEmpty( pos ) )
        {
            return "";
        }

        // This is a OID name
        int start = pos.start;
        char c = pos.line.charAt( pos.start );
        boolean isDigit = Character.isDigit( c );
        
        while ( isDigit || Character.isAlphabetic( c ) || ( c == HYPHEN ) || ( c == UNDERSCORE )
            || ( c == SEMI_COLON ) || ( c == DOT ) || ( c == SHARP ) )
        {
            pos.start++;
            
            if ( isEmpty( pos ) )
            {
                break;
            }
            
            c = pos.line.charAt( pos.start );
            isDigit = Character.isDigit( c );
        }
        
        String oidName = pos.line.substring( start, pos.start  );
        
        if ( Strings.isEmpty( oidName ) )
        {
            throw new LdapSchemaException( I18n.err( I18n.ERR_13787_OID_EXPECTED, pos.lineNumber, pos.start ) );
        }
        
        // We may have a ':' followed by an OID
        if ( startsWith( pos, COLON ) )
        {
            pos.start++;
            String oid = getPartialNumericOid( pos );
            
            return objectIdentifierMacros.get( oidName ).getRawOidOrNameSuffix() + DOT + oid;
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
     */
    private static String getOidStrict( PosSchema pos ) throws LdapSchemaException
    {
        if ( isEmpty( pos ) )
        {
            return "";
        }

        if ( isAlpha( pos ) )
        {
            // A descr
            return getDescrStrict( pos );
        }
        else if ( isDigit( pos ) )
        {
            // This is a numeric oid
            return getNumericOid( pos );
        }
        else
        {
            // This is an error
            throw new LdapSchemaException( I18n.err( I18n.ERR_13787_OID_EXPECTED, pos.lineNumber, pos.start ) );
        }
    }

    
    /**
     * In quirks mode :
     * <pre>
     * oid          ::= descr-relaxed | numericoid | SQUOTE descr-relaxed SQUOTE |
     *                  DQUOTE descr-relaxed DQUOTE | SQUOTE numericoid SQUOTE |
     *                  DQUOTE numericoid DQUOTE
     * descr-relaxed::= macro (COLON numericoid)
     * macro        ::= keystring
     * keystring    ::= Lkeychar  keychar*
     * Lkeychar     ::= ALPHA | HYPHEN | UNDERSCORE | SEMI_COLON | DOT | COLON | SHARP 
     * keychar      ::= ALPHA | DIGIT | HYPHEN | UNDERSCORE | SEMI_COLON | DOT | COLON | SHARP 
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
    private static String getOidRelaxed( PosSchema pos, boolean hadQuote ) throws LdapSchemaException
    {
        if ( isEmpty( pos ) )
        {
            return "";
        }
        
        boolean hasQuote = false;

        char c = pos.line.charAt( pos.start );
        
        if ( c == SQUOTE )
        {
            if ( hadQuote )
            {
                return "";
            }
            
            hasQuote = true;
            pos.start++;

            if ( isEmpty( pos ) )
            {
                return "";
            }
            
            c = pos.line.charAt( pos.start );
        }
        
        String oid;

        if ( Character.isAlphabetic( c ) )
        {
            // This is a OID name
            oid = getDescrRelaxed( pos );
        }
        else if ( Character.isDigit( c ) )
        {
            // This is a numeric oid
            oid = getNumericOid( pos );
        }
        else
        {
            // This is an error
            throw new LdapSchemaException( I18n.err( I18n.ERR_13787_OID_EXPECTED, 
                pos.lineNumber, pos.start ) );
        }
        
        if ( isEmpty( pos ) )
        {
            if ( hasQuote || hadQuote )
            {
                throw new LdapSchemaException( I18n.err( I18n.ERR_13792_SIMPLE_QUOTE_EXPECTED_AT_END, 
                    pos.lineNumber, pos.start ) );
            }
            else
            {
                return oid;
            }
        }
        
        c = pos.line.charAt( pos.start );
        
        if ( ( c == SQUOTE ) && !hadQuote )
        {
           if ( hasQuote )
           {
               pos.start++;
           }
           else
           {
               throw new LdapSchemaException( I18n.err( I18n.ERR_13792_SIMPLE_QUOTE_EXPECTED_AT_END, 
                   pos.lineNumber, pos.start ) );
           }
        }
        
        return oid;
    }
    
    
    /**
     * In strict mode :
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
     */
    private static String getDescrStrict( PosSchema pos ) throws LdapSchemaException
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
                
                if ( Character.isAlphabetic( c ) || Character.isDigit( c ) || ( c == HYPHEN ) )
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
    
    
    
    /**
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
     */
    private static String getDescrRelaxed( PosSchema pos ) throws LdapSchemaException
    {
        int start = pos.start;
        boolean isFirst = true;
        
        while ( !isEmpty( pos ) )
        {
            if ( isFirst )
            {
                isFirst = false;
                
                char c = pos.line.charAt( pos.start );
                
                if ( Character.isAlphabetic( c ) || ( c == HYPHEN ) || ( c == UNDERSCORE )
                    || ( c == SEMI_COLON ) || ( c == DOT ) || ( c == COLON ) || ( c == SHARP ) ) 
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
                
                if ( Character.isAlphabetic( c ) || Character.isDigit( c ) || ( c == HYPHEN )
                    || ( c == UNDERSCORE ) || ( c == SEMI_COLON ) || ( c == DOT ) || ( c == COLON ) || ( c == SHARP ) ) 
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
    
    
    private String getMacro( PosSchema pos ) throws LdapSchemaException
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
                    
                    if ( Character.isAlphabetic( c ) || ( c == HYPHEN ) || ( c == UNDERSCORE ) 
                        || ( c == SEMI_COLON ) || ( c == DOT ) || ( c == SHARP ) ) 
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
                    
                    if ( Character.isAlphabetic( c ) || Character.isDigit( c ) || ( c == HYPHEN ) 
                        || ( c == UNDERSCORE ) || ( c == SEMI_COLON ) || ( c == DOT ) || ( c == SHARP ) ) 
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
                    
                    if ( Character.isAlphabetic( c ) || Character.isDigit( c ) || ( c == HYPHEN ) )
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
    private static String getQDescrStrict( Reader reader, PosSchema pos ) throws LdapSchemaException, IOException
    {
        // The first quote
        if ( !startsWith( reader, pos, SQUOTE ) )
        {
            throw new LdapSchemaException( I18n.err( I18n.ERR_13789_SIMPLE_QUOTE_EXPECTED_AT_START, 
                pos.lineNumber, pos.start ) );
        }
        
        pos.start++;
        int start = pos.start;
        boolean isFirst = true;
        
        while ( !startsWith( pos, SQUOTE ) )
        {
            if ( isFirst )
            {
                isFirst = false;
                
                if ( !isEmpty( pos ) && isAlpha( pos ) ) 
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
                if ( isEmpty( pos ) )
                {
                    // This is an error
                    throw new LdapSchemaException( I18n.err( I18n.ERR_13792_SIMPLE_QUOTE_EXPECTED_AT_END, 
                        pos.lineNumber, pos.start ) );
                }
                
                char c = pos.line.charAt( pos.start );
                
                if ( Character.isAlphabetic( c ) || Character.isDigit( c ) || ( c == HYPHEN ) )
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
        
        if ( startsWith( pos, SQUOTE ) )
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
    private static String getQDescrRelaxed( Reader reader, PosSchema pos ) throws LdapSchemaException, IOException
    {
        if ( startsWith( reader, pos, SQUOTE ) )
        {
            pos.start++;
            int start = pos.start;
            
            while ( !startsWith( pos, SQUOTE ) )
            {
                if ( isEmpty( pos ) )
                {
                    throw new LdapSchemaException( I18n.err( I18n.ERR_13789_SIMPLE_QUOTE_EXPECTED_AT_START, 
                        pos.lineNumber, pos.start ) );
                }
                
                char c = pos.line.charAt( pos.start );
                
                if ( Character.isDigit( c ) || Character.isAlphabetic( c ) || ( c == HYPHEN ) || ( c == UNDERSCORE )
                    || ( c == SEMI_COLON ) || ( c == DOT ) || ( c == COLON ) || ( c == SHARP ) )
                {
                    pos.start++;
                }
                else if ( c != SQUOTE )
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

                if ( Character.isDigit( c ) || Character.isAlphabetic( c ) || ( c == HYPHEN ) || ( c == UNDERSCORE )
                    || ( c == SEMI_COLON ) || ( c == DOT ) || ( c == COLON ) || ( c == SHARP ) )
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
    
    
    /**
     * No relaxed version.
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
    private static String getQDString( Reader reader, PosSchema pos ) throws LdapSchemaException, IOException
    {
        // The first quote
        if ( !startsWith( reader, pos, SQUOTE ) )
        {
            throw new LdapSchemaException( I18n.err( I18n.ERR_13789_SIMPLE_QUOTE_EXPECTED_AT_START, 
                pos.lineNumber, pos.start ) );
        }
        
        pos.start++;
        int start = pos.start;
        int nbEscapes = 0;
        
        while ( !isEmpty( pos ) && !startsWith( pos, SQUOTE ) )
        {
            // At the moment, just swallow anything
            if ( startsWith( pos, ESCAPE ) )
            {
                nbEscapes++;
            }
            
            pos.start++;
            
        }
        
        if ( startsWith( pos, SQUOTE ) )
        {
            // We are done, move one char forward to eliminate the simple quote
            pos.start++;
            
            // Now, un-escape the escaped chars
            char[] unescaped = new char[pos.start - 1 - start - nbEscapes * 2];
            int newPos = 0;
            
            for ( int i = start; i < pos.start - 1; i++ )
            {
                char c = pos.line.charAt( i );
                
                if ( c == ESCAPE )
                {
                    if ( i + 2 > pos.start )
                    {
                        // Error : not enough hex value
                        throw new LdapSchemaException( I18n.err( I18n.ERR_13792_SIMPLE_QUOTE_EXPECTED_AT_END, 
                            pos.lineNumber, pos.start ) );
                    }
                    
                    int u = Character.digit( pos.line.charAt( i + 1 ), 16 );
                    int l = Character.digit( pos.line.charAt( i + 2 ), 16 );

                    unescaped[newPos] = ( char ) ( ( u << 4 ) + l );
                    i += 2;
                }
                else
                {
                    unescaped[newPos] = c;
                }
                
                newPos++;
            }
            
            return new String( unescaped );
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
    private static List<String> getQDescrs( Reader reader, PosSchema pos, boolean relaxed ) throws LdapSchemaException, IOException
    {
        List<String> qdescrs = new ArrayList<>();
        
        // It may start with a '('
        if ( startsWith( reader, pos, LPAREN ) )
        {
            pos.start++;
            
            // We have more than a name
            skipWhites( reader, pos, false );
            
            while ( !startsWith( reader, pos, RPAREN ) )
            {
                String qdescr;
                
                if ( relaxed )
                {
                    qdescr = getQDescrRelaxed( reader, pos );
                }
                else
                {
                    qdescr = getQDescrStrict( reader, pos );
                }
                
                qdescrs.add( qdescr );
                
                if ( startsWith( reader, pos, RPAREN ) )
                {
                    break;
                }
                
                skipWhites( reader, pos, true );
            }
            
            if ( !startsWith( reader, pos, RPAREN ) )
            {
                throw new LdapSchemaException( I18n.err( I18n.ERR_13793_NO_CLOSING_PAREN, 
                    pos.lineNumber, pos.start ) );
            }
            
            pos.start++;
        }
        else
        {
            // Only one name, read it
            String qDescr;
            
            if ( relaxed )
            {
                qDescr = getQDescrRelaxed( reader, pos );
            }
            else
            {
                qDescr = getQDescrStrict( reader, pos );
            }
            
            if ( Strings.isEmpty( qDescr ) )
            {
                throw new LdapSchemaException( I18n.err( I18n.ERR_13732_NAME_CANNOT_BE_NULL, pos.lineNumber, pos.start ) );
            }
            
            qdescrs.add( qDescr );
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
    private static List<String> getQDStrings( Reader reader, PosSchema pos ) 
        throws LdapSchemaException, IOException
    {
        List<String> qdStrings = new ArrayList<>();
        
        // It may start with a '('
        if ( startsWith( reader, pos, LPAREN ) )
        {
            pos.start++;
            
            // We have more than a name
            skipWhites( reader, pos, false );
            
            while ( !startsWith( reader, pos, RPAREN ) )
            {
                qdStrings.add( getQDString( reader, pos ) );
                
                if ( startsWith( reader, pos, RPAREN ) )
                {
                    break;
                }
                
                skipWhites( reader, pos, true );
            }
            
            if ( !startsWith( reader, pos, RPAREN ) )
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
    private static List<String> getOidsStrict( Reader reader, PosSchema pos ) throws LdapSchemaException, IOException
    {
        List<String> oids = new ArrayList<>();
        
        // It may start with a '('
        if ( startsWith( reader, pos, LPAREN ) )
        {
            pos.start++;
            
            // We have more than a name
            skipWhites( reader, pos, false );
            boolean moreExpected = false;
            
            while ( !startsWith( reader, pos, RPAREN ) )
            {
                moreExpected = false;
                
                oids.add( getOidStrict( pos ) );
                
                if ( startsWith( reader, pos, RPAREN ) )
                {
                    break;
                }
                
                skipWhites( reader, pos, false );
                
                if ( startsWith( reader, pos, DOLLAR ) )
                {
                    pos.start++;
                    moreExpected = true;
                }

                skipWhites( reader, pos, false );
            }
            
            if ( !startsWith( reader, pos, RPAREN ) )
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
            oids.add( getOidStrict( pos ) );
        }
        
        return oids;
    }

    
    /**
     * <pre>
     * oids     ::= oid | ( LPAREN WSP oidlist WSP RPAREN )
     * oidlist  ::= oid *( WSP DOLLAR WSP oid )
     * </pre>
     */
    private static List<String> getOidsRelaxed( Reader reader, PosSchema pos ) throws LdapSchemaException, IOException
    {
        List<String> oids = new ArrayList<>();
        
        // It may start with a '('
        if ( startsWith( reader, pos, LPAREN ) )
        {
            pos.start++;
            
            // We have more than a name
            skipWhites( reader, pos, false );
            boolean moreExpected = false;
            
            while ( !startsWith( reader, pos, RPAREN ) )
            {
                moreExpected = false;
                
                oids.add( getOidRelaxed( pos, UN_QUOTED ) );
                
                if ( startsWith( reader, pos, RPAREN ) )
                {
                    break;
                }
                
                skipWhites( reader, pos, false );
                
                if ( startsWith( reader, pos, DOLLAR ) )
                {
                    pos.start++;
                    moreExpected = true;
                }

                skipWhites( reader, pos, false );
            }
            
            if ( !startsWith( reader, pos, RPAREN ) )
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
            oids.add( getOidRelaxed( pos, UN_QUOTED ) );
        }
        
        return oids;
    }

    
    /**
     * noidlen = oidStrict [ LCURLY len RCURLY ]
     */
    private static void getNoidLenStrict( MutableAttributeType attributeType, PosSchema pos ) throws LdapSchemaException
    {
        // Get the oid
        String oid = getOidStrict( pos );
        
        if ( oid.length() == 0 )
        {
            throw new LdapSchemaException( I18n.err( I18n.ERR_13828_MISSING_SYNTAX_OID, pos.line, pos.start ) );
        }
        
        attributeType.setSyntaxOid( oid );

        // Then the len, if any
        if ( startsWith( pos, LBRACE ) )
        {
            pos.start++;
            int start = pos.start;
            
            while ( !isEmpty( pos ) && isDigit( pos ) )
            {
                pos.start++;
            }
            
            if ( startsWith( pos, RBRACE ) )
            {
                String lenStr = pos.line.substring( start, pos.start );
                
                if ( lenStr.length() == 0 )
                {
                    throw new LdapSchemaException( I18n.err( I18n.ERR_13827_EMPTY_SYNTAX_LEN, pos.line, pos.start ) );
                }
                
                pos.start++;
                
                if ( Strings.isEmpty( lenStr ) )
                {
                    attributeType.setSyntaxLength( -1L );
                }
                else
                {
                    attributeType.setSyntaxLength( Long.parseLong( lenStr ) );
                }
            }
            else
            {
                // The opening curly hasn't been closed
                throw new LdapSchemaException( I18n.err( I18n.ERR_13795_OPENED_BRACKET_NOT_CLOSED, 
                    pos.lineNumber, pos.start ) );
            }
        }
    }

    
    /**
     * noidlen = oidRelaxed [ LCURLY len RCURLY ]
     */
    private static void getNoidLenRelaxed( MutableAttributeType attributeType, PosSchema pos ) throws LdapSchemaException
    {
        // Check for quotes
        boolean hasQuote = false;

        char c = pos.line.charAt( pos.start );
        
        if ( c == SQUOTE )
        {
            hasQuote = true;
            pos.start++;

            if ( isEmpty( pos ) )
            {
                throw new LdapSchemaException( I18n.err( I18n.ERR_13792_SIMPLE_QUOTE_EXPECTED_AT_END, 
                    pos.lineNumber, pos.start ) );
            }
        }

        // Get the oid
        String oid = getOidRelaxed( pos, hasQuote );
        
        if ( oid.length() == 0 )
        {
            throw new LdapSchemaException( I18n.err( I18n.ERR_13828_MISSING_SYNTAX_OID, pos.line, pos.start ) );
        }
        
        attributeType.setSyntaxOid( oid );

        // Then the len, if any
        if ( startsWith( pos, LBRACE ) )
        {
            pos.start++;
            int start = pos.start;
            
            while ( !isEmpty( pos ) && isDigit( pos ) )
            {
                pos.start++;
            }
            
            if ( startsWith( pos, RBRACE ) )
            {
                String lenStr = pos.line.substring( start, pos.start );
                
                pos.start++;
                
                if ( Strings.isEmpty( lenStr ) )
                {
                    attributeType.setSyntaxLength( -1L );
                }
                else
                {
                    attributeType.setSyntaxLength( Long.parseLong( lenStr ) );
                }
            }
            else
            {
                // The opening curly hasn't been closed
                throw new LdapSchemaException( I18n.err( I18n.ERR_13795_OPENED_BRACKET_NOT_CLOSED, 
                    pos.lineNumber, pos.start ) );
            }
        }
        
        if ( hasQuote )
        {
            if ( isEmpty( pos ) )
            {
                throw new LdapSchemaException( I18n.err( I18n.ERR_13792_SIMPLE_QUOTE_EXPECTED_AT_END, 
                    pos.lineNumber, pos.start ) );
            }
            
            c = pos.line.charAt( pos.start );
            
            if ( c == SQUOTE )
            {
               pos.start++;
           }
           else
           {
               throw new LdapSchemaException( I18n.err( I18n.ERR_13792_SIMPLE_QUOTE_EXPECTED_AT_END, 
                   pos.lineNumber, pos.start ) );
           }
        }
    }
    

    
    /**
     * <pre>
     * ruleid ::= number
     * number ::= DIGIT | LDIGIT DIGIT+
     * DIGIT  ::= [0-9]
     * LDIGIT ::= [1-9]
     */
    private static int getRuleId( PosSchema pos ) throws LdapSchemaException
    {
        int start = pos.start;

        while ( !isEmpty( pos ) && isDigit( pos ) )
        {
            pos.start++;
        }
        
        if ( start == pos.start )
        {
            // No ruleID
            throw new LdapSchemaException( I18n.err( I18n.ERR_13811_INVALID_RULE_ID, 
                pos.lineNumber, pos.start ) );
        }

        String lenStr = pos.line.substring( start, pos.start );
        
        return Integer.parseInt( lenStr );
    }

    
    /**
     * <pre>
     * ruleids      ::= ruleid | ( LPAREN WSP ruleidlist WSP RPAREN )
     * ruleidlist   ::= ruleid ( SP ruleid )*
     * </pre>
     */
    private static List<Integer> getRuleIds( Reader reader, PosSchema pos ) throws LdapSchemaException, IOException
    {
        List<Integer> ruleIds = new ArrayList<>();
        
        // It may start with a '('
        if ( startsWith( reader, pos, LPAREN ) )
        {
            pos.start++;
            
            // We may have more than a ruleid
            skipWhites( reader, pos, false );
            boolean moreExpected = false;
            
            while ( !startsWith( reader, pos, RPAREN ) )
            {
                moreExpected = false;
                
                ruleIds.add( getRuleId( pos ) );
                
                if ( startsWith( reader, pos, RPAREN ) )
                {
                    break;
                }
                
                skipWhites( reader, pos, false );
                
                if ( startsWith( reader, pos, DOLLAR ) )
                {
                    pos.start++;
                    moreExpected = true;
                }

                skipWhites( reader, pos, false );
            }
            
            if ( !startsWith( reader, pos, RPAREN ) )
            {
                throw new LdapSchemaException( I18n.err( I18n.ERR_13793_NO_CLOSING_PAREN, 
                    pos.lineNumber, pos.start ) );
            }
            
            if ( moreExpected )
            {
                throw new LdapSchemaException( I18n.err( I18n.ERR_13813_MORE_RULE_IDS_EXPECTED, 
                    pos.lineNumber, pos.start ) );
            }
            
            pos.start++;
        }
        else
        {
            // Only one ruleId, read it
            ruleIds.add( getRuleId( pos ) );
        }
        
        return ruleIds;
    }
    
    
    private static UsageEnum getUsageStrict( PosSchema pos ) throws LdapSchemaException
    {
        if ( isEmpty( pos ) )
        {
            throw new LdapSchemaException( I18n.err( I18n.ERR_13796_USAGE_EXPECTED, 
                pos.lineNumber, pos.start ) );
        }
        
        if ( startsWith( pos, USER_APPLICATIONS_STR ) )
        { 
            pos.start += USER_APPLICATIONS_STR.length();
            
            return UsageEnum.USER_APPLICATIONS;
        }
        else if ( startsWith( pos, DIRECTORY_OPERATION_STR ) )
        {
            pos.start += DIRECTORY_OPERATION_STR.length();
            
            return UsageEnum.DIRECTORY_OPERATION;
        }
        else if ( startsWith( pos, DISTRIBUTED_OPERATION_STR ) )
        { 
            pos.start += DISTRIBUTED_OPERATION_STR.length();
            
            return UsageEnum.DISTRIBUTED_OPERATION;
        }
        else if ( startsWith( pos, DSA_OPERATION_STR ) )
        { 
            pos.start += DSA_OPERATION_STR.length();

            return UsageEnum.DSA_OPERATION;
        }
        else
        {
            throw new LdapSchemaException( I18n.err( I18n.ERR_13797_USAGE_UNKNOWN, 
                pos.lineNumber, pos.start ) );
        }
    }
    
    
    private static UsageEnum getUsageRelaxed( PosSchema pos ) throws LdapSchemaException
    {
        if ( isEmpty( pos ) )
        {
            throw new LdapSchemaException( I18n.err( I18n.ERR_13796_USAGE_EXPECTED, 
                pos.lineNumber, pos.start ) );
        }
        
        boolean isSQuoted = false;
        boolean isDQuoted = false;
        
        if ( pos.line.charAt( pos.start ) == SQUOTE )
        {
            isSQuoted = true;
            pos.start++;

            if ( isEmpty( pos ) )
            {
                throw new LdapSchemaException( I18n.err( I18n.ERR_13796_USAGE_EXPECTED, 
                    pos.lineNumber, pos.start ) );
            }
        }
        else if ( pos.line.charAt( pos.start ) == DQUOTE )
        {
            isDQuoted = true;
            pos.start++;

            if ( isEmpty( pos ) )
            {
                throw new LdapSchemaException( I18n.err( I18n.ERR_13796_USAGE_EXPECTED, 
                    pos.lineNumber, pos.start ) );
            }
        }

        UsageEnum usage = UsageEnum.USER_APPLICATIONS;

        if ( startsWith( pos, USER_APPLICATIONS_STR ) )
        { 
            pos.start += USER_APPLICATIONS_STR.length();
            
            usage = UsageEnum.USER_APPLICATIONS;
        }
        else if ( startsWith( pos, DIRECTORY_OPERATION_STR ) )
        {
            pos.start += DIRECTORY_OPERATION_STR.length();
            
            usage = UsageEnum.DIRECTORY_OPERATION;
        } 
        else if ( startsWith( pos, DISTRIBUTED_OPERATION_STR ) )
        { 
            pos.start += DISTRIBUTED_OPERATION_STR.length();
            
            usage = UsageEnum.DISTRIBUTED_OPERATION;
        } 
        else if ( startsWith( pos, DSA_OPERATION_STR ) )
        { 
            pos.start += DSA_OPERATION_STR.length();

            usage = UsageEnum.DSA_OPERATION;
        } 
        else
        {
            throw new LdapSchemaException( I18n.err( I18n.ERR_13797_USAGE_UNKNOWN, 
                pos.lineNumber, pos.start ) );
        }
        
        if ( isSQuoted )
        {
            if ( isEmpty( pos ) )
            {
                throw new LdapSchemaException( I18n.err( I18n.ERR_13796_USAGE_EXPECTED, 
                    pos.lineNumber, pos.start ) );
            }
            
            if ( pos.line.charAt( pos.start ) != SQUOTE )
            {
                throw new LdapSchemaException( I18n.err( I18n.ERR_13792_SIMPLE_QUOTE_EXPECTED_AT_END, 
                    pos.lineNumber, pos.start ) );
            }
            
            pos.start++;
        }
        else if ( isDQuoted )
        {
            if ( isEmpty( pos ) )
            {
                throw new LdapSchemaException( I18n.err( I18n.ERR_13796_USAGE_EXPECTED, 
                    pos.lineNumber, pos.start ) );
            }
            
            if ( pos.line.charAt( pos.start ) != DQUOTE )
            {
                throw new LdapSchemaException( I18n.err( I18n.ERR_13792_SIMPLE_QUOTE_EXPECTED_AT_END, 
                    pos.lineNumber, pos.start ) );
            }
            
            pos.start++;
        }
        
        return usage;
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
    private static void processExtension( Reader reader, PosSchema pos, SchemaObject schemaObject ) 
        throws LdapSchemaException, IOException
    {
        // The xstring first
        String extensionKey = getXString( pos );
        
        skipWhites( reader, pos, true );
        
        List<String> extensionValues = getQDStrings( reader, pos );
        
        if ( schemaObject.hasExtension( extensionKey ) )
        {
            throw new LdapSchemaException( 
                I18n.err( I18n.ERR_13780_SCHEMA_OBJECT_DESCRIPTION_HAS_ELEMENT_TWICE, extensionKey, 
                pos.lineNumber, pos.start ) );
        }

        schemaObject.addExtension( extensionKey, extensionValues );
    }
    
    
    /**
     * <pre>
     * xstring      ::= "X" HYPHEN ( ALPHA | HYPHEN | USCORE )+
     * </pre>
     */
    private static String getXString( PosSchema pos ) throws LdapSchemaException
    {
        int start = pos.start;
        
        if ( startsWith( pos, EXTENSION_PREFIX ) )
        {
            pos.start += 2;
            
            // Now parse the remaining string
            while ( !isEmpty( pos ) && ( isAlpha( pos ) || startsWith( pos, HYPHEN ) || startsWith( pos, UNDERSCORE ) ) )
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
     * A FQCN
     * <pre>
     * FQCN ::= FQCN_IDENTIFIER ( '.' FQCN_IDENTIFIER )*
     * FQCN_IDENTIFIER ::= ( JavaLetter ( JavaLetterOrDigit )*
     */
    private static String getFqcn( PosSchema pos ) throws LdapSchemaException
    {
        if ( ( pos.line == null ) || ( pos.line.length() - pos.start < 1 ) )
        {
            return "";
        }

        int start = pos.start;
        boolean isFirst = true;
        boolean dotSeen = false;
        
        while ( true )
        {
            char c = pos.line.charAt( pos.start );
            
            if ( isFirst )
            {
                if ( !Character.isJavaIdentifierStart( c ) )
                {
                    throw new LdapSchemaException( I18n.err( I18n.ERR_13822_INVALID_FQCN_BAD_IDENTIFIER_START, 
                        pos.lineNumber, pos.start ) );
                }
                
                isFirst = false;
                dotSeen = false;
                pos.start++;
            }
            else
            {
                if ( c == DOT ) 
                {
                    if ( dotSeen )
                    {
                        throw new LdapSchemaException( I18n.err( I18n.ERR_13823_INVALID_FQCN_DOUBLE_DOT, 
                            pos.lineNumber, pos.start ) );
                    }
                    else
                    {
                        isFirst = true;
                        dotSeen = true;
                        pos.start++;
                    }
                }
                else
                {
                    if ( Character.isJavaIdentifierPart( c ) )
                    {
                        pos.start++;
                        dotSeen = false;
                    }
                    else
                    {
                        return pos.line.substring( start, pos.start );
                    }
                }
            }
            
            if ( pos.line.length() - pos.start < 1 )
            {
                return pos.line.substring( start, pos.start );
            }
        }
    }

    
    /**
     * A base64 string
     * <pre>
     * byteCode ::= ( [a-z] | [A-Z] | [0-9] | '+' | '/' | '=' )*
     */
    private static String getByteCode( PosSchema pos )
    {
        if ( ( pos.line == null ) || ( pos.line.length() - pos.start < 1 ) )
        {
            return "";
        }

        int start = pos.start;
        
        
        while ( !isEmpty( pos ) && ( isAlpha( pos ) || isDigit( pos ) || startsWith( pos, PLUS ) 
            || startsWith( pos, SLASH ) || startsWith( pos, EQUAL ) ) )
        {
            pos.start++;
            
            if ( ( pos.line == null ) || ( pos.line.length() - pos.start < 1 ) )
            {
                return pos.line.substring( start, pos.start );
            }
        }
        
        return pos.line.substring( start, pos.start );
    }
    
    
    private static int checkElement( int elementsSeen, SchemaObjectElements element, PosSchema pos ) throws LdapSchemaException
    {
        if ( ( elementsSeen & element.getValue() ) != 0 )
        {
            throw new LdapSchemaException( I18n.err( I18n.ERR_13780_SCHEMA_OBJECT_DESCRIPTION_HAS_ELEMENT_TWICE, 
                element, pos.lineNumber, pos.start ) );
        }
        
        elementsSeen |= element.getValue();
        
        return elementsSeen;
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
     * 
     * @param attributeTypeDescription The String containing the AttributeTypeDescription
     * @return An instance of AttributeType
     * @throws ParseException If the element was invalid
     */
    public AttributeType parseAttributeType( String attributeTypeDescription ) throws ParseException
    {
        if ( ( attributeTypeDescription == null ) || Strings.isEmpty( attributeTypeDescription.trim() ) )
        {
            throw new ParseException( I18n.err( I18n.ERR_13716_NULL_OR_EMPTY_STRING_SCHEMA_OBJECT ), 0 );
        }
        
        try ( Reader reader = new BufferedReader( new StringReader( attributeTypeDescription ) ) )
        {
            PosSchema pos = new PosSchema();

            if ( isQuirksModeEnabled )
            {
                return parseAttributeTypeRelaxed( reader, pos, objectIdentifierMacros );
            }
            else
            {
                return parseAttributeTypeStrict( reader, pos, objectIdentifierMacros );
            }
        }
        catch ( IOException | LdapSchemaException e )
        {
            throw new ParseException( e.getMessage(), 0 );
        }
    }

    
    /**
     * Production for matching attribute type descriptions. It is fault-tolerant
     * against element ordering. It's strict.
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
    private static AttributeType parseAttributeTypeStrict( Reader reader, PosSchema pos,
        Map<String, OpenLdapObjectIdentifierMacro> objectIdentifierMacros ) throws IOException, LdapSchemaException
    {
        // Get rid of whites, comments end empty lines
        skipWhites( reader, pos, false );
        
        // we must have a '('
        if ( pos.line.charAt( pos.start ) != LPAREN )
        {
            throw new LdapSchemaException( I18n.err( I18n.ERR_13829_NO_OPENING_PAREN, 
                pos.lineNumber, pos.start ) );
        }
        else
        {
            pos.start++;
        }
        
        // Get rid of whites, comments end empty lines
        skipWhites( reader, pos, false );
        
        // Now, the OID. 
        String oid = getOidAndMacroRelaxed( pos, objectIdentifierMacros );
        
        // Check that the OID is valid
        if ( !Oid.isOid( oid ) )
        {
            throw new LdapSchemaException( I18n.err( I18n.ERR_13787_OID_EXPECTED, pos.lineNumber, pos.start ) );
        }
        
        MutableAttributeType attributeType = new MutableAttributeType( oid );
        boolean hasSup = false;
        boolean hasSyntax = false;
        int elementsSeen = 0;
        
        while ( true )
        {
            if ( startsWith( reader, pos, RPAREN ) )
            {
                pos.start++;
                break;
            }
            
            skipWhites( reader, pos, true );

            if ( startsWith( pos, NAME_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, AttributeTypeElements.NAME, pos );
                
                pos.start += NAME_STR.length();
                
                skipWhites( reader, pos, true );

                attributeType.setNames( getQDescrs( reader, pos, STRICT ) );
            }
            else if ( startsWith( pos, DESC_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, AttributeTypeElements.DESC, pos );

                pos.start += DESC_STR.length();
                
                skipWhites( reader, pos, true );

                attributeType.setDescription( getQDString( reader, pos ) );
            }
            else if ( startsWith( pos, OBSOLETE_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, AttributeTypeElements.OBSOLETE, pos );
                
                pos.start += OBSOLETE_STR.length();
                
                attributeType.setObsolete( true );
            }
            else if ( startsWith( pos, SUP_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, AttributeTypeElements.SUP, pos );
                
                pos.start += SUP_STR.length();
                
                skipWhites( reader, pos, true );
                
                String superiorOid = getOidStrict( pos );

                attributeType.setSuperiorOid( superiorOid );
                hasSup = true;
            }
            else if ( startsWith( pos, EQUALITY_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, AttributeTypeElements.EQUALITY, pos );
                
                pos.start += EQUALITY_STR.length();
                
                skipWhites( reader, pos, true );
                
                String equalityOid = getOidStrict( pos );

                attributeType.setEqualityOid( equalityOid );
            }
            else if ( startsWith( pos, ORDERING_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, AttributeTypeElements.ORDERING, pos );
                
                pos.start += ORDERING_STR.length();
                
                skipWhites( reader, pos, true );
                
                String orderingOid = getOidStrict( pos );

                attributeType.setOrderingOid( orderingOid );
            }
            else if ( startsWith( pos, SUBSTR_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, AttributeTypeElements.SUBSTR, pos );

                pos.start += SUBSTR_STR.length();
                
                skipWhites( reader, pos, true );
                
                String substrOid = getOidStrict( pos );

                attributeType.setSubstringOid( substrOid );
            }
            else if ( startsWith( pos, SYNTAX_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, AttributeTypeElements.SYNTAX, pos );
                
                pos.start += SYNTAX_STR.length();
                
                skipWhites( reader, pos, true );
                
                getNoidLenStrict( attributeType, pos );

                hasSyntax = true;
            }
            else if ( startsWith( pos, SINGLE_VALUE_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, AttributeTypeElements.SINGLE_VALUE, pos );
                
                pos.start += SINGLE_VALUE_STR.length();
                
                attributeType.setSingleValued( true );
            }
            else if ( startsWith( pos, COLLECTIVE_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, AttributeTypeElements.COLLECTIVE, pos );
                
                pos.start += COLLECTIVE_STR.length();
                
                attributeType.setCollective( true );
            }
            else if ( startsWith( pos, NO_USER_MODIFICATION_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, AttributeTypeElements.NO_USER_MODIFICATION, pos );
                
                pos.start += NO_USER_MODIFICATION_STR.length();
                
                attributeType.setUserModifiable( false );
            }
            else if ( startsWith( pos, USAGE_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, AttributeTypeElements.USAGE, pos );
                
                pos.start += USAGE_STR.length();
                
                skipWhites( reader, pos, true );
                
                UsageEnum usage = getUsageStrict( pos );

                attributeType.setUsage( usage );
            }
            else if ( startsWith( pos, EXTENSION_PREFIX ) )
            {
                processExtension( reader, pos, attributeType );
            }
            else if ( startsWith( reader, pos, RPAREN ) )
            {
                pos.start++;
                break;
            }
            else
            {
                // This is an error
                throw new LdapSchemaException( I18n.err( I18n.ERR_13798_AT_DESCRIPTION_INVALID, 
                    pos.lineNumber, pos.start ) );
            }
        }
        
        // Semantic checks
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
        
        return attributeType;
    }
    
    
    /**
     * Production for matching attribute type descriptions. It is fault-tolerant
     * against element ordering. It's relaxed.
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
    private static AttributeType parseAttributeTypeRelaxed( Reader reader, PosSchema pos,
        Map<String, OpenLdapObjectIdentifierMacro> objectIdentifierMacros ) throws IOException, LdapSchemaException
    {
        // Get rid of whites, comments end empty lines
        skipWhites( reader, pos, false );
        
        // we must have a '('
        if ( pos.line.charAt( pos.start ) != LPAREN )
        {
            throw new LdapSchemaException( I18n.err( I18n.ERR_13829_NO_OPENING_PAREN, 
                pos.lineNumber, pos.start ) );
        }
        else
        {
            pos.start++;
        }
        
        // Get rid of whites, comments end empty lines
        skipWhites( reader, pos, false );
        
        // Now, the OID. 
        String oid = getOidAndMacroRelaxed( pos, objectIdentifierMacros );
        
        MutableAttributeType attributeType = new MutableAttributeType( oid );
        int elementsSeen = 0;
        
        while ( true )
        {
            if ( startsWith( reader, pos, RPAREN ) )
            {
                pos.start++;
                break;
            }
            
            skipWhites( reader, pos, true );

            if ( startsWith( pos, NAME_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, AttributeTypeElements.NAME, pos );
                
                pos.start += NAME_STR.length();
                
                skipWhites( reader, pos, true );

                attributeType.setNames( getQDescrs( reader, pos, RELAXED ) );
            }
            else if ( startsWith( pos, DESC_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, AttributeTypeElements.DESC, pos );

                pos.start += DESC_STR.length();
                
                skipWhites( reader, pos, true );

                attributeType.setDescription( getQDString( reader, pos ) );
            }
            else if ( startsWith( pos, OBSOLETE_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, AttributeTypeElements.OBSOLETE, pos );
                
                pos.start += OBSOLETE_STR.length();
                
                attributeType.setObsolete( true );
            }
            else if ( startsWith( pos, SUP_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, AttributeTypeElements.SUP, pos );
                
                pos.start += SUP_STR.length();
                
                skipWhites( reader, pos, true );
                
                String superiorOid = getOidRelaxed( pos, false );

                attributeType.setSuperiorOid( superiorOid );
            }
            else if ( startsWith( pos, EQUALITY_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, AttributeTypeElements.EQUALITY, pos );
                
                pos.start += EQUALITY_STR.length();
                
                skipWhites( reader, pos, true );
                
                String equalityOid = getOidRelaxed( pos, false );

                attributeType.setEqualityOid( equalityOid );
            }
            else if ( startsWith( pos, ORDERING_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, AttributeTypeElements.ORDERING, pos );
                
                pos.start += ORDERING_STR.length();
                
                skipWhites( reader, pos, true );
                
                String orderingOid = getOidRelaxed( pos, false );

                attributeType.setOrderingOid( orderingOid );
            }
            else if ( startsWith( pos, SUBSTR_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, AttributeTypeElements.SUBSTR, pos );

                pos.start += SUBSTR_STR.length();
                
                skipWhites( reader, pos, true );
                
                String substrOid = getOidRelaxed( pos, false );

                attributeType.setSubstringOid( substrOid );
            }
            else if ( startsWith( pos, SYNTAX_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, AttributeTypeElements.SYNTAX, pos );
                
                pos.start += SYNTAX_STR.length();
                
                skipWhites( reader, pos, true );
                
                getNoidLenRelaxed( attributeType, pos );
            }
            else if ( startsWith( pos, SINGLE_VALUE_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, AttributeTypeElements.SINGLE_VALUE, pos );
                
                pos.start += SINGLE_VALUE_STR.length();
                
                attributeType.setSingleValued( true );
            }
            else if ( startsWith( pos, COLLECTIVE_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, AttributeTypeElements.COLLECTIVE, pos );
                
                pos.start += COLLECTIVE_STR.length();
                
                attributeType.setCollective( true );
            }
            else if ( startsWith( pos, NO_USER_MODIFICATION_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, AttributeTypeElements.NO_USER_MODIFICATION, pos );
                
                pos.start += NO_USER_MODIFICATION_STR.length();
                
                attributeType.setUserModifiable( false );
            }
            else if ( startsWith( pos, USAGE_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, AttributeTypeElements.USAGE, pos );
                
                pos.start += USAGE_STR.length();
                
                skipWhites( reader, pos, true );
                
                UsageEnum usage = getUsageRelaxed( pos );

                attributeType.setUsage( usage );
            }
            else if ( startsWith( pos, EXTENSION_PREFIX ) )
            {
                processExtension( reader, pos, attributeType );
            }
            else if ( startsWith( reader, pos, RPAREN ) )
            {
                pos.start++;
                break;
            }
            else
            {
                // This is an error
                throw new LdapSchemaException( I18n.err( I18n.ERR_13798_AT_DESCRIPTION_INVALID, 
                    pos.lineNumber, pos.start ) );
            }
        }
        
        return attributeType;
    }

    
    /**
     * Production for matching DitContentRule descriptions. It is fault-tolerant
     * against element ordering.
     *
     * <pre>
     * DITContentRuleDescription = LPAREN WSP
     *    numericoid                 ; object identifier
     *    [ SP "NAME" SP qdescrs ]   ; short names (descriptors)
     *    [ SP "DESC" SP qdstring ]  ; description
     *    [ SP "OBSOLETE" ]          ; not active
     *    [ SP "AUX" SP oids ]       ; auxiliary object classes
     *    [ SP "MUST" SP oids ]      ; attribute types
     *    [ SP "MAY" SP oids ]       ; attribute types
     *    [ SP "NOT" SP oids ]       ; attribute types
     *    extensions WSP RPAREN      ; extensions
     * </pre>
     * 
     * @param ditContentRuleDescription The String containing the DitContentRuleDescription
     * @return An instance of ditContentRule
     * @throws ParseException If the element was invalid
     */
    public DitContentRule parseDitContentRule( String ditContentRuleDescription ) throws ParseException
    {
        if ( ( ditContentRuleDescription == null ) || Strings.isEmpty( ditContentRuleDescription.trim() ) )
        {
            throw new ParseException( I18n.err( I18n.ERR_13716_NULL_OR_EMPTY_STRING_SCHEMA_OBJECT ), 0 );
        }
        
        try ( Reader reader = new BufferedReader( new StringReader( ditContentRuleDescription ) ) )
        {
            PosSchema pos = new PosSchema();

            if ( isQuirksModeEnabled )
            {
                return parseDitContentRuleRelaxed( reader, pos, objectIdentifierMacros );
            }
            else
            {
                return parseDitContentRuleStrict( reader, pos, objectIdentifierMacros );
            }
        }
        catch ( IOException | LdapSchemaException e )
        {
            throw new ParseException( e.getMessage(), 0 );
        }
    }

    
    /**
     * Production for DitContentRule descriptions. It is fault-tolerant
     * against element ordering.
     *
     * <pre>
     * DITContentRuleDescription = LPAREN WSP
     *    numericoid                 ; object identifier
     *    [ SP "NAME" SP qdescrs ]   ; short names (descriptors)
     *    [ SP "DESC" SP qdstring ]  ; description
     *    [ SP "OBSOLETE" ]          ; not active
     *    [ SP "AUX" SP oids ]       ; auxiliary object classes
     *    [ SP "MUST" SP oids ]      ; attribute types
     *    [ SP "MAY" SP oids ]       ; attribute types
     *    [ SP "NOT" SP oids ]       ; attribute types
     *    extensions WSP RPAREN      ; extensions
     * </pre>
     */
    private static DitContentRule parseDitContentRuleStrict( Reader reader, PosSchema pos,
        Map<String, OpenLdapObjectIdentifierMacro> objectIdentifierMacros ) throws IOException, LdapSchemaException
    {
        // Get rid of whites, comments end empty lines
        skipWhites( reader, pos, false );
        
        // we must have a '('
        if ( pos.line.charAt( pos.start ) != LPAREN )
        {
            throw new LdapSchemaException( I18n.err( I18n.ERR_13829_NO_OPENING_PAREN, 
                pos.lineNumber, pos.start ) );
        }
        else
        {
            pos.start++;
        }
        
        // Get rid of whites, comments end empty lines
        skipWhites( reader, pos, false );
        
        // Now, the OID. 
        String oid = getOidAndMacroRelaxed( pos, objectIdentifierMacros );
        
        // Check that the OID is valid
        if ( !Oid.isOid( oid ) )
        {
            throw new LdapSchemaException( I18n.err( I18n.ERR_13787_OID_EXPECTED, pos.lineNumber, pos.start ) );
        }
        
        DitContentRule ditContentRule = new DitContentRule( oid );
        int elementsSeen = 0;
        
        while ( true )
        {
            if ( startsWith( reader, pos, RPAREN ) )
            {
                pos.start++;
                break;
            }
            
            skipWhites( reader, pos, true );
            
            if ( startsWith( pos, NAME_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, DitContentRuleElements.NAME, pos );

                pos.start += NAME_STR.length();
                
                skipWhites( reader, pos, true );

                ditContentRule.setNames( getQDescrs( reader, pos, STRICT ) );
            }
            else if ( startsWith( pos, DESC_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, DitContentRuleElements.DESC, pos );

                pos.start += DESC_STR.length();
                
                skipWhites( reader, pos, true );

                ditContentRule.setDescription( getQDString( reader, pos ) );
            }
            else if ( startsWith( pos, OBSOLETE_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, DitContentRuleElements.OBSOLETE, pos );

                pos.start += OBSOLETE_STR.length();
                
                ditContentRule.setObsolete( true );
            }
            else if ( startsWith( pos, AUX_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, DitContentRuleElements.AUX, pos );

                pos.start += AUX_STR.length();
                
                skipWhites( reader, pos, true );
                
                List<String> aux = getOidsStrict( reader, pos );
                
                ditContentRule.setAuxObjectClassOids( aux );
            }
            else if ( startsWith( pos, MUST_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, DitContentRuleElements.MUST, pos );

                pos.start += MUST_STR.length();
                
                skipWhites( reader, pos, true );
                
                List<String> must = getOidsStrict( reader, pos );
                
                ditContentRule.setMustAttributeTypeOids( must );
            }
            else if ( startsWith( pos, MAY_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, DitContentRuleElements.MAY, pos );

                pos.start += MAY_STR.length();
                
                skipWhites( reader, pos, true );
                
                List<String> may = getOidsStrict( reader, pos );
                
                ditContentRule.setMayAttributeTypeOids( may );
            }
            else if ( startsWith( pos, NOT_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, DitContentRuleElements.NOT, pos );

                pos.start += NOT_STR.length();
                
                skipWhites( reader, pos, true );
                
                List<String> not = getOidsStrict( reader, pos );
                
                ditContentRule.setNotAttributeTypeOids( not );
            }
            else if ( startsWith( pos, EXTENSION_PREFIX ) )
            {
                processExtension( reader, pos, ditContentRule );
            }
            else if ( startsWith( reader, pos, RPAREN ) )
            {
                pos.start++;

                break;
            }
            else
            {
                // This is an error
                throw new LdapSchemaException( I18n.err( I18n.ERR_13809_DCR_DESCRIPTION_INVALID, 
                    pos.lineNumber, pos.start ) );
            }
        }
        
        return ditContentRule;
    }

    
    /**
     * Production for DitContentRule descriptions. It is fault-tolerant
     * against element ordering.
     *
     * <pre>
     * DITContentRuleDescription = LPAREN WSP
     *    numericoid                 ; object identifier
     *    [ SP "NAME" SP qdescrs ]   ; short names (descriptors)
     *    [ SP "DESC" SP qdstring ]  ; description
     *    [ SP "OBSOLETE" ]          ; not active
     *    [ SP "AUX" SP oids ]       ; auxiliary object classes
     *    [ SP "MUST" SP oids ]      ; attribute types
     *    [ SP "MAY" SP oids ]       ; attribute types
     *    [ SP "NOT" SP oids ]       ; attribute types
     *    extensions WSP RPAREN      ; extensions
     * </pre>
     */
    private static DitContentRule parseDitContentRuleRelaxed( Reader reader, PosSchema pos,
        Map<String, OpenLdapObjectIdentifierMacro> objectIdentifierMacros ) throws IOException, LdapSchemaException
    {
        // Get rid of whites, comments end empty lines
        skipWhites( reader, pos, false );
        
        // we must have a '('
        if ( pos.line.charAt( pos.start ) != LPAREN )
        {
            throw new LdapSchemaException( I18n.err( I18n.ERR_13829_NO_OPENING_PAREN, 
                pos.lineNumber, pos.start ) );
        }
        else
        {
            pos.start++;
        }
        
        // Get rid of whites, comments end empty lines
        skipWhites( reader, pos, false );
        
        // Now, the OID. 
        String oid = getOidAndMacroRelaxed( pos, objectIdentifierMacros );
        // Now, the OID. 
        
        DitContentRule ditContentRule = new DitContentRule( oid );
        int elementsSeen = 0;
        
        while ( true )
        {
            if ( startsWith( reader, pos, RPAREN ) )
            {
                pos.start++;
                break;
            }
            
            skipWhites( reader, pos, true );

            if ( startsWith( pos, NAME_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, DitContentRuleElements.NAME, pos );

                pos.start += NAME_STR.length();
                
                skipWhites( reader, pos, true );

                ditContentRule.setNames( getQDescrs( reader, pos, RELAXED ) );
            }
            else if ( startsWith( pos, DESC_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, DitContentRuleElements.DESC, pos );

                pos.start += DESC_STR.length();
                
                skipWhites( reader, pos, true );

                ditContentRule.setDescription( getQDString( reader, pos ) );
            }
            else if ( startsWith( pos, OBSOLETE_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, DitContentRuleElements.OBSOLETE, pos );

                pos.start += OBSOLETE_STR.length();
                
                ditContentRule.setObsolete( true );
            }
            else if ( startsWith( pos, AUX_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, DitContentRuleElements.AUX, pos );

                pos.start += AUX_STR.length();
                
                skipWhites( reader, pos, true );
                
                List<String> aux = getOidsRelaxed( reader, pos );
                
                ditContentRule.setAuxObjectClassOids( aux );
            }
            else if ( startsWith( pos, MUST_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, DitContentRuleElements.MUST, pos );

                pos.start += MUST_STR.length();
                
                skipWhites( reader, pos, true );
                
                List<String> must = getOidsRelaxed( reader, pos );
                
                ditContentRule.setMustAttributeTypeOids( must );
            }
            else if ( startsWith( pos, MAY_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, DitContentRuleElements.MAY, pos );

                pos.start += MAY_STR.length();
                
                skipWhites( reader, pos, true );
                
                List<String> may = getOidsRelaxed( reader, pos );
                
                ditContentRule.setMayAttributeTypeOids( may );
            }
            else if ( startsWith( pos, NOT_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, DitContentRuleElements.NOT, pos );

                pos.start += NOT_STR.length();
                
                skipWhites( reader, pos, true );
                
                List<String> not = getOidsRelaxed( reader, pos );
                
                ditContentRule.setNotAttributeTypeOids( not );
            }
            else if ( startsWith( pos, EXTENSION_PREFIX ) )
            {
                processExtension( reader, pos, ditContentRule );
            }
            else if ( startsWith( reader, pos, RPAREN ) )
            {
                pos.start++;

                break;
            }
            else
            {
                // This is an error
                throw new LdapSchemaException( I18n.err( I18n.ERR_13809_DCR_DESCRIPTION_INVALID, 
                    pos.lineNumber, pos.start ) );
            }
        }
        
        return ditContentRule;
    }

    
    /**
     * Production for matching DitStructureRule descriptions. It is fault-tolerant
     * against element ordering.
     *
     * <pre>
     * DITStructureRuleDescription = LPAREN WSP
     *   ruleid                     ; rule identifier
     *   [ SP "NAME" SP qdescrs ]   ; short names (descriptors)
     *   [ SP "DESC" SP qdstring ]  ; description
     *   [ SP "OBSOLETE" ]          ; not active
     *   SP "FORM" SP oid           ; NameForm
     *   [ SP "SUP" ruleids ]       ; superior rules
     *   extensions WSP RPAREN      ; extensions
     *
     * ruleids = ruleid / ( LPAREN WSP ruleidlist WSP RPAREN )
     * ruleidlist = ruleid *( SP ruleid )
     * ruleid = number
     * </pre>
     * 
     * @param ditStructureRuleDescription The String containing the DitStructureRuleDescription
     * @return An instance of DitStructureRule
     * @throws ParseException If the element was invalid
     */
    public DitStructureRule parseDitStructureRule( String ditStructureRuleDescription ) throws ParseException
    {
        if ( ( ditStructureRuleDescription == null ) || Strings.isEmpty( ditStructureRuleDescription.trim() ) )
        {
            throw new ParseException( I18n.err( I18n.ERR_13716_NULL_OR_EMPTY_STRING_SCHEMA_OBJECT ), 0 );
        }
        
        try ( Reader reader = new BufferedReader( new StringReader( ditStructureRuleDescription ) ) )
        {
            PosSchema pos = new PosSchema();

            if ( isQuirksModeEnabled )
            {
                return parseDitStructureRuleRelaxed( reader, pos, objectIdentifierMacros );
            }
            else
            {
                return parseDitStructureRuleStrict( reader, pos );
            }
        }
        catch ( IOException | LdapSchemaException e )
        {
            throw new ParseException( e.getMessage(), 0 );
        }
    }

    
    /**
     * Production for DitStructureRule descriptions. It is fault-tolerant
     * against element ordering.
     *
     * <pre>
     * DITStructureRuleDescription = LPAREN WSP
     *   ruleid                     ; rule identifier
     *   [ SP "NAME" SP qdescrs ]   ; short names (descriptors)
     *   [ SP "DESC" SP qdstring ]  ; description
     *   [ SP "OBSOLETE" ]          ; not active
     *   SP "FORM" SP oid           ; NameForm
     *   [ SP "SUP" ruleids ]       ; superior rules
     *   extensions WSP RPAREN      ; extensions
     *
     * ruleids = ruleid / ( LPAREN WSP ruleidlist WSP RPAREN )
     * ruleidlist = ruleid *( SP ruleid )
     * ruleid = number
     * </pre>
     */
    private static DitStructureRule parseDitStructureRuleStrict( Reader reader, PosSchema pos ) 
        throws IOException, LdapSchemaException
    {
        // Get rid of whites, comments end empty lines
        skipWhites( reader, pos, false );
        
        // we must have a '('
        if ( pos.line.charAt( pos.start ) != LPAREN )
        {
            throw new LdapSchemaException( I18n.err( I18n.ERR_13829_NO_OPENING_PAREN, 
                pos.lineNumber, pos.start ) );
        }
        else
        {
            pos.start++;
        }
        
        // Get rid of whites, comments end empty lines
        skipWhites( reader, pos, false );
        
        // Now, the ruleID. 
        int ruleId = getRuleId( pos );
        
        DitStructureRule ditStructureRule = new DitStructureRule( ruleId );
        int elementsSeen = 0;
        boolean hasForm = false;
        
        while ( true )
        {
            if ( startsWith( reader, pos, RPAREN ) )
            {
                pos.start++;
                break;
            }
            
            skipWhites( reader, pos, true );
            
            if ( startsWith( pos, NAME_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, DitStructureRuleElements.NAME, pos );

                pos.start += NAME_STR.length();
                
                skipWhites( reader, pos, true );

                ditStructureRule.setNames( getQDescrs( reader, pos, STRICT ) );
            }
            else if ( startsWith( pos, DESC_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, DitStructureRuleElements.DESC, pos );

                pos.start += DESC_STR.length();
                
                skipWhites( reader, pos, true );

                ditStructureRule.setDescription( getQDString( reader, pos ) );
            }
            else if ( startsWith( pos, OBSOLETE_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, DitStructureRuleElements.OBSOLETE, pos );

                pos.start += OBSOLETE_STR.length();
                
                ditStructureRule.setObsolete( true );
            }
            else if ( startsWith( pos, FORM_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, DitStructureRuleElements.FORM, pos );

                pos.start += FORM_STR.length();
                
                skipWhites( reader, pos, true );
                
                String form = getOidStrict( pos );
                
                ditStructureRule.setForm( form );
                hasForm = true;
            }
            else if ( startsWith( pos, SUP_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, DitStructureRuleElements.SUP, pos );

                pos.start += SUP_STR.length();
                
                skipWhites( reader, pos, true );
                
                List<Integer> superRules = getRuleIds( reader, pos );
                
                ditStructureRule.setSuperRules( superRules );
            }
            else if ( startsWith( pos, EXTENSION_PREFIX ) )
            {
                processExtension( reader, pos, ditStructureRule );
            }
            else if ( startsWith( reader, pos, RPAREN ) )
            {
                pos.start++;
                break;
            }
            else
            {
                // This is an error
                throw new LdapSchemaException( I18n.err( I18n.ERR_13809_DCR_DESCRIPTION_INVALID, 
                    pos.lineNumber, pos.start ) );
            }
        }
        
        // Semantic checks
        if ( !hasForm )
        {
            throw new LdapSchemaException( I18n.err( I18n.ERR_13812_FORM_REQUIRED, 
                pos.lineNumber, pos.start ) );
        }

        return ditStructureRule;
    }

    
    /**
     * Production for DitStructureRule descriptions. It is fault-tolerant
     * against element ordering.
     *
     * <pre>
     * DITStructureRuleDescription = LPAREN WSP
     *   ruleid                     ; rule identifier
     *   [ SP "NAME" SP qdescrs ]   ; short names (descriptors)
     *   [ SP "DESC" SP qdstring ]  ; description
     *   [ SP "OBSOLETE" ]          ; not active
     *   SP "FORM" SP oid           ; NameForm
     *   [ SP "SUP" ruleids ]       ; superior rules
     *   extensions WSP RPAREN      ; extensions
     *
     * ruleids = ruleid / ( LPAREN WSP ruleidlist WSP RPAREN )
     * ruleidlist = ruleid *( SP ruleid )
     * ruleid = number
     * </pre>
     */
    private static DitStructureRule parseDitStructureRuleRelaxed( Reader reader, PosSchema pos,
        Map<String, OpenLdapObjectIdentifierMacro> objectIdentifierMacros ) 
            throws IOException, LdapSchemaException
    {
        // Get rid of whites, comments end empty lines
        skipWhites( reader, pos, false );
        
        // we must have a '('
        if ( pos.line.charAt( pos.start ) != LPAREN )
        {
            throw new LdapSchemaException( I18n.err( I18n.ERR_13829_NO_OPENING_PAREN, 
                pos.lineNumber, pos.start ) );
        }
        else
        {
            pos.start++;
        }
        
        // Get rid of whites, comments end empty lines
        skipWhites( reader, pos, false );
        
        // Now, the ruleID. 
        int ruleId = getRuleId( pos );
        
        DitStructureRule ditStructureRule = new DitStructureRule( ruleId );
        int elementsSeen = 0;
        boolean hasForm = false;
        
        while ( true )
        {
            if ( startsWith( reader, pos, RPAREN ) )
            {
                pos.start++;
                break;
            }
            
            skipWhites( reader, pos, true );
            
            if ( startsWith( pos, NAME_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, DitStructureRuleElements.NAME, pos );

                pos.start += NAME_STR.length();
                
                skipWhites( reader, pos, true );

                ditStructureRule.setNames( getQDescrs( reader, pos, RELAXED ) );
            }
            else if ( startsWith( pos, DESC_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, DitStructureRuleElements.DESC, pos );

                pos.start += DESC_STR.length();
                
                skipWhites( reader, pos, true );

                ditStructureRule.setDescription( getQDString( reader, pos ) );
            }
            else if ( startsWith( pos, OBSOLETE_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, DitStructureRuleElements.OBSOLETE, pos );

                pos.start += OBSOLETE_STR.length();
                
                ditStructureRule.setObsolete( true );
            }
            else if ( startsWith( pos, FORM_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, DitStructureRuleElements.FORM, pos );

                pos.start += FORM_STR.length();
                
                skipWhites( reader, pos, true );
                
                String form = getOidRelaxed( pos, UN_QUOTED );
                
                ditStructureRule.setForm( form );
                hasForm = true;
            }
            else if ( startsWith( pos, SUP_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, DitStructureRuleElements.SUP, pos );

                pos.start += SUP_STR.length();
                
                skipWhites( reader, pos, true );
                
                List<Integer> superRules = getRuleIds( reader, pos );
                
                ditStructureRule.setSuperRules( superRules );
            }
            else if ( startsWith( pos, EXTENSION_PREFIX ) )
            {
                processExtension( reader, pos, ditStructureRule );
            }
            else if ( startsWith( reader, pos, RPAREN ) )
            {
                pos.start++;
                break;
            }
            else
            {
                // This is an error
                throw new LdapSchemaException( I18n.err( I18n.ERR_13809_DCR_DESCRIPTION_INVALID, 
                    pos.lineNumber, pos.start ) );
            }
        }

        if ( !hasForm )
        {
            throw new LdapSchemaException( I18n.err( I18n.ERR_13812_FORM_REQUIRED, 
                pos.lineNumber, pos.start ) );
        }

        return ditStructureRule;
    }

    
    /**
     * Production for LdapComparator descriptions. It is fault-tolerant
     * against element ordering.
     *
     * <pre>
     * LdapComparatorDescription = LPAREN WSP
     *       numericoid                           ; object identifier
     *       [ SP "DESC" SP qdstring ]            ; description
     *       SP "FQCN" SP fqcn                    ; fully qualified class name
     *       [ SP "BYTECODE" SP base64 ]          ; optional base64 encoded bytecode
     *       extensions WSP RPAREN                ; extensions
     * 
     * base64          = *(4base64-char)
     * base64-char     = ALPHA / DIGIT / "+" / "/"
     * fqcn = fqcnComponent 1*( DOT fqcnComponent )
     * fqcnComponent = ???
     * </pre>
     * 
     * @param ldapComparatorDescription The String containing the LdapComparatorDescription
     * @return An instance of LdapComparatorDescription
     * @throws ParseException If the element was invalid
     */
    public LdapComparatorDescription parseLdapComparator( String ldapComparatorDescription ) throws ParseException
    {
        if ( ( ldapComparatorDescription == null ) || Strings.isEmpty( ldapComparatorDescription.trim() ) )
        {
            throw new ParseException( I18n.err( I18n.ERR_13716_NULL_OR_EMPTY_STRING_SCHEMA_OBJECT ), 0 );
        }
        
        try ( Reader reader = new BufferedReader( new StringReader( ldapComparatorDescription ) ) )
        {
            PosSchema pos = new PosSchema();

            if ( isQuirksModeEnabled )
            {
                return parseLdapComparatorRelaxed( reader, pos, objectIdentifierMacros );
            }
            else
            {
                return parseLdapComparatorStrict( reader, pos, objectIdentifierMacros );
            }
        }
        catch ( IOException | LdapSchemaException e )
        {
            throw new ParseException( e.getMessage(), 0 );
        }
    }

    
    /**
     * Production for LdapComparator descriptions. It is fault-tolerant
     * against element ordering.
     *
     * <pre>
     * LdapComparatorDescription = LPAREN WSP
     *       numericoid                           ; object identifier
     *       [ SP "DESC" SP qdstring ]            ; description
     *       SP "FQCN" SP fqcn                    ; fully qualified class name
     *       [ SP "BYTECODE" SP base64 ]          ; optional base64 encoded bytecode
     *       extensions WSP RPAREN                ; extensions
     * 
     * base64          = *(4base64-char)
     * base64-char     = ALPHA / DIGIT / "+" / "/"
     * fqcn = fqcnComponent 1*( DOT fqcnComponent )
     * fqcnComponent = ???
     * </pre>
     */
    private static LdapComparatorDescription parseLdapComparatorStrict( Reader reader, PosSchema pos,
        Map<String, OpenLdapObjectIdentifierMacro> objectIdentifierMacros ) throws IOException, LdapSchemaException
    {
        // Get rid of whites, comments end empty lines
        skipWhites( reader, pos, false );
        
        // we must have a '('
        if ( pos.line.charAt( pos.start ) != LPAREN )
        {
            throw new LdapSchemaException( I18n.err( I18n.ERR_13829_NO_OPENING_PAREN, 
                pos.lineNumber, pos.start ) );
        }
        else
        {
            pos.start++;
        }
        
        // Get rid of whites, comments end empty lines
        skipWhites( reader, pos, false );
        
        // Now, the OID. 
        String oid = getOidAndMacroRelaxed( pos, objectIdentifierMacros );
        
        // Check that the OID is valid
        if ( !Oid.isOid( oid ) )
        {
            throw new LdapSchemaException( I18n.err( I18n.ERR_13787_OID_EXPECTED, pos.lineNumber, pos.start ) );
        }
        
        LdapComparatorDescription ldapComparator = new LdapComparatorDescription( oid );
        int elementsSeen = 0;
        boolean hasFqcn = false;
        boolean hasByteCode = false;
        
        while ( true )
        {
            if ( startsWith( reader, pos, RPAREN ) )
            {
                pos.start++;
                break;
            }
            
            skipWhites( reader, pos, true );
            
            if ( startsWith( pos, DESC_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, LdapComparatorElements.DESC, pos );

                pos.start += DESC_STR.length();
                
                skipWhites( reader, pos, true );

                ldapComparator.setDescription( getQDString( reader, pos ) );
            }
            else if ( startsWith( pos, FQCN_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, LdapComparatorElements.FQCN, pos );

                pos.start += FQCN_STR.length();
                
                skipWhites( reader, pos, true );

                String fqcn = getFqcn( pos );
                ldapComparator.setFqcn( fqcn );
                hasFqcn = true;
            }
            else if ( startsWith( pos, BYTECODE_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, LdapComparatorElements.BYTECODE, pos );

                pos.start += BYTECODE_STR.length();
                
                skipWhites( reader, pos, true );
                
                String byteCode = getByteCode( pos );
                ldapComparator.setBytecode( byteCode );
                hasByteCode = true;
            }
            else if ( startsWith( pos, EXTENSION_PREFIX ) )
            {
                processExtension( reader, pos, ldapComparator );
            }
            else if ( startsWith( reader, pos, RPAREN ) )
            {
                pos.start++;
                break;
            }
            else
            {
                // This is an error
                throw new LdapSchemaException( I18n.err( I18n.ERR_13825_COMP_DESCRIPTION_INVALID, 
                    pos.lineNumber, pos.start ) );
            }
        }
        
        // Semantic checks
        if ( !hasFqcn )
        {
            throw new LdapSchemaException( I18n.err( I18n.ERR_13819_FQCN_REQUIRED, 
                pos.lineNumber, pos.start ) );
        }

        if ( ( hasByteCode ) && ( ldapComparator.getBytecode().length() % 4 != 0 ) )
        {
            throw new LdapSchemaException( I18n.err( I18n.ERR_13820_BYTE_CODE_REQUIRED, 
                pos.lineNumber, pos.start ) );
        }

        return ldapComparator;
    }

    
    /**
     * Production for LdapComparator descriptions. It is fault-tolerant
     * against element ordering.
     *
     * <pre>
     * LdapComparatorDescription = LPAREN WSP
     *       numericoid                           ; object identifier
     *       [ SP "DESC" SP qdstring ]            ; description
     *       SP "FQCN" SP fqcn                    ; fully qualified class name
     *       [ SP "BYTECODE" SP base64 ]          ; optional base64 encoded bytecode
     *       extensions WSP RPAREN                ; extensions
     * 
     * base64          = *(4base64-char)
     * base64-char     = ALPHA / DIGIT / "+" / "/"
     * fqcn = fqcnComponent 1*( DOT fqcnComponent )
     * fqcnComponent = ???
     * </pre>
     */
    private static LdapComparatorDescription parseLdapComparatorRelaxed( Reader reader, PosSchema pos,
        Map<String, OpenLdapObjectIdentifierMacro> objectIdentifierMacros ) 
            throws IOException, LdapSchemaException
    {
        // Get rid of whites, comments end empty lines
        skipWhites( reader, pos, false );
        
        // we must have a '('
        if ( pos.line.charAt( pos.start ) != LPAREN )
        {
            throw new LdapSchemaException( I18n.err( I18n.ERR_13829_NO_OPENING_PAREN, 
                pos.lineNumber, pos.start ) );
        }
        else
        {
            pos.start++;
        }
        
        // Get rid of whites, comments end empty lines
        skipWhites( reader, pos, false );
        
        // Now, the OID. 
        String oid = getOidAndMacroRelaxed( pos, objectIdentifierMacros );
        
        LdapComparatorDescription ldapComparator = new LdapComparatorDescription( oid );
        int elementsSeen = 0;
        
        while ( true )
        {
            if ( startsWith( reader, pos, RPAREN ) )
            {
                pos.start++;
                break;
            }
            
            skipWhites( reader, pos, true );
            
            if ( startsWith( pos, DESC_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, LdapComparatorElements.DESC, pos );

                pos.start += DESC_STR.length();
                
                skipWhites( reader, pos, true );

                ldapComparator.setDescription( getQDString( reader, pos ) );
            }
            else if ( startsWith( pos, FQCN_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, LdapComparatorElements.FQCN, pos );

                pos.start += FQCN_STR.length();
                
                skipWhites( reader, pos, true );

                String fqcn = getFqcn( pos );
                ldapComparator.setFqcn( fqcn );
            }
            else if ( startsWith( pos, BYTECODE_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, LdapComparatorElements.BYTECODE, pos );

                pos.start += BYTECODE_STR.length();
                
                skipWhites( reader, pos, true );
                
                String byteCode = getByteCode( pos );
                ldapComparator.setBytecode( byteCode );
            }
            else if ( startsWith( pos, EXTENSION_PREFIX ) )
            {
                processExtension( reader, pos, ldapComparator );
            }
            else if ( startsWith( reader, pos, RPAREN ) )
            {
                pos.start++;
                break;
            }
            else
            {
                // This is an error
                throw new LdapSchemaException( I18n.err( I18n.ERR_13825_COMP_DESCRIPTION_INVALID, 
                    pos.lineNumber, pos.start ) );
            }
        }

        return ldapComparator;
    }

    
    /**
     * Production for matching ldap syntax descriptions. It is fault-tolerant
     * against element ordering.
     *
     * <pre>
     * SyntaxDescription = LPAREN WSP
     *    numericoid                 ; object identifier
     *    [ SP "DESC" SP qdstring ]  ; description
     *    extensions WSP RPAREN      ; extensions
     * </pre>
     * 
     * @param ldapSyntaxDescription The String containing the Ldap Syntax description
     * @return An instance of LdapSyntax
     * @throws ParseException If the element was invalid
     */
    public LdapSyntax parseLdapSyntax( String ldapSyntaxDescription ) throws ParseException
    {
        if ( ( ldapSyntaxDescription == null ) || Strings.isEmpty( ldapSyntaxDescription.trim() ) )
        {
            throw new ParseException( I18n.err( I18n.ERR_13716_NULL_OR_EMPTY_STRING_SCHEMA_OBJECT ), 0 );
        }
        
        try ( Reader reader = new BufferedReader( new StringReader( ldapSyntaxDescription ) ) )
        {
            PosSchema pos = new PosSchema();

            if ( isQuirksModeEnabled )
            {
                return parseLdapSyntaxRelaxed( reader, pos, objectIdentifierMacros );
            }
            else
            {
                return parseLdapSyntaxStrict( reader, pos, objectIdentifierMacros );
            }
        }
        catch ( IOException | LdapSchemaException e )
        {
            throw new ParseException( e.getMessage(), 0 );
        }
    }

    
    /**
     * Production for matching ldap syntax descriptions. It is fault-tolerant
     * against element ordering.
     *
     * <pre>
     * SyntaxDescription = LPAREN WSP
     *    numericoid                 ; object identifier
     *    [ SP "DESC" SP qdstring ]  ; description
     *    extensions WSP RPAREN      ; extensions
     * </pre>
     */
    private static LdapSyntax parseLdapSyntaxStrict( Reader reader, PosSchema pos,
        Map<String, OpenLdapObjectIdentifierMacro> objectIdentifierMacros ) throws IOException, LdapSchemaException
    {
        // Get rid of whites, comments end empty lines
        skipWhites( reader, pos, false );
        
        // we must have a '('
        if ( pos.line.charAt( pos.start ) != LPAREN )
        {
            throw new LdapSchemaException( I18n.err( I18n.ERR_13829_NO_OPENING_PAREN, 
                pos.lineNumber, pos.start ) );
        }
        else
        {
            pos.start++;
        }
        
        // Get rid of whites, comments end empty lines
        skipWhites( reader, pos, false );
        
        // Now, the OID. 
        String oid = getOidAndMacroRelaxed( pos, objectIdentifierMacros );
        
        // Check that the OID is valid
        if ( !Oid.isOid( oid ) )
        {
            throw new LdapSchemaException( I18n.err( I18n.ERR_13787_OID_EXPECTED, pos.lineNumber, pos.start ) );
        }
        
        LdapSyntax ldapSyntax = new LdapSyntax( oid );
        int elementsSeen = 0;
        
        while ( true )
        {
            if ( startsWith( reader, pos, RPAREN ) )
            {
                pos.start++;
                break;
            }
            
            skipWhites( reader, pos, true );
            
            if ( startsWith( pos, DESC_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, LdapSyntaxElements.DESC, pos );

                pos.start += DESC_STR.length();
                
                skipWhites( reader, pos, true );

                ldapSyntax.setDescription( getQDString( reader, pos ) );
            }
            else if ( startsWith( pos, EXTENSION_PREFIX ) )
            {
                processExtension( reader, pos, ldapSyntax );
            }
            else if ( startsWith( reader, pos, RPAREN ) )
            {
                pos.start++;
                break;
            }
            else
            {
                // This is an error
                throw new LdapSchemaException( I18n.err( I18n.ERR_13807_SYN_DESCRIPTION_INVALID, 
                    pos.lineNumber, pos.start ) );
            }
        }
        
        return ldapSyntax;
    }

    
    /**
     * Production for matching ldap syntax descriptions. It is fault-tolerant
     * against element ordering.
     *
     * <pre>
     * SyntaxDescription = LPAREN WSP
     *    numericoid                 ; object identifier
     *    [ SP "DESC" SP qdstring ]  ; description
     *    extensions WSP RPAREN      ; extensions
     * </pre>
     */
    private static LdapSyntax parseLdapSyntaxRelaxed( Reader reader, PosSchema pos,
        Map<String, OpenLdapObjectIdentifierMacro> objectIdentifierMacros ) throws IOException, LdapSchemaException
    {
        // Get rid of whites, comments end empty lines
        skipWhites( reader, pos, false );
        
        // we must have a '('
        if ( pos.line.charAt( pos.start ) != LPAREN )
        {
            throw new LdapSchemaException( I18n.err( I18n.ERR_13829_NO_OPENING_PAREN, 
                pos.lineNumber, pos.start ) );
        }
        else
        {
            pos.start++;
        }
        
        // Get rid of whites, comments end empty lines
        skipWhites( reader, pos, false );
        
        // Now, the OID. 
        String oid = getOidAndMacroRelaxed( pos, objectIdentifierMacros );
        
        LdapSyntax ldapSyntax = new LdapSyntax( oid );
        int elementsSeen = 0;
        
        while ( true )
        {
            if ( startsWith( reader, pos, RPAREN ) )
            {
                pos.start++;
                break;
            }
            
            skipWhites( reader, pos, true );
            
            if ( startsWith( pos, DESC_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, LdapSyntaxElements.DESC, pos );

                pos.start += DESC_STR.length();
                
                skipWhites( reader, pos, true );

                ldapSyntax.setDescription( getQDString( reader, pos ) );
            }
            else if ( startsWith( pos, EXTENSION_PREFIX ) )
            {
                processExtension( reader, pos, ldapSyntax );
            }
            else if ( startsWith( reader, pos, RPAREN ) )
            {
                pos.start++;
                break;
            }
            else
            {
                // This is an error
                throw new LdapSchemaException( I18n.err( I18n.ERR_13807_SYN_DESCRIPTION_INVALID, 
                    pos.lineNumber, pos.start ) );
            }
        }
        
        return ldapSyntax;
    }
    
    
    /**
     * Production for matching MatchingRule descriptions. It is fault-tolerant
     * against element ordering.
     *
     * <pre>
     * MatchingRuleDescription = LPAREN WSP
     *    numericoid                 ; object identifier
     *    [ SP "NAME" SP qdescrs ]   ; short names (descriptors)
     *    [ SP "DESC" SP qdstring ]  ; description
     *    [ SP "OBSOLETE" ]          ; not active
     *    SP "SYNTAX" SP numericoid  ; assertion syntax
     *    extensions WSP RPAREN      ; extensions
     * </pre>
     * 
     * @param matchingRuleDescription The String containing the MatchingRuledescription
     * @return An instance of MatchingRule
     * @throws ParseException If the element was invalid
     */
    public MatchingRule parseMatchingRule( String matchingRuleDescription ) throws ParseException
    {
        if ( ( matchingRuleDescription == null ) || Strings.isEmpty( matchingRuleDescription.trim() ) )
        {
            throw new ParseException( I18n.err( I18n.ERR_13716_NULL_OR_EMPTY_STRING_SCHEMA_OBJECT ), 0 );
        }
        
        try ( Reader reader = new BufferedReader( new StringReader( matchingRuleDescription ) ) )
        {
            PosSchema pos = new PosSchema();

            if ( isQuirksModeEnabled )
            {
                return parseMatchingRuleRelaxed( reader, pos, objectIdentifierMacros );
            }
            else
            {
                return parseMatchingRuleStrict( reader, pos, objectIdentifierMacros );
            }
        }
        catch ( IOException | LdapSchemaException e )
        {
            throw new ParseException( e.getMessage(), 0 );
        }
    }

    
    /**
     * Production for matching rule descriptions. It is fault-tolerant
     * against element ordering.
     *
     * <pre>
     * MatchingRuleDescription = LPAREN WSP
     *    numericoid                 ; object identifier
     *    [ SP "NAME" SP qdescrs ]   ; short names (descriptors)
     *    [ SP "DESC" SP qdstring ]  ; description
     *    [ SP "OBSOLETE" ]          ; not active
     *    SP "SYNTAX" SP numericoid  ; assertion syntax
     *    extensions WSP RPAREN      ; extensions
     * </pre>
     */
    private static MatchingRule parseMatchingRuleStrict( Reader reader, PosSchema pos, 
        Map<String, OpenLdapObjectIdentifierMacro> objectIdentifierMacros ) throws IOException, LdapSchemaException
    {
        // Get rid of whites, comments end empty lines
        skipWhites( reader, pos, false );
        
        // we must have a '('
        if ( pos.line.charAt( pos.start ) != LPAREN )
        {
            throw new LdapSchemaException( I18n.err( I18n.ERR_13829_NO_OPENING_PAREN, 
                pos.lineNumber, pos.start ) );
        }
        else
        {
            pos.start++;
        }
        
        // Get rid of whites, comments end empty lines
        skipWhites( reader, pos, false );
        
        // Now, the OID. 
        String oid = getOidAndMacroRelaxed( pos, objectIdentifierMacros );
        
        // Check that the OID is valid
        if ( !Oid.isOid( oid ) )
        {
            throw new LdapSchemaException( I18n.err( I18n.ERR_13787_OID_EXPECTED, pos.lineNumber, pos.start ) );
        }
        
        MutableMatchingRule matchingRule = new MutableMatchingRule( oid );
        int elementsSeen = 0;
        boolean hasSyntax = false;
        
        while ( true )
        {
            if ( startsWith( reader, pos, RPAREN ) )
            {
                pos.start++;
                break;
            }
            
            skipWhites( reader, pos, true );
            
            if ( startsWith( pos, NAME_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, MatchingRuleElements.NAME, pos );

                pos.start += NAME_STR.length();
                
                skipWhites( reader, pos, true );

                matchingRule.setNames( getQDescrs( reader, pos, STRICT ) );
            }
            else if ( startsWith( pos, DESC_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, MatchingRuleElements.DESC, pos );

                pos.start += DESC_STR.length();
                
                skipWhites( reader, pos, true );

                matchingRule.setDescription( getQDString( reader, pos ) );
            }
            else if ( startsWith( pos, OBSOLETE_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, MatchingRuleElements.OBSOLETE, pos );

                pos.start += OBSOLETE_STR.length();
                
                matchingRule.setObsolete( true );
            }
            else if ( startsWith( pos, SYNTAX_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, MatchingRuleElements.SYNTAX, pos );

                pos.start += SYNTAX_STR.length();
                
                skipWhites( reader, pos, true );
                
                String syntaxOid = getNumericOid( pos );

                matchingRule.setSyntaxOid( syntaxOid );
                hasSyntax = true;
            }
            else if ( startsWith( pos, EXTENSION_PREFIX ) )
            {
                processExtension( reader, pos, matchingRule );
            }
            else if ( startsWith( reader, pos, RPAREN ) )
            {
                pos.start++;
                break;
            }
            else
            {
                // This is an error
                throw new LdapSchemaException( I18n.err( I18n.ERR_13781_MR_DESCRIPTION_INVALID, 
                    pos.lineNumber, pos.start ) );
            }
        }
        
        // Semantic checks
        if ( !hasSyntax )
        {
            throw new LdapSchemaException( I18n.err( I18n.ERR_13808_SYNTAX_REQUIRED, 
                pos.lineNumber, pos.start ) );
        }

        return matchingRule;
    }

    
    /**
     * Production for matching rule descriptions. It is fault-tolerant
     * against element ordering.
     *
     * <pre>
     * MatchingRuleDescription = LPAREN WSP
     *    numericoid                 ; object identifier
     *    [ SP "NAME" SP qdescrs ]   ; short names (descriptors)
     *    [ SP "DESC" SP qdstring ]  ; description
     *    [ SP "OBSOLETE" ]          ; not active
     *    SP "SYNTAX" SP numericoid  ; assertion syntax
     *    extensions WSP RPAREN      ; extensions
     * </pre>
     */
    private static MatchingRule parseMatchingRuleRelaxed( Reader reader, PosSchema pos,
        Map<String, OpenLdapObjectIdentifierMacro> objectIdentifierMacros ) 
            throws IOException, LdapSchemaException
    {
        // Get rid of whites, comments end empty lines
        skipWhites( reader, pos, false );
        
        // we must have a '('
        if ( pos.line.charAt( pos.start ) != LPAREN )
        {
            throw new LdapSchemaException( I18n.err( I18n.ERR_13829_NO_OPENING_PAREN, 
                pos.lineNumber, pos.start ) );
        }
        else
        {
            pos.start++;
        }
        
        // Get rid of whites, comments end empty lines
        skipWhites( reader, pos, false );
        
        // Now, the OID. 
        String oid = getOidAndMacroRelaxed( pos, objectIdentifierMacros );
        
        MutableMatchingRule matchingRule = new MutableMatchingRule( oid );
        int elementsSeen = 0;
        
        while ( true )
        {
            if ( startsWith( reader, pos, RPAREN ) )
            {
                pos.start++;
                break;
            }
            
            skipWhites( reader, pos, true );
            
            if ( startsWith( pos, NAME_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, MatchingRuleElements.NAME, pos );

                pos.start += NAME_STR.length();
                
                skipWhites( reader, pos, true );

                matchingRule.setNames( getQDescrs( reader, pos, RELAXED ) );
            }
            else if ( startsWith( pos, DESC_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, MatchingRuleElements.DESC, pos );

                pos.start += DESC_STR.length();
                
                skipWhites( reader, pos, true );

                matchingRule.setDescription( getQDString( reader, pos ) );
            }
            else if ( startsWith( pos, OBSOLETE_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, MatchingRuleElements.OBSOLETE, pos );

                pos.start += OBSOLETE_STR.length();
                
                matchingRule.setObsolete( true );
            }
            else if ( startsWith( pos, SYNTAX_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, MatchingRuleElements.SYNTAX, pos );

                pos.start += SYNTAX_STR.length();
                
                skipWhites( reader, pos, true );
                
                String syntaxOid = getNumericOid( pos );

                matchingRule.setSyntaxOid( syntaxOid );
            }
            else if ( startsWith( pos, EXTENSION_PREFIX ) )
            {
                processExtension( reader, pos, matchingRule );
            }
            else if ( startsWith( reader, pos, RPAREN ) )
            {
                pos.start++;
                break;
            }
            else
            {
                // This is an error
                throw new LdapSchemaException( I18n.err( I18n.ERR_13781_MR_DESCRIPTION_INVALID, 
                    pos.lineNumber, pos.start ) );
            }
        }

        return matchingRule;
    }

    
    /**
     * Production for matching MatchingRuleUse descriptions. It is fault-tolerant
     * against element ordering.
     *
     * <pre>
     * MatchingRuleUseDescription = LPAREN WSP
     *    numericoid                 ; object identifier
     *    [ SP "NAME" SP qdescrs ]   ; short names (descriptors)
     *    [ SP "DESC" SP qdstring ]  ; description
     *    [ SP "OBSOLETE" ]          ; not active
     *    SP "APPLIES" SP oids       ; attribute types
     *    extensions WSP RPAREN      ; extensions
     * </pre>
     * 
     * @param matchingRuleUseDescription The String containing the MatchingRuleUsedescription
     * @return An instance of MatchingRuleUse
     * @throws ParseException If the element was invalid
     */
    public MatchingRuleUse parseMatchingRuleUse( String matchingRuleUseDescription ) throws ParseException
    {
        if ( ( matchingRuleUseDescription == null ) || Strings.isEmpty( matchingRuleUseDescription.trim() ) )
        {
            throw new ParseException( I18n.err( I18n.ERR_13716_NULL_OR_EMPTY_STRING_SCHEMA_OBJECT ), 0 );
        }
        
        try ( Reader reader = new BufferedReader( new StringReader( matchingRuleUseDescription ) ) )
        {
            PosSchema pos = new PosSchema();

            if ( isQuirksModeEnabled )
            {
                return parseMatchingRuleUseRelaxed( reader, pos, objectIdentifierMacros );
            }
            else
            {
                return parseMatchingRuleUseStrict( reader, pos, objectIdentifierMacros );
            }
        }
        catch ( IOException | LdapSchemaException e )
        {
            throw new ParseException( e.getMessage(), 0 );
        }
    }

    
    /**
     * Production for MatchingRuleUse descriptions. It is fault-tolerant
     * against element ordering.
     *
     * <pre>
     * MatchingRuleUseDescription = LPAREN WSP
     *    numericoid                 ; object identifier
     *    [ SP "NAME" SP qdescrs ]   ; short names (descriptors)
     *    [ SP "DESC" SP qdstring ]  ; description
     *    [ SP "OBSOLETE" ]          ; not active
     *    SP "APPLIES" SP oids       ; attribute types
     *    extensions WSP RPAREN      ; extensions
     * </pre>
     */
    private static  MatchingRuleUse parseMatchingRuleUseStrict( Reader reader, PosSchema pos,
        Map<String, OpenLdapObjectIdentifierMacro> objectIdentifierMacros ) throws IOException, LdapSchemaException
    {
        // Get rid of whites, comments end empty lines
        skipWhites( reader, pos, false );
        
        // we must have a '('
        if ( pos.line.charAt( pos.start ) != LPAREN )
        {
            throw new LdapSchemaException( I18n.err( I18n.ERR_13829_NO_OPENING_PAREN, 
                pos.lineNumber, pos.start ) );
        }
        else
        {
            pos.start++;
        }
        
        // Get rid of whites, comments end empty lines
        skipWhites( reader, pos, false );
        
        // Now, the OID. 
        String oid = getOidAndMacroRelaxed( pos, objectIdentifierMacros );
        
        // Check that the OID is valid
        if ( !Oid.isOid( oid ) )
        {
            throw new LdapSchemaException( I18n.err( I18n.ERR_13787_OID_EXPECTED, pos.lineNumber, pos.start ) );
        }
        
        MatchingRuleUse matchingRuleUse = new MatchingRuleUse( oid );
        int elementsSeen = 0;
        boolean hasApplies = false;
        
        while ( true )
        {
            if ( startsWith( reader, pos, RPAREN ) )
            {
                pos.start++;
                break;
            }
            
            skipWhites( reader, pos, false );
            
            if ( startsWith( pos, NAME_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, MatchingRuleUseElements.NAME, pos );

                pos.start += NAME_STR.length();
                
                skipWhites( reader, pos, true );

                matchingRuleUse.setNames( getQDescrs( reader, pos, STRICT ) );
            }
            else if ( startsWith( pos, DESC_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, MatchingRuleUseElements.DESC, pos );

                pos.start += DESC_STR.length();
                
                skipWhites( reader, pos, true );

                matchingRuleUse.setDescription( getQDString( reader, pos ) );
            }
            else if ( startsWith( pos, OBSOLETE_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, MatchingRuleUseElements.OBSOLETE, pos );

                pos.start += OBSOLETE_STR.length();
                
                matchingRuleUse.setObsolete( true );
            }
            else if ( startsWith( pos, APPLIES_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, MatchingRuleUseElements.APPLIES, pos );

                pos.start += APPLIES_STR.length();
                
                skipWhites( reader, pos, true );
                
                List<String> oids = getOidsStrict( reader, pos );

                matchingRuleUse.setApplicableAttributeOids( oids );
                hasApplies = true;
            }
            else if ( startsWith( pos, EXTENSION_PREFIX ) )
            {
                processExtension( reader, pos, matchingRuleUse );
            }
            else if ( startsWith( reader, pos, RPAREN ) )
            {
                pos.start++;
                break;
            }
            else
            {
                // This is an error
                throw new LdapSchemaException( I18n.err( I18n.ERR_13815_MRU_DESCRIPTION_INVALID, 
                    pos.lineNumber, pos.start ) );
            }
        }
        
        // Semantic checks
        if ( !hasApplies )
        {
            throw new LdapSchemaException( I18n.err( I18n.ERR_13814_APPLIES_REQUIRED, 
                pos.lineNumber, pos.start ) );
        }

        return matchingRuleUse;
    }

    
    /**
     * Production for MatchingRuleUse descriptions. It is fault-tolerant
     * against element ordering.
     *
     * <pre>
     * MatchingRuleUseDescription = LPAREN WSP
     *    numericoid                 ; object identifier
     *    [ SP "NAME" SP qdescrs ]   ; short names (descriptors)
     *    [ SP "DESC" SP qdstring ]  ; description
     *    [ SP "OBSOLETE" ]          ; not active
     *    SP "APPLIES" SP oids       ; attribute types
     *    extensions WSP RPAREN      ; extensions
     * </pre>
     */
    private static MatchingRuleUse parseMatchingRuleUseRelaxed( Reader reader, PosSchema pos,
        Map<String, OpenLdapObjectIdentifierMacro> objectIdentifierMacros ) 
            throws IOException, LdapSchemaException
    {
        // Get rid of whites, comments end empty lines
        skipWhites( reader, pos, false );
        
        // we must have a '('
        if ( pos.line.charAt( pos.start ) != LPAREN )
        {
            throw new LdapSchemaException( I18n.err( I18n.ERR_13829_NO_OPENING_PAREN, 
                pos.lineNumber, pos.start ) );
        }
        else
        {
            pos.start++;
        }
        
        // Get rid of whites, comments end empty lines
        skipWhites( reader, pos, false );
        
        // Now, the OID. 
        String oid = getOidAndMacroRelaxed( pos, objectIdentifierMacros );
        
        MatchingRuleUse matchingRuleUse = new MatchingRuleUse( oid );
        int elementsSeen = 0;
        
        while ( true )
        {
            if ( startsWith( reader, pos, RPAREN ) )
            {
                pos.start++;
                break;
            }
            
            skipWhites( reader, pos, true );
            
            if ( startsWith( pos, NAME_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, MatchingRuleUseElements.NAME, pos );

                pos.start += NAME_STR.length();
                
                skipWhites( reader, pos, true );

                matchingRuleUse.setNames( getQDescrs( reader, pos, RELAXED ) );
            }
            else if ( startsWith( pos, DESC_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, MatchingRuleUseElements.DESC, pos );

                pos.start += DESC_STR.length();
                
                skipWhites( reader, pos, true );

                matchingRuleUse.setDescription( getQDString( reader, pos ) );
            }
            else if ( startsWith( pos, OBSOLETE_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, MatchingRuleUseElements.OBSOLETE, pos );

                pos.start += OBSOLETE_STR.length();
                
                matchingRuleUse.setObsolete( true );
            }
            else if ( startsWith( pos, APPLIES_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, MatchingRuleUseElements.APPLIES, pos );

                pos.start += APPLIES_STR.length();
                
                skipWhites( reader, pos, true );
                
                List<String> oids = getOidsRelaxed( reader, pos );

                matchingRuleUse.setApplicableAttributeOids( oids );
            }
            else if ( startsWith( pos, EXTENSION_PREFIX ) )
            {
                processExtension( reader, pos, matchingRuleUse );
            }
            else if ( startsWith( reader, pos, RPAREN ) )
            {
                pos.start++;
                break;
            }
            else
            {
                // This is an error
                throw new LdapSchemaException( I18n.err( I18n.ERR_13815_MRU_DESCRIPTION_INVALID, 
                    pos.lineNumber, pos.start ) );
            }
        }

        return matchingRuleUse;
    }

    
    /**
     * Production for NameForm descriptions. It is fault-tolerant
     * against element ordering.
     *
     * <pre>
     * NameFormDescription = LPAREN WSP
     *    numericoid                 ; object identifier
     *    [ SP "NAME" SP qdescrs ]   ; short names (descriptors)
     *    [ SP "DESC" SP qdstring ]  ; description
     *    [ SP "OBSOLETE" ]          ; not active
     *    SP "OC" SP oid             ; structural object class
     *    SP "MUST" SP oids          ; attribute types
     *    [ SP "MAY" SP oids ]       ; attribute types
     *    extensions WSP RPAREN      ; extensions
     * </pre>
     * 
     * @param nameFormDescription The String containing the NameFormdescription
     * @return An instance of NameForm
     * @throws ParseException If the element was invalid
     */
    public NameForm parseNameForm( String nameFormDescription ) throws ParseException
    {
        if ( ( nameFormDescription == null ) || Strings.isEmpty( nameFormDescription.trim() ) )
        {
            throw new ParseException( I18n.err( I18n.ERR_13716_NULL_OR_EMPTY_STRING_SCHEMA_OBJECT ), 0 );
        }
        
        try ( Reader reader = new BufferedReader( new StringReader( nameFormDescription ) ) )
        {
            PosSchema pos = new PosSchema();

            if ( isQuirksModeEnabled )
            {
                return parseNameFormRelaxed( reader, pos, objectIdentifierMacros );
            }
            else
            {
                return parseNameFormStrict( reader, pos, objectIdentifierMacros );
            }
        }
        catch ( IOException | LdapSchemaException e )
        {
            throw new ParseException( e.getMessage(), 0 );
        }
    }

    
    /**
     * Production for NameForm descriptions. It is fault-tolerant
     * against element ordering.
     *
     * <pre>
     * NameFormDescription = LPAREN WSP
     *    numericoid                 ; object identifier
     *    [ SP "NAME" SP qdescrs ]   ; short names (descriptors)
     *    [ SP "DESC" SP qdstring ]  ; description
     *    [ SP "OBSOLETE" ]          ; not active
     *    SP "OC" SP oid             ; structural object class
     *    SP "MUST" SP oids          ; attribute types
     *    [ SP "MAY" SP oids ]       ; attribute types
     *    extensions WSP RPAREN      ; extensions
     * </pre>
     */
    private static NameForm parseNameFormStrict( Reader reader, PosSchema pos,
        Map<String, OpenLdapObjectIdentifierMacro> objectIdentifierMacros ) throws IOException, LdapSchemaException
    {
        // Get rid of whites, comments end empty lines
        skipWhites( reader, pos, false );
        
        // we must have a '('
        if ( pos.line.charAt( pos.start ) != LPAREN )
        {
            throw new LdapSchemaException( I18n.err( I18n.ERR_13829_NO_OPENING_PAREN, 
                pos.lineNumber, pos.start ) );
        }
        else
        {
            pos.start++;
        }
        
        // Get rid of whites, comments end empty lines
        skipWhites( reader, pos, false );
        
        // Now, the OID. 
        String oid = getOidAndMacroRelaxed( pos, objectIdentifierMacros );
        
        // Check that the OID is valid
        if ( !Oid.isOid( oid ) )
        {
            throw new LdapSchemaException( I18n.err( I18n.ERR_13787_OID_EXPECTED, pos.lineNumber, pos.start ) );
        }
        
        NameForm nameForm = new NameForm( oid );
        int elementsSeen = 0;
        boolean hasOc = false;
        boolean hasMust = false;
        
        while ( true )
        {
            if ( startsWith( reader, pos, RPAREN ) )
            {
                pos.start++;
                break;
            }
            
            skipWhites( reader, pos, true );

            if ( startsWith( pos, NAME_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, NameFormElements.NAME, pos );

                pos.start += NAME_STR.length();
                
                skipWhites( reader, pos, true );

                nameForm.setNames( getQDescrs( reader, pos, STRICT ) );
            }
            else if ( startsWith( pos, DESC_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, NameFormElements.DESC, pos );

                pos.start += DESC_STR.length();
                
                skipWhites( reader, pos, true );

                nameForm.setDescription( getQDString( reader, pos ) );
            }
            else if ( startsWith( pos, OBSOLETE_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, NameFormElements.OBSOLETE, pos );

                pos.start += OBSOLETE_STR.length();
                
                nameForm.setObsolete( true );
            }
            else if ( startsWith( pos, OC_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, NameFormElements.OC, pos );

                pos.start += OC_STR.length();
                
                skipWhites( reader, pos, true );
                
                String oc = getOidStrict( pos );

                nameForm.setStructuralObjectClassOid( oc );
                hasOc = true;
            }
            else if ( startsWith( pos, MUST_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, NameFormElements.MUST, pos );

                pos.start += MUST_STR.length();
                
                skipWhites( reader, pos, true );
                
                List<String> must = getOidsStrict( reader, pos );

                nameForm.setMustAttributeTypeOids( must );
                hasMust = true;
            }
            else if ( startsWith( pos, MAY_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, NameFormElements.MAY, pos );

                pos.start += MAY_STR.length();
                
                skipWhites( reader, pos, true );
                
                List<String> may = getOidsStrict( reader, pos );

                nameForm.setMayAttributeTypeOids( may );
            }
            else if ( startsWith( pos, EXTENSION_PREFIX ) )
            {
                processExtension( reader, pos, nameForm );
            }
            else if ( startsWith( reader, pos, RPAREN ) )
            {
                pos.start++;
                break;
            }
            else
            {
                // This is an error
                throw new LdapSchemaException( I18n.err( I18n.ERR_13816_NF_DESCRIPTION_INVALID, 
                    pos.lineNumber, pos.start ) );
            }
        }
        
        // Semantic checks
        if ( !hasOc )
        {
            throw new LdapSchemaException( I18n.err( I18n.ERR_13817_STRUCTURAL_OBJECT_CLASS_REQUIRED, 
                pos.lineNumber, pos.start ) );
        }

        if ( !hasMust )
        {
            throw new LdapSchemaException( I18n.err( I18n.ERR_13818_MUST_REQUIRED, 
                pos.lineNumber, pos.start ) );
        }

        return nameForm;
    }

    
    /**
     * Production for NameForm descriptions. It is fault-tolerant
     * against element ordering.
     *
     * <pre>
     * NameFormDescription = LPAREN WSP
     *    numericoid                 ; object identifier
     *    [ SP "NAME" SP qdescrs ]   ; short names (descriptors)
     *    [ SP "DESC" SP qdstring ]  ; description
     *    [ SP "OBSOLETE" ]          ; not active
     *    SP "OC" SP oid             ; structural object class
     *    SP "MUST" SP oids          ; attribute types
     *    [ SP "MAY" SP oids ]       ; attribute types
     *    extensions WSP RPAREN      ; extensions
     * </pre>
     */
    private static NameForm parseNameFormRelaxed( Reader reader, PosSchema pos,
        Map<String, OpenLdapObjectIdentifierMacro> objectIdentifierMacros ) 
            throws IOException, LdapSchemaException
    {
        // Get rid of whites, comments end empty lines
        skipWhites( reader, pos, false );
        
        // we must have a '('
        if ( pos.line.charAt( pos.start ) != LPAREN )
        {
            throw new LdapSchemaException( I18n.err( I18n.ERR_13829_NO_OPENING_PAREN, 
                pos.lineNumber, pos.start ) );
        }
        else
        {
            pos.start++;
        }
        
        // Get rid of whites, comments end empty lines
        skipWhites( reader, pos, false );
        
        // Now, the OID. 
        String oid = getOidAndMacroRelaxed( pos, objectIdentifierMacros );
        
        NameForm nameForm = new NameForm( oid );
        int elementsSeen = 0;
        
        while ( true )
        {
            if ( startsWith( reader, pos, RPAREN ) )
            {
                pos.start++;
                break;
            }
            
            skipWhites( reader, pos, true );

            if ( startsWith( pos, NAME_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, NameFormElements.NAME, pos );

                pos.start += NAME_STR.length();
                
                skipWhites( reader, pos, true );

                nameForm.setNames( getQDescrs( reader, pos, RELAXED ) );
            }
            else if ( startsWith( pos, DESC_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, NameFormElements.DESC, pos );

                pos.start += DESC_STR.length();
                
                skipWhites( reader, pos, true );

                nameForm.setDescription( getQDString( reader, pos ) );
            }
            else if ( startsWith( pos, OBSOLETE_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, NameFormElements.OBSOLETE, pos );

                pos.start += OBSOLETE_STR.length();
                
                nameForm.setObsolete( true );
            }
            else if ( startsWith( pos, OC_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, NameFormElements.OC, pos );

                pos.start += OC_STR.length();
                
                skipWhites( reader, pos, true );
                
                String oc = getOidRelaxed( pos, UN_QUOTED );

                nameForm.setStructuralObjectClassOid( oc );
            }
            else if ( startsWith( pos, MUST_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, NameFormElements.MUST, pos );

                pos.start += MUST_STR.length();
                
                skipWhites( reader, pos, true );
                
                List<String> must = getOidsRelaxed( reader, pos );

                nameForm.setMustAttributeTypeOids( must );
            }
            else if ( startsWith( pos, MAY_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, NameFormElements.MAY, pos );

                pos.start += MAY_STR.length();
                
                skipWhites( reader, pos, true );
                
                List<String> may = getOidsRelaxed( reader, pos );

                nameForm.setMayAttributeTypeOids( may );
            }
            else if ( startsWith( pos, EXTENSION_PREFIX ) )
            {
                processExtension( reader, pos, nameForm );
            }
            else if ( startsWith( reader, pos, RPAREN ) )
            {
                pos.start++;
                break;
            }
            else
            {
                // This is an error
                throw new LdapSchemaException( I18n.err( I18n.ERR_13816_NF_DESCRIPTION_INVALID, 
                    pos.lineNumber, pos.start ) );
            }
        }
        
        return nameForm;
    }

    
    /**
     * Production for Normalizer descriptions. It is fault-tolerant
     * against element ordering.
     *
     * <pre>
     * NormalizerDescription = LPAREN WSP
     *       numericoid                           ; object identifier
     *       [ SP "DESC" SP qdstring ]            ; description
     *       SP "FQCN" SP fqcn                    ; fully qualified class name
     *       [ SP "BYTECODE" SP base64 ]          ; optional base64 encoded bytecode
     *       extensions WSP RPAREN                ; extensions
     * 
     * base64          = *(4base64-char)
     * base64-char     = ALPHA / DIGIT / "+" / "/"
     * fqcn = fqcnComponent 1*( DOT fqcnComponent )
     * fqcnComponent = ???
     * </pre>
     * 
     * @param normalizerDescription The String containing the NormalizerDescription
     * @return An instance of NormalizerDescription
     * @throws ParseException If the element was invalid
     */
    public NormalizerDescription parseNormalizer( String normalizerDescription ) throws ParseException
    {
        if ( ( normalizerDescription == null ) || Strings.isEmpty( normalizerDescription.trim() ) )
        {
            throw new ParseException( I18n.err( I18n.ERR_13716_NULL_OR_EMPTY_STRING_SCHEMA_OBJECT ), 0 );
        }
        
        try ( Reader reader = new BufferedReader( new StringReader( normalizerDescription ) ) )
        {
            PosSchema pos = new PosSchema();

            if ( isQuirksModeEnabled )
            {
                return parseNormalizerRelaxed( reader, pos, objectIdentifierMacros );
            }
            else
            {
                return parseNormalizerStrict( reader, pos, objectIdentifierMacros );
            }
        }
        catch ( IOException | LdapSchemaException e )
        {
            throw new ParseException( e.getMessage(), 0 );
        }
    }

    
    /**
     * Production for Normalizer descriptions. It is fault-tolerant
     * against element ordering.
     *
     * <pre>
     * NormalizerDescription = LPAREN WSP
     *       numericoid                           ; object identifier
     *       [ SP "DESC" SP qdstring ]            ; description
     *       SP "FQCN" SP fqcn                    ; fully qualified class name
     *       [ SP "BYTECODE" SP base64 ]          ; optional base64 encoded bytecode
     *       extensions WSP RPAREN                ; extensions
     * 
     * base64          = *(4base64-char)
     * base64-char     = ALPHA / DIGIT / "+" / "/"
     * fqcn = fqcnComponent 1*( DOT fqcnComponent )
     * fqcnComponent = ???
     * </pre>
     */
    private static NormalizerDescription parseNormalizerStrict( Reader reader, PosSchema pos,
        Map<String, OpenLdapObjectIdentifierMacro> objectIdentifierMacros ) throws IOException, LdapSchemaException
    {
        // Get rid of whites, comments end empty lines
        skipWhites( reader, pos, false );
        
        // we must have a '('
        if ( pos.line.charAt( pos.start ) != LPAREN )
        {
            throw new LdapSchemaException( I18n.err( I18n.ERR_13829_NO_OPENING_PAREN, 
                pos.lineNumber, pos.start ) );
        }
        else
        {
            pos.start++;
        }
        
        // Get rid of whites, comments end empty lines
        skipWhites( reader, pos, false );
        
        // Now, the OID. 
        String oid = getOidAndMacroRelaxed( pos, objectIdentifierMacros );
        
        // Check that the OID is valid
        if ( !Oid.isOid( oid ) )
        {
            throw new LdapSchemaException( I18n.err( I18n.ERR_13787_OID_EXPECTED, pos.lineNumber, pos.start ) );
        }
        
        NormalizerDescription normalizer = new NormalizerDescription( oid );
        int elementsSeen = 0;
        boolean hasFqcn = false;
        boolean hasByteCode = false;
        
        while ( true )
        {
            if ( startsWith( reader, pos, RPAREN ) )
            {
                pos.start++;
                break;
            }
            
            skipWhites( reader, pos, true );

            if ( startsWith( pos, DESC_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, NormalizerElements.DESC, pos );

                pos.start += DESC_STR.length();
                
                skipWhites( reader, pos, true );

                normalizer.setDescription( getQDString( reader, pos ) );
            }
            else if ( startsWith( pos, FQCN_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, NormalizerElements.FQCN, pos );

                pos.start += FQCN_STR.length();
                
                skipWhites( reader, pos, true );

                String fqcn = getFqcn( pos );
                normalizer.setFqcn( fqcn );
                hasFqcn = true;
            }
            else if ( startsWith( pos, BYTECODE_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, NormalizerElements.BYTECODE, pos );

                pos.start += BYTECODE_STR.length();
                
                skipWhites( reader, pos, true );

                String byteCode = getByteCode( pos );
                normalizer.setBytecode( byteCode );
                hasByteCode = true;
            }
            else if ( startsWith( pos, EXTENSION_PREFIX ) )
            {
                processExtension( reader, pos, normalizer );
            }
            else if ( startsWith( reader, pos, RPAREN ) )
            {
                pos.start++;
                break;
            }
            else
            {
                // This is an error
                throw new LdapSchemaException( I18n.err( I18n.ERR_13821_NORM_DESCRIPTION_INVALID, 
                    pos.lineNumber, pos.start ) );
            }
        }
        
        // Semantic checks
        if ( !hasFqcn )
        {
            throw new LdapSchemaException( I18n.err( I18n.ERR_13819_FQCN_REQUIRED, 
                pos.lineNumber, pos.start ) );
        }

        if ( ( hasByteCode ) && ( normalizer.getBytecode().length() % 4 != 0 ) )
        {
            throw new LdapSchemaException( I18n.err( I18n.ERR_13820_BYTE_CODE_REQUIRED, 
                pos.lineNumber, pos.start ) );
        }

        return normalizer;
    }

    
    /**
     * Production for Normalizer descriptions. It is fault-tolerant
     * against element ordering.
     *
     * <pre>
     * NormalizerDescription = LPAREN WSP
     *       numericoid                           ; object identifier
     *       [ SP "DESC" SP qdstring ]            ; description
     *       SP "FQCN" SP fqcn                    ; fully qualified class name
     *       [ SP "BYTECODE" SP base64 ]          ; optional base64 encoded bytecode
     *       extensions WSP RPAREN                ; extensions
     * 
     * base64          = *(4base64-char)
     * base64-char     = ALPHA / DIGIT / "+" / "/"
     * fqcn = fqcnComponent 1*( DOT fqcnComponent )
     * fqcnComponent = ???
     * </pre>
     */
    private static NormalizerDescription parseNormalizerRelaxed( Reader reader, PosSchema pos,
        Map<String, OpenLdapObjectIdentifierMacro> objectIdentifierMacros ) 
            throws IOException, LdapSchemaException
    {
        // Get rid of whites, comments end empty lines
        skipWhites( reader, pos, false );
        
        // we must have a '('
        if ( pos.line.charAt( pos.start ) != LPAREN )
        {
            throw new LdapSchemaException( I18n.err( I18n.ERR_13829_NO_OPENING_PAREN, 
                pos.lineNumber, pos.start ) );
        }
        else
        {
            pos.start++;
        }
        
        // Get rid of whites, comments end empty lines
        skipWhites( reader, pos, false );
        
        // Now, the OID. 
        String oid = getOidAndMacroRelaxed( pos, objectIdentifierMacros );
        
        NormalizerDescription normalizer = new NormalizerDescription( oid );
        int elementsSeen = 0;
        
        while ( true )
        {
            if ( startsWith( reader, pos, RPAREN ) )
            {
                pos.start++;
                break;
            }
            
            skipWhites( reader, pos, true );

            if ( startsWith( pos, DESC_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, NormalizerElements.DESC, pos );

                pos.start += DESC_STR.length();
                
                skipWhites( reader, pos, true );

                normalizer.setDescription( getQDString( reader, pos ) );
            }
            else if ( startsWith( pos, FQCN_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, NormalizerElements.FQCN, pos );

                pos.start += FQCN_STR.length();
                
                skipWhites( reader, pos, true );

                String fqcn = getFqcn( pos );
                normalizer.setFqcn( fqcn );
            }
            else if ( startsWith( pos, BYTECODE_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, NormalizerElements.BYTECODE, pos );

                pos.start += BYTECODE_STR.length();
                
                skipWhites( reader, pos, true );

                String byteCode = getByteCode( pos );
                normalizer.setBytecode( byteCode );
            }
            else if ( startsWith( pos, EXTENSION_PREFIX ) )
            {
                processExtension( reader, pos, normalizer );
            }
            else if ( startsWith( reader, pos, RPAREN ) )
            {
                pos.start++;
                break;
            }
            else
            {
                // This is an error
                throw new LdapSchemaException( I18n.err( I18n.ERR_13821_NORM_DESCRIPTION_INVALID, 
                    pos.lineNumber, pos.start ) );
            }
        }
        
        return normalizer;
    }

    
    /**
     * Production for matching ObjectClass descriptions. It is fault-tolerant
     * against element ordering.
     * 
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
     * 
     * @param objectClassDescription The String containing the ObjectClassDescription
     * @return An instance of objectClass
     * @throws ParseException If the element was invalid
     */
    public ObjectClass parseObjectClass( String objectClassDescription ) throws ParseException
    {
        if ( ( objectClassDescription == null ) || Strings.isEmpty( objectClassDescription.trim() ) )
        {
            throw new ParseException( I18n.err( I18n.ERR_13716_NULL_OR_EMPTY_STRING_SCHEMA_OBJECT ), 0 );
        }
        
        try ( Reader reader = new BufferedReader( new StringReader( objectClassDescription ) ) )
        {
            PosSchema pos = new PosSchema();

            if ( isQuirksModeEnabled )
            {
                return parseObjectClassRelaxed( reader, pos, objectIdentifierMacros );
            }
            else
            {
                return parseObjectClassStrict( reader, pos, objectIdentifierMacros );
            }
        }
        catch ( IOException | LdapSchemaException e )
        {
            throw new ParseException( e.getMessage(), 0 );
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
    private static ObjectClass parseObjectClassStrict( Reader reader, PosSchema pos,
        Map<String, OpenLdapObjectIdentifierMacro> objectIdentifierMacros ) 
        throws IOException, LdapSchemaException
    {
        // Get rid of whites, comments end empty lines
        skipWhites( reader, pos, false );
        
        // we must have a '('
        if ( pos.line.charAt( pos.start ) != LPAREN )
        {
            throw new LdapSchemaException( I18n.err( I18n.ERR_13829_NO_OPENING_PAREN, 
                pos.lineNumber, pos.start ) );
        }
        else
        {
            pos.start++;
        }
        
        // Get rid of whites, comments end empty lines
        skipWhites( reader, pos, false );
        
        // Now, the numeric OID
        String oid = getOidAndMacroRelaxed( pos, objectIdentifierMacros );
        
        // Check that the OID is valid
        if ( !Oid.isOid( oid ) )
        {
            throw new LdapSchemaException( I18n.err( I18n.ERR_13787_OID_EXPECTED, pos.lineNumber, pos.start ) );
        }

        MutableObjectClass objectClass = new MutableObjectClass( oid );
        int elementsSeen = 0;
        
        while ( true )
        {
            if ( startsWith( reader, pos, RPAREN ) )
            {
                pos.start++;
                break;
            }
            
            skipWhites( reader, pos, true );

            if ( startsWith( pos, NAME_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, ObjectClassElements.NAME, pos );

                pos.start += NAME_STR.length();
                
                skipWhites( reader, pos, true );

                List<String> names = getQDescrs( reader, pos, STRICT );
                objectClass.setNames( names );
            }
            else if ( startsWith( pos, DESC_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, ObjectClassElements.DESC, pos );
                
                pos.start += DESC_STR.length();
                
                skipWhites( reader, pos, true );

                objectClass.setDescription( getQDString( reader, pos ) );
            }
            else if ( startsWith( pos, OBSOLETE_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, ObjectClassElements.OBSOLETE, pos );
                
                pos.start += OBSOLETE_STR.length();
                
                objectClass.setObsolete( true );
            }
            else if ( startsWith( pos, SUP_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, ObjectClassElements.SUP, pos );
                
                pos.start += SUP_STR.length();
                
                skipWhites( reader, pos, true );
                
                List<String> superiorOids = getOidsStrict( reader, pos );

                objectClass.setSuperiorOids( superiorOids );
            }
            else if ( startsWith( pos, ABSTRACT_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, ObjectClassElements.ABSTRACT, pos );
                
                pos.start += ABSTRACT_STR.length();
                
                objectClass.setType( ObjectClassTypeEnum.ABSTRACT );
            }
            else if ( startsWith( pos, STRUCTURAL_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, ObjectClassElements.STRUCTURAL, pos );
                
                pos.start += STRUCTURAL_STR.length();
                
                objectClass.setType( ObjectClassTypeEnum.STRUCTURAL );
            }
            else if ( startsWith( pos, AUXILIARY_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, ObjectClassElements.AUXILIARY, pos );
                
                pos.start += AUXILIARY_STR.length();
                
                objectClass.setType( ObjectClassTypeEnum.AUXILIARY );
            }
            else if ( startsWith( pos, MUST_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, ObjectClassElements.MUST, pos );
                
                pos.start += MUST_STR.length();
                
                skipWhites( reader, pos, true );
                
                List<String> mustAttributeTypes = getOidsStrict( reader, pos );
                objectClass.setMustAttributeTypeOids( mustAttributeTypes );
            }
            else if ( startsWith( pos, MAY_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, ObjectClassElements.MAY, pos );
                
                pos.start += MAY_STR.length();
                
                skipWhites( reader, pos, true );
                
                List<String> mayAttributeTypes = getOidsStrict( reader, pos );
                objectClass.setMayAttributeTypeOids( mayAttributeTypes );
            }
            else if ( startsWith( pos, EXTENSION_PREFIX ) )
            {
                processExtension( reader, pos, objectClass );
            }
            else if ( startsWith( reader, pos, RPAREN ) )
            {
                pos.start++;
                break;
            }
            else
            {
                // This is an error
                throw new LdapSchemaException( I18n.err( I18n.ERR_13803_OC_DESCRIPTION_INVALID, 
                    pos.lineNumber, pos.start ) );
            }
        }

        pos.start++;
        
        return objectClass;
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
    private static ObjectClass parseObjectClassRelaxed( Reader reader, PosSchema pos,
        Map<String, OpenLdapObjectIdentifierMacro> objectIdentifierMacros ) 
            throws IOException, LdapSchemaException
    {
        // Get rid of whites, comments end empty lines
        skipWhites( reader, pos, false );
        
        // we must have a '('
        if ( pos.line.charAt( pos.start ) != LPAREN )
        {
            throw new LdapSchemaException( I18n.err( I18n.ERR_13829_NO_OPENING_PAREN, 
                pos.lineNumber, pos.start ) );
        }
        else
        {
            pos.start++;
        }
        
        // Get rid of whites, comments end empty lines
        skipWhites( reader, pos, false );
        
        // Now, the numeric OID
        String oid = getOidAndMacroRelaxed( pos, objectIdentifierMacros );
        
        MutableObjectClass objectClass = new MutableObjectClass( oid );
        int elementsSeen = 0;
        
        while ( true )
        {
            if ( startsWith( reader, pos, RPAREN ) )
            {
                pos.start++;
                break;
            }
            
            skipWhites( reader, pos, true );

            if ( startsWith( pos, NAME_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, ObjectClassElements.NAME, pos );

                pos.start += NAME_STR.length();
                
                skipWhites( reader, pos, true );

                List<String> names = getQDescrs( reader, pos, RELAXED );

                objectClass.setNames( names );
            }
            else if ( startsWith( pos, DESC_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, ObjectClassElements.DESC, pos );
                
                pos.start += DESC_STR.length();
                
                skipWhites( reader, pos, true );

                objectClass.setDescription( getQDString( reader, pos ) );
            }
            else if ( startsWith( pos, OBSOLETE_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, ObjectClassElements.OBSOLETE, pos );
                
                pos.start += OBSOLETE_STR.length();
                
                objectClass.setObsolete( true );
            }
            else if ( startsWith( pos, SUP_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, ObjectClassElements.SUP, pos );
                
                pos.start += SUP_STR.length();
                
                skipWhites( reader, pos, true );
                
                List<String> superiorOids = getOidsRelaxed( reader, pos );

                objectClass.setSuperiorOids( superiorOids );
            }
            else if ( startsWith( pos, ABSTRACT_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, ObjectClassElements.ABSTRACT, pos );
                
                pos.start += ABSTRACT_STR.length();
                
                objectClass.setType( ObjectClassTypeEnum.ABSTRACT );
            }
            else if ( startsWith( pos, STRUCTURAL_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, ObjectClassElements.STRUCTURAL, pos );
                
                pos.start += STRUCTURAL_STR.length();
                
                objectClass.setType( ObjectClassTypeEnum.STRUCTURAL );
            }
            else if ( startsWith( pos, AUXILIARY_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, ObjectClassElements.AUXILIARY, pos );
                
                pos.start += AUXILIARY_STR.length();
                
                objectClass.setType( ObjectClassTypeEnum.AUXILIARY );
            }
            else if ( startsWith( pos, MUST_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, ObjectClassElements.MUST, pos );
                
                pos.start += MUST_STR.length();
                
                skipWhites( reader, pos, true );
                
                List<String> mustAttributeTypes = getOidsRelaxed( reader, pos );
                objectClass.setMustAttributeTypeOids( mustAttributeTypes );
            }
            else if ( startsWith( pos, MAY_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, ObjectClassElements.MAY, pos );
                
                pos.start += MAY_STR.length();
                
                skipWhites( reader, pos, true );
                
                List<String> mayAttributeTypes = getOidsRelaxed( reader, pos );
                objectClass.setMayAttributeTypeOids( mayAttributeTypes );
            }
            else if ( startsWith( pos, EXTENSION_PREFIX ) )
            {
                processExtension( reader, pos, objectClass );
            }
            else if ( startsWith( reader, pos, RPAREN ) )
            {
                pos.start++;
                break;
            }
            else
            {
                // This is an error
                throw new LdapSchemaException( I18n.err( I18n.ERR_13803_OC_DESCRIPTION_INVALID, 
                    pos.lineNumber, pos.start ) );
            }
        }

        pos.start++;
        
        return objectClass;
    }

    
    /**
     * Production for SyntaxChecker descriptions. It is fault-tolerant
     * against element ordering.
     *
     * <pre>
     * SyntaxCheckerDescription = LPAREN WSP
     *       numericoid                           ; object identifier
     *       [ SP "DESC" SP qdstring ]            ; description
     *       SP "FQCN" SP fqcn                    ; fully qualified class name
     *       [ SP "BYTECODE" SP base64 ]          ; optional base64 encoded bytecode
     *       extensions WSP RPAREN                ; extensions
     * 
     * base64          = *(4base64-char)
     * base64-char     = ALPHA / DIGIT / "+" / "/"
     * fqcn = fqcnComponent 1*( DOT fqcnComponent )
     * fqcnComponent = ???
     * </pre>
     * 
     * @param syntaxCheckerDescription The String containing the SyntaxCheckerDescription
     * @return An instance of SyntaxCheckerDescription
     * @throws ParseException If the element was invalid
     */
    public SyntaxCheckerDescription parseSyntaxChecker( String syntaxCheckerDescription ) throws ParseException
    {
        if ( ( syntaxCheckerDescription == null ) || Strings.isEmpty( syntaxCheckerDescription.trim() ) )
        {
            throw new ParseException( I18n.err( I18n.ERR_13716_NULL_OR_EMPTY_STRING_SCHEMA_OBJECT ), 0 );
        }
        
        try ( Reader reader = new BufferedReader( new StringReader( syntaxCheckerDescription ) ) )
        {
            PosSchema pos = new PosSchema();

            if ( isQuirksModeEnabled )
            {
                return parseSyntaxCheckerRelaxed( reader, pos, objectIdentifierMacros );
            }
            else
            {
                return parseSyntaxCheckerStrict( reader, pos, objectIdentifierMacros );
            }
        }
        catch ( IOException | LdapSchemaException e )
        {
            throw new ParseException( e.getMessage(), 0 );
        }
    }

    
    /**
     * Production for SyntaxChecker descriptions. It is fault-tolerant
     * against element ordering.
     *
     * <pre>
     * SyntaxCheckerDescription = LPAREN WSP
     *       numericoid                           ; object identifier
     *       [ SP "DESC" SP qdstring ]            ; description
     *       SP "FQCN" SP fqcn                    ; fully qualified class name
     *       [ SP "BYTECODE" SP base64 ]          ; optional base64 encoded bytecode
     *       extensions WSP RPAREN                ; extensions
     * 
     * base64          = *(4base64-char)
     * base64-char     = ALPHA / DIGIT / "+" / "/"
     * fqcn = fqcnComponent 1*( DOT fqcnComponent )
     * fqcnComponent = ???
     * </pre>
     */
    private static SyntaxCheckerDescription parseSyntaxCheckerStrict( Reader reader, PosSchema pos,
        Map<String, OpenLdapObjectIdentifierMacro> objectIdentifierMacros ) throws IOException, LdapSchemaException
    {
        // Get rid of whites, comments end empty lines
        skipWhites( reader, pos, false );
        
        // we must have a '('
        if ( pos.line.charAt( pos.start ) != LPAREN )
        {
            throw new LdapSchemaException( I18n.err( I18n.ERR_13829_NO_OPENING_PAREN, 
                pos.lineNumber, pos.start ) );
        }
        else
        {
            pos.start++;
        }
        
        // Get rid of whites, comments end empty lines
        skipWhites( reader, pos, false );
        
        // Now, the OID. 
        String oid = getOidAndMacroRelaxed( pos, objectIdentifierMacros );
        
        // Check that the OID is valid
        if ( !Oid.isOid( oid ) )
        {
            throw new LdapSchemaException( I18n.err( I18n.ERR_13787_OID_EXPECTED, pos.lineNumber, pos.start ) );
        }
        
        SyntaxCheckerDescription syntaxChecker = new SyntaxCheckerDescription( oid );
        int elementsSeen = 0;
        boolean hasFqcn = false;
        boolean hasByteCode = false;
        
        while ( true )
        {
            if ( startsWith( reader, pos, RPAREN ) )
            {
                pos.start++;
                break;
            }
            
            skipWhites( reader, pos, true );

            if ( startsWith( pos, DESC_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, SyntaxCheckerElements.DESC, pos );

                pos.start += DESC_STR.length();
                
                skipWhites( reader, pos, true );

                syntaxChecker.setDescription( getQDString( reader, pos ) );
            }
            else if ( startsWith( pos, FQCN_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, SyntaxCheckerElements.FQCN, pos );

                pos.start += FQCN_STR.length();
                
                skipWhites( reader, pos, true );

                String fqcn = getFqcn( pos );
                syntaxChecker.setFqcn( fqcn );
                hasFqcn = true;
            }
            else if ( startsWith( pos, BYTECODE_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, SyntaxCheckerElements.BYTECODE, pos );

                pos.start += BYTECODE_STR.length();
                
                skipWhites( reader, pos, true );

                String byteCode = getByteCode( pos );
                syntaxChecker.setBytecode( byteCode );
                hasByteCode = true;
            }
            else if ( startsWith( pos, EXTENSION_PREFIX ) )
            {
                processExtension( reader, pos, syntaxChecker );
            }
            else if ( startsWith( reader, pos, RPAREN ) )
            {
                pos.start++;
                break;
            }
            else
            {
                // This is an error
                throw new LdapSchemaException( I18n.err( I18n.ERR_13826_SC_DESCRIPTION_INVALID, 
                    pos.lineNumber, pos.start ) );
            }
        }
        
        // Semantic checks
        if ( !hasFqcn )
        {
            throw new LdapSchemaException( I18n.err( I18n.ERR_13819_FQCN_REQUIRED, 
                pos.lineNumber, pos.start ) );
        }

        if ( ( hasByteCode ) && ( syntaxChecker.getBytecode().length() % 4 != 0 ) )
        {
            throw new LdapSchemaException( I18n.err( I18n.ERR_13820_BYTE_CODE_REQUIRED, 
                pos.lineNumber, pos.start ) );
        }

        return syntaxChecker;
    }

    
    /**
     * Production for SyntaxChecker descriptions. It is fault-tolerant
     * against element ordering.
     *
     * <pre>
     * SyntaxCheckerDescription = LPAREN WSP
     *       numericoid                           ; object identifier
     *       [ SP "DESC" SP qdstring ]            ; description
     *       SP "FQCN" SP fqcn                    ; fully qualified class name
     *       [ SP "BYTECODE" SP base64 ]          ; optional base64 encoded bytecode
     *       extensions WSP RPAREN                ; extensions
     * 
     * base64          = *(4base64-char)
     * base64-char     = ALPHA / DIGIT / "+" / "/"
     * fqcn = fqcnComponent 1*( DOT fqcnComponent )
     * fqcnComponent = ???
     * </pre>
     */
    private static SyntaxCheckerDescription parseSyntaxCheckerRelaxed( Reader reader, PosSchema pos,
        Map<String, OpenLdapObjectIdentifierMacro> objectIdentifierMacros ) 
            throws IOException, LdapSchemaException
    {
        // Get rid of whites, comments end empty lines
        skipWhites( reader, pos, false );
        
        // we must have a '('
        if ( pos.line.charAt( pos.start ) != LPAREN )
        {
            throw new LdapSchemaException( I18n.err( I18n.ERR_13829_NO_OPENING_PAREN, 
                pos.lineNumber, pos.start ) );
        }
        else
        {
            pos.start++;
        }
        
        // Get rid of whites, comments end empty lines
        skipWhites( reader, pos, false );
        
        // Now, the OID. 
        String oid = getOidAndMacroRelaxed( pos, objectIdentifierMacros );
        
        SyntaxCheckerDescription syntaxChecker = new SyntaxCheckerDescription( oid );
        int elementsSeen = 0;
        
        while ( true )
        {
            if ( startsWith( reader, pos, RPAREN ) )
            {
                pos.start++;
                break;
            }
            
            skipWhites( reader, pos, true );

            if ( startsWith( pos, DESC_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, SyntaxCheckerElements.DESC, pos );

                pos.start += DESC_STR.length();
                
                skipWhites( reader, pos, true );

                syntaxChecker.setDescription( getQDString( reader, pos ) );
            }
            else if ( startsWith( pos, FQCN_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, SyntaxCheckerElements.FQCN, pos );

                pos.start += FQCN_STR.length();
                
                skipWhites( reader, pos, true );

                String fqcn = getFqcn( pos );
                syntaxChecker.setFqcn( fqcn );
            }
            else if ( startsWith( pos, BYTECODE_STR ) )
            {
                elementsSeen = checkElement( elementsSeen, SyntaxCheckerElements.BYTECODE, pos );

                pos.start += BYTECODE_STR.length();
                
                skipWhites( reader, pos, true );

                String byteCode = getByteCode( pos );
                syntaxChecker.setBytecode( byteCode );
            }
            else if ( startsWith( pos, EXTENSION_PREFIX ) )
            {
                processExtension( reader, pos, syntaxChecker );
            }
            else if ( startsWith( reader, pos, RPAREN ) )
            {
                pos.start++;
                break;
            }
            else
            {
                // This is an error
                throw new LdapSchemaException( I18n.err( I18n.ERR_13826_SC_DESCRIPTION_INVALID, 
                    pos.lineNumber, pos.start ) );
            }
        }
        
        return syntaxChecker;
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
        String name = getDescrStrict( pos );
        
        OpenLdapObjectIdentifierMacro macro = new OpenLdapObjectIdentifierMacro();
        
        skipWhites( reader, pos, true );

        // Get the descr, if any
        if ( isEmpty( pos ) )
        {
            throw new LdapSchemaException( I18n.err( I18n.ERR_13805_OBJECT_IDENTIFIER_INVALID_OID, 
                pos.lineNumber, pos.start ) );
        }
        
        if ( isAlpha( pos ) )
        {
            // A macro
            String descr = getMacro( pos );
            
            if ( isEmpty( pos ) )
            {
                throw new LdapSchemaException( I18n.err( I18n.ERR_13804_OBJECT_IDENTIFIER_HAS_NO_OID, 
                    pos.lineNumber, pos.start ) );
            }
            
            if ( startsWith( reader, pos, COLON ) )
            {
                pos.start++;
                
                // Now, the OID
                String numericOid = getPartialNumericOid( pos );
                String realOid = objectIdentifierMacros.get( descr ).getRawOidOrNameSuffix() + DOT + numericOid;
                macro.setName( name );
                macro.setRawOidOrNameSuffix( realOid );
                
                objectIdentifierMacros.put( name, macro );
                
                return;
            }
        }
        else if ( isDigit( pos ) )
        {
            // An oid
            String numericOid = getNumericOid( pos );
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
    public void parse( Reader reader ) throws LdapSchemaException, IOException
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
                
                AttributeType attributeType = parseAttributeTypeStrict( reader, pos, objectIdentifierMacros );
                schemaDescriptions.add( attributeType );
            }
            else if ( startsWith( pos, "objectclass" ) )
            {
                pos.start += "objectclass".length();
                
                ObjectClass objectClass = parseObjectClassStrict( reader, pos, objectIdentifierMacros );
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