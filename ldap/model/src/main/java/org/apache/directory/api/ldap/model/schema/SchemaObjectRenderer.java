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
package org.apache.directory.api.ldap.model.schema;


import java.util.List;

import org.apache.directory.api.ldap.model.exception.LdapException;


/**
 * Renderer for schema objects.
 * 
 * Currently the following preconfigured renderers exist: 
 * <ol>
 * <li> {@link SchemaObjectRenderer#SUBSCHEMA_SUBENTRY_RENDERER}: renders the schema object 
 *      without line break and with X-SCHEMA extension. To be used for building subschema subentry.
 * <li> {@link SchemaObjectRenderer#OPEN_LDAP_SCHEMA_RENDERER}: renders the schema object in OpenLDAP schema  
 *      format. That means is starts with schema type and contains line breaks for easier readability.
 * </ol>
 * <p>
 * TODO: currently only {@link ObjectClass} and {@link AttributeType} are supported, implement other schema object types.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class SchemaObjectRenderer
{
    /**
     * Preconfigured {@link SchemaObjectRenderer} that renders the schema object without line break and with
     * X-SCHEMA extension. To be used for building subschema subentry.
     */
    public static final SchemaObjectRenderer SUBSCHEMA_SUBENTRY_RENDERER = new SchemaObjectRenderer(
        Style.SUBSCHEMA_SUBENTRY_WITH_SCHEMA_NAME );

    /**
     * Preconfigured {@link SchemaObjectRenderer} that renders the schema object in OpenLDAP schema format. 
     * That means is starts with schema type and contains line breaks for easier readability.
     */
    public static final SchemaObjectRenderer OPEN_LDAP_SCHEMA_RENDERER = new SchemaObjectRenderer(
        Style.OPENLDAP_SCHEMA_PRETTY_PRINTED );

    private enum Style
    {
        SUBSCHEMA_SUBENTRY_WITH_SCHEMA_NAME(false, false, true),

        OPENLDAP_SCHEMA_PRETTY_PRINTED(true, true, false);

        final boolean startWithSchemaType;
        final boolean prettyPrint;
        final boolean printSchemaName;


        private Style( boolean startWithSchemaType, boolean prettyPrint, boolean printSchemaName )
        {
            this.startWithSchemaType = startWithSchemaType;
            this.prettyPrint = prettyPrint;
            this.printSchemaName = printSchemaName;
        }
    }

    private final Style style;


    private SchemaObjectRenderer( Style style )
    {
        this.style = style;
    }


    /**
     * Renders an objectClass according to the Object Class 
     * Description Syntax 1.3.6.1.4.1.1466.115.121.1.37. The syntax is
     * described in detail within section 4.1.1. of 
     * <a href="https://tools.ietf.org/rfc/rfc4512.txt">RFC 4512</a>
     * which is replicated here for convenience:
     * 
     * <pre>
     *  4.1.1. Object Class Definitions
     * 
     *   Object Class definitions are written according to the ABNF:
     * 
     *     ObjectClassDescription = LPAREN WSP
     *         numericoid                 ; object identifier
     *         [ SP &quot;NAME&quot; SP qdescrs ]   ; short names (descriptors)
     *         [ SP &quot;DESC&quot; SP qdstring ]  ; description
     *         [ SP &quot;OBSOLETE&quot; ]          ; not active
     *         [ SP &quot;SUP&quot; SP oids ]       ; superior object classes
     *         [ SP kind ]                ; kind of class
     *         [ SP &quot;MUST&quot; SP oids ]      ; attribute types
     *         [ SP &quot;MAY&quot; SP oids ]       ; attribute types
     *         extensions WSP RPAREN
     * 
     *     kind = &quot;ABSTRACT&quot; / &quot;STRUCTURAL&quot; / &quot;AUXILIARY&quot;
     * 
     *   where:
     *     &lt;numericoid&gt; is object identifier assigned to this object class;
     *     NAME &lt;qdescrs&gt; are short names (descriptors) identifying this object
     *         class;
     *     DESC &lt;qdstring&gt; is a short descriptive string;
     *     OBSOLETE indicates this object class is not active;
     *     SUP &lt;oids&gt; specifies the direct superclasses of this object class;
     *     the kind of object class is indicated by one of ABSTRACT,
     *         STRUCTURAL, or AUXILIARY, default is STRUCTURAL;
     *     MUST and MAY specify the sets of required and allowed attribute
     *         types, respectively; and
     *     &lt;extensions&gt; describe extensions.
     * </pre>
     * @param oc the ObjectClass to render the description of
     * @return the string form of the Object Class description
     */
    public String render( ObjectClass oc )
    {
        StringBuilder buf = renderStartOidNamesDescObsolete( oc, "objectclass" );

        List<String> superiorOids = oc.getSuperiorOids();

        if ( ( superiorOids != null ) && ( superiorOids.size() > 0 ) )
        {
            prettyPrintIndent( buf );
            buf.append( "SUP " );
            renderOids( buf, superiorOids );
            prettyPrintNewLine( buf );
        }

        if ( oc.getType() != null )
        {
            prettyPrintIndent( buf );
            buf.append( oc.getType() );
            prettyPrintNewLine( buf );
        }

        List<String> must = oc.getMustAttributeTypeOids();

        if ( ( must != null ) && ( must.size() > 0 ) )
        {
            prettyPrintIndent( buf );
            buf.append( "MUST " );
            renderOids( buf, must );
            prettyPrintNewLine( buf );
        }

        List<String> may = oc.getMayAttributeTypeOids();

        if ( ( may != null ) && ( may.size() > 0 ) )
        {
            prettyPrintIndent( buf );
            buf.append( "MAY " );
            renderOids( buf, may );
            prettyPrintNewLine( buf );
        }

        renderXSchemaName( oc, buf );

        // @todo extensions are not presently supported and skipped
        // the extensions would go here before closing off the description

        buf.append( ")" );

        return buf.toString();
    }


    /**
     * Renders an attributeType according to the
     * Attribute Type Description Syntax 1.3.6.1.4.1.1466.115.121.1.3. The
     * syntax is described in detail within section 4.1.2. of 
     * <a href="https://tools.ietf.org/rfc/rfc4512.txt">RFC 4512</a>
     * which is replicated here for convenience:
     * 
     * <pre>
     *  4.1.2. Attribute Types
     * 
     *   Attribute Type definitions are written according to the ABNF:
     * 
     *   AttributeTypeDescription = LPAREN WSP
     *         numericoid                    ; object identifier
     *         [ SP &quot;NAME&quot; SP qdescrs ]      ; short names (descriptors)
     *         [ SP &quot;DESC&quot; SP qdstring ]     ; description
     *         [ SP &quot;OBSOLETE&quot; ]             ; not active
     *         [ SP &quot;SUP&quot; SP oid ]           ; supertype
     *         [ SP &quot;EQUALITY&quot; SP oid ]      ; equality matching rule
     *         [ SP &quot;ORDERING&quot; SP oid ]      ; ordering matching rule
     *         [ SP &quot;SUBSTR&quot; SP oid ]        ; substrings matching rule
     *         [ SP &quot;SYNTAX&quot; SP noidlen ]    ; value syntax
     *         [ SP &quot;SINGLE-VALUE&quot; ]         ; single-value
     *         [ SP &quot;COLLECTIVE&quot; ]           ; collective
     *         [ SP &quot;NO-USER-MODIFICATION&quot; ] ; not user modifiable
     *         [ SP &quot;USAGE&quot; SP usage ]       ; usage
     *         extensions WSP RPAREN         ; extensions
     * 
     *     usage = &quot;userApplications&quot;     /  ; user
     *             &quot;directoryOperation&quot;   /  ; directory operational
     *             &quot;distributedOperation&quot; /  ; DSA-shared operational
     *             &quot;dSAOperation&quot;            ; DSA-specific operational
     * 
     *   where:
     *     &lt;numericoid&gt; is object identifier assigned to this attribute type;
     *     NAME &lt;qdescrs&gt; are short names (descriptors) identifying this
     *         attribute type;
     *     DESC &lt;qdstring&gt; is a short descriptive string;
     *     OBSOLETE indicates this attribute type is not active;
     *     SUP oid specifies the direct supertype of this type;
     *     EQUALITY, ORDERING, SUBSTR provide the oid of the equality,
     *         ordering, and substrings matching rules, respectively;
     *     SYNTAX identifies value syntax by object identifier and may suggest
     *         a minimum upper bound;
     *     SINGLE-VALUE indicates attributes of this type are restricted to a
     *         single value;
     *     COLLECTIVE indicates this attribute type is collective
     *         [X.501][RFC3671];
     *     NO-USER-MODIFICATION indicates this attribute type is not user
     *         modifiable;
     *     USAGE indicates the application of this attribute type; and
     *     &lt;extensions&gt; describe extensions.
     * </pre>
     * @param at the AttributeType to render the description for
     * @return the StringBuffer containing the rendered attributeType description
     * @throws LdapException if there are problems accessing the objects
     * associated with the attribute type.
     */
    public String render( AttributeType at )
    {
        StringBuilder buf = renderStartOidNamesDescObsolete( at, "attributetype" );

        /*
         *  TODO: Check for getSuperior(), getEquality(), getOrdering(), and getSubstring() should not be necessary. 
         *  The getXyzOid() methods should return a name but return a numeric OID currently.
         */

        if ( at.getSuperior() != null )
        {
            prettyPrintIndent( buf );
            buf.append( "SUP " ).append( at.getSuperior().getName() );
            prettyPrintNewLine( buf );
        }
        else if ( at.getSuperiorOid() != null )
        {
            prettyPrintIndent( buf );
            buf.append( "SUP " ).append( at.getSuperiorOid() );
            prettyPrintNewLine( buf );
        }

        if ( at.getEquality() != null )
        {
            prettyPrintIndent( buf );
            buf.append( "EQUALITY " ).append( at.getEquality().getName() );
            prettyPrintNewLine( buf );
        }
        else if ( at.getEqualityOid() != null )
        {
            prettyPrintIndent( buf );
            buf.append( "EQUALITY " ).append( at.getEqualityOid() );
            prettyPrintNewLine( buf );
        }

        if ( at.getOrdering() != null )
        {
            prettyPrintIndent( buf );
            buf.append( "ORDERING " ).append( at.getOrdering().getName() );
            prettyPrintNewLine( buf );
        }
        else if ( at.getOrderingOid() != null )
        {
            prettyPrintIndent( buf );
            buf.append( "ORDERING " ).append( at.getOrderingOid() );
            prettyPrintNewLine( buf );
        }

        if ( at.getSubstring() != null )
        {
            prettyPrintIndent( buf );
            buf.append( "SUBSTR " ).append( at.getSubstring().getName() );
            prettyPrintNewLine( buf );
        }
        else if ( at.getSubstringOid() != null )
        {
            prettyPrintIndent( buf );
            buf.append( "SUBSTR " ).append( at.getSubstringOid() );
            prettyPrintNewLine( buf );
        }

        if ( at.getSyntaxOid() != null )
        {
            prettyPrintIndent( buf );
            buf.append( "SYNTAX " ).append( at.getSyntaxOid() );

            if ( at.getSyntaxLength() > 0 )
            {
                buf.append( "{" ).append( at.getSyntaxLength() ).append( "}" );
            }
            prettyPrintNewLine( buf );
        }

        if ( at.isSingleValued() )
        {
            prettyPrintIndent( buf );
            buf.append( "SINGLE-VALUE" );
            prettyPrintNewLine( buf );
        }

        if ( at.isCollective() )
        {
            prettyPrintIndent( buf );
            buf.append( "COLLECTIVE" );
            prettyPrintNewLine( buf );
        }

        if ( !at.isUserModifiable() )
        {
            prettyPrintIndent( buf );
            buf.append( "NO-USER-MODIFICATION" );
            prettyPrintNewLine( buf );
        }

        if ( at.getUsage() != null )
        {
            prettyPrintIndent( buf );
            buf.append( "USAGE " ).append( UsageEnum.render( at.getUsage() ) );
            prettyPrintNewLine( buf );
        }

        renderXSchemaName( at, buf );

        // @todo extensions are not presently supported and skipped
        // the extensions would go here before closing off the description

        buf.append( ")" );

        return buf.toString();
    }


    private StringBuilder renderStartOidNamesDescObsolete( SchemaObject so, String schemaObjectType )
    {
        StringBuilder buf = new StringBuilder();

        if ( style.startWithSchemaType )
        {
            buf.append( schemaObjectType ).append( ' ' );
        }

        buf.append( "( " ).append( so.getOid() );

        List<String> names = so.getNames();

        if ( ( names != null ) && ( names.size() > 0 ) )
        {
            buf.append( " NAME " );
            renderQDescrs( buf, names );
            prettyPrintNewLine( buf );
        }
        else
        {
            prettyPrintNewLine( buf );
        }

        if ( so.getDescription() != null )
        {
            prettyPrintIndent( buf );
            buf.append( "DESC " );
            renderQDString( buf, so.getDescription() );
            prettyPrintNewLine( buf );
        }

        if ( so.isObsolete() )
        {
            prettyPrintIndent( buf );
            buf.append( "OBSOLETE" );
            prettyPrintNewLine( buf );
        }
        return buf;
    }


    private void prettyPrintNewLine( StringBuilder buf )
    {
        if ( style.prettyPrint )
        {
            buf.append( '\n' );
        }
        else
        {
            buf.append( " " );
        }
    }


    private void prettyPrintIndent( StringBuilder buf )
    {
        if ( style.prettyPrint )
        {
            buf.append( "\t" );
        }
    }


    /**
     * Renders qdescrs into a new buffer.<br>
     * <pre>
     * descrs ::= qdescr | '(' WSP qdescrlist WSP ')'
     * qdescrlist ::= [ qdescr ( SP qdescr )* ]
     * qdescr     ::= SQUOTE descr SQUOTE
     * </pre>
     * @param qdescrs the quoted description strings to render
     * @return the string buffer the qdescrs are rendered into
     */
    private StringBuilder renderQDescrs( StringBuilder buf, List<String> qdescrs )
    {
        if ( ( qdescrs == null ) || ( qdescrs.size() == 0 ) )
        {
            return buf;
        }

        if ( qdescrs.size() == 1 )
        {
            buf.append( '\'' ).append( qdescrs.get( 0 ) ).append( '\'' );
        }
        else
        {
            buf.append( "( " );

            for ( String qdescr : qdescrs )
            {
                buf.append( '\'' ).append( qdescr ).append( "' " );
            }

            buf.append( ")" );
        }

        return buf;
    }


    /**
     * Renders oids into a new buffer.<br>
     * <pre>
     * oids    ::= oid | '(' WSP oidlist WSP ')'
     * oidlist ::= oid ( WSP '$' WSP oid )*
     * </pre>
     * 
     * @param qdescrs the quoted description strings to render
     * @return the string buffer the qdescrs are rendered into
     */
    private StringBuilder renderOids( StringBuilder buf, List<String> oids )
    {
        if ( oids.size() == 1 )
        {
            buf.append( oids.get( 0 ) );
        }
        else
        {
            buf.append( "( " );

            boolean isFirst = true;

            for ( String oid : oids )
            {
                if ( isFirst )
                {
                    isFirst = false;
                }
                else
                {
                    buf.append( " $ " );
                }

                buf.append( oid );
            }

            buf.append( " )" );
        }

        return buf;
    }


    /**
     * Renders QDString into a new buffer.<br>
     * 
     * @param qdescrs the quoted description strings to render
     * @return the string buffer the qdescrs are rendered into
     */
    private StringBuilder renderQDString( StringBuilder buf, String qdString )
    {
        buf.append( '\'' );

        for ( char c : qdString.toCharArray() )
        {
            switch ( c )
            {
                case 0x27:
                    buf.append( "\\27" );
                    break;

                case 0x5C:
                    buf.append( "\\5C" );
                    break;

                default:
                    buf.append( c );
                    break;
            }
        }

        buf.append( '\'' );

        return buf;
    }


    private void renderXSchemaName( SchemaObject oc, StringBuilder buf )
    {
        if ( style.printSchemaName )
        {
            prettyPrintIndent( buf );
            buf.append( "X-SCHEMA '" );
            buf.append( oc.getSchemaName() );
            buf.append( "'" );
            prettyPrintNewLine( buf );
        }
    }
}
