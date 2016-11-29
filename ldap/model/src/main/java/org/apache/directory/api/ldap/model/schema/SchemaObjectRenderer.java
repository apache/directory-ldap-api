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
public final class SchemaObjectRenderer
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


        Style( boolean startWithSchemaType, boolean prettyPrint, boolean printSchemaName )
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

        renderOids( buf, "SUP", oc.getSuperiorOids() );

        if ( oc.getType() != null )
        {
            prettyPrintIndent( buf );
            buf.append( oc.getType() );
            prettyPrintNewLine( buf );
        }

        renderOids( buf, "MUST", oc.getMustAttributeTypeOids() );

        renderOids( buf, "MAY", oc.getMayAttributeTypeOids() );

        renderXSchemaName( oc, buf );

        // @todo extensions are not presently supported and skipped
        // the extensions would go here before closing off the description

        renderClose( buf );

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

        renderClose( buf );

        return buf.toString();
    }


    /**
     * Renders an matchingRule according to the
     * MatchingRule Description Syntax 1.3.6.1.4.1.1466.115.121.1.30. The syntax
     * is described in detail within section 4.1.3. 
     * <a href="https://tools.ietf.org/rfc/rfc4512.txt">RFC 4512</a>
     * which is replicated here for convenience:
     * 
     * <pre>
     *  4.1.3. Matching Rules
     * 
     *   Matching rules are used in performance of attribute value assertions,
     *   such as in performance of a Compare operation.  They are also used in
     *   evaluation of a Search filters, in determining which individual values
     *   are be added or deleted during performance of a Modify operation, and
     *   used in comparison of distinguished names.
     * 
     *   Each matching rule is identified by an object identifier (OID) and,
     *   optionally, one or more short names (descriptors).
     * 
     *   Matching rule definitions are written according to the ABNF:
     * 
     *   MatchingRuleDescription = LPAREN WSP
     *        numericoid                 ; object identifier
     *         [ SP &quot;NAME&quot; SP qdescrs ]   ; short names (descriptors)
     *         [ SP &quot;DESC&quot; SP qdstring ]  ; description
     *         [ SP &quot;OBSOLETE&quot; ]          ; not active
     *         SP &quot;SYNTAX&quot; SP numericoid  ; assertion syntax
     *         extensions WSP RPAREN      ; extensions
     * 
     *   where:
     *     &lt;numericoid&gt; is object identifier assigned to this matching rule;
     *     NAME &lt;qdescrs&gt; are short names (descriptors) identifying this
     *         matching rule;
     *     DESC &lt;qdstring&gt; is a short descriptive string;
     *     OBSOLETE indicates this matching rule is not active;
     *     SYNTAX identifies the assertion syntax (the syntax of the assertion
     *         value) by object identifier; and
     *     &lt;extensions&gt; describe extensions.
     * </pre>
     * @param mr the MatchingRule to render the description for
     * @return the StringBuffer containing the rendered matchingRule description
     */
    public String render( MatchingRule mr )
    {
        StringBuilder buf = renderStartOidNamesDescObsolete( mr, "matchingrule" );

        prettyPrintIndent( buf );
        buf.append( "SYNTAX " ).append( mr.getSyntaxOid() );
        prettyPrintNewLine( buf );

        renderXSchemaName( mr, buf );

        // @todo extensions are not presently supported and skipped
        // the extensions would go here before closing off the description

        renderClose( buf );

        return buf.toString();
    }


    /**
     * Renders a Syntax according to the LDAP Syntax
     * Description Syntax 1.3.6.1.4.1.1466.115.121.1.54. The syntax is described
     * in detail within section 4.1.5. of 
     * <a href="https://tools.ietf.org/rfc/rfc4512.txt">RFC 4512</a>
     * which is replicated here for convenience:
     * 
     * <pre>
     *  LDAP syntax definitions are written according to the ABNF:
     * 
     *   SyntaxDescription = LPAREN WSP
     *       numericoid                 ; object identifier
     *       [ SP &quot;DESC&quot; SP qdstring ]  ; description
     *       extensions WSP RPAREN      ; extensions
     * 
     *  where:
     *   &lt;numericoid&gt; is the object identifier assigned to this LDAP syntax;
     *   DESC &lt;qdstring&gt; is a short descriptive string; and
     *   &lt;extensions&gt; describe extensions.
     * </pre>
     * @param syntax the Syntax to render the description for
     * @return the StringBuffer containing the rendered syntax description
     */
    public String render( LdapSyntax syntax )
    {
        StringBuilder buf = new StringBuilder();

        if ( style.startWithSchemaType )
        {
            buf.append( "ldapsyntax " );
        }

        buf.append( "( " ).append( syntax.getOid() );
        prettyPrintNewLine( buf );

        renderDescription( syntax, buf );

        renderXSchemaName( syntax, buf );

        prettyPrintIndent( buf );
        if ( syntax.isHumanReadable() )
        {
            buf.append( "X-NOT-HUMAN-READABLE 'false'" );
        }
        else
        {
            buf.append( "X-NOT-HUMAN-READABLE 'true'" );
        }
        prettyPrintNewLine( buf );

        // @todo extensions are not presently supported and skipped
        // the extensions would go here before closing off the description

        renderClose( buf );

        return buf.toString();
    }


    /**
     * NOT FULLY IMPLEMENTED!
     * Renders a MatchingRuleUse as a String
     * 
     * @param mru The MatchingRuleUse to render
     * @return The MatchingRuleUse as a String
     */
    public String render( MatchingRuleUse mru )
    {
        StringBuilder buf = renderStartOidNamesDescObsolete( mru, "matchingruleuse" );

        List<String> applies = mru.getApplicableAttributeOids();

        if ( ( applies != null ) && !applies.isEmpty() )
        {
            prettyPrintIndent( buf );
            buf.append( "APPLIES " );
            renderOids( buf, applies );
            prettyPrintNewLine( buf );
        }

        renderXSchemaName( mru, buf );

        // @todo extensions are not presently supported and skipped
        // the extensions would go here before closing off the description

        renderClose( buf );

        return buf.toString();
    }


    /**
     * NOT FULLY IMPLEMENTED!
     * Renders a DitContentRule as a String
     * 
     * @param dcr The DitContentRule to render
     * @return The DitContentRule as a String
     */
    public String render( DitContentRule dcr )
    {
        StringBuilder buf = renderStartOidNamesDescObsolete( dcr, "ditcontentrule" );

        renderOids( buf, "AUX", dcr.getAuxObjectClassOids() );

        renderOids( buf, "MUST", dcr.getMustAttributeTypeOids() );

        renderOids( buf, "MAY", dcr.getMayAttributeTypeOids() );

        renderOids( buf, "NOT", dcr.getNotAttributeTypeOids() );

        renderXSchemaName( dcr, buf );

        // @todo extensions are not presently supported and skipped
        // the extensions would go here before closing off the description

        renderClose( buf );

        return buf.toString();
    }


    /**
     * NOT FULLY IMPLEMENTED!
     * 
     * @param dsr The DitStructureRule to render
     * @return The DitStructureRule as a String
     */
    public String render( DitStructureRule dsr )
    {
        StringBuilder buf = new StringBuilder();

        if ( style.startWithSchemaType )
        {
            buf.append( "ditstructurerule " );
        }

        buf.append( "( " ).append( dsr.getRuleId() );

        renderNames( dsr, buf );

        renderDescription( dsr, buf );

        renderObsolete( dsr, buf );

        prettyPrintIndent( buf );
        buf.append( "FORM " ).append( dsr.getForm() );
        prettyPrintNewLine( buf );

        renderRuleIds( buf, dsr.getSuperRules() );

        renderXSchemaName( dsr, buf );

        // @todo extensions are not presently supported and skipped
        // the extensions would go here before closing off the description

        renderClose( buf );

        return buf.toString();
    }


    /**
     * NOT FULLY IMPLEMENTED!
     * Render a NameForm as a String
     * 
     * @param nf The NameForm to render
     * @return The rendered String
     */
    public String render( NameForm nf )
    {
        StringBuilder buf = renderStartOidNamesDescObsolete( nf, "nameform" );

        prettyPrintIndent( buf );
        buf.append( "OC " ).append( nf.getStructuralObjectClassOid() );
        prettyPrintNewLine( buf );

        renderOids( buf, "MUST", nf.getMustAttributeTypeOids() );

        renderOids( buf, "MAY", nf.getMayAttributeTypeOids() );

        renderXSchemaName( nf, buf );

        renderClose( buf );

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

        renderNames( so, buf );

        renderDescription( so, buf );

        renderObsolete( so, buf );
        return buf;
    }


    private void renderNames( SchemaObject so, StringBuilder buf )
    {
        List<String> names = so.getNames();

        if ( ( names != null ) && !names.isEmpty() )
        {
            buf.append( " NAME " );
            renderQDescrs( buf, names );
            prettyPrintNewLine( buf );
        }
        else
        {
            prettyPrintNewLine( buf );
        }
    }


    private void renderDescription( SchemaObject so, StringBuilder buf )
    {
        if ( so.getDescription() != null )
        {
            prettyPrintIndent( buf );
            buf.append( "DESC " );
            renderQDString( buf, so.getDescription() );
            prettyPrintNewLine( buf );
        }
    }


    private void renderObsolete( SchemaObject so, StringBuilder buf )
    {
        if ( so.isObsolete() )
        {
            prettyPrintIndent( buf );
            buf.append( "OBSOLETE" );
            prettyPrintNewLine( buf );
        }
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
        if ( ( qdescrs == null ) || qdescrs.isEmpty() )
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


    private void renderOids( StringBuilder buf, String prefix, List<String> oids )
    {
        if ( ( oids != null ) && !oids.isEmpty() )
        {
            prettyPrintIndent( buf );
            buf.append( prefix ).append( ' ' );
            renderOids( buf, oids );
            prettyPrintNewLine( buf );
        }
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


    private StringBuilder renderRuleIds( StringBuilder buf, List<Integer> ruleIds )
    {
        if ( ( ruleIds != null ) && !ruleIds.isEmpty() )
        {
            prettyPrintIndent( buf );
            buf.append( "SUP " );

            if ( ruleIds.size() == 1 )
            {
                buf.append( ruleIds.get( 0 ) );
            }
            else
            {
                buf.append( "( " );

                boolean isFirst = true;

                for ( Integer ruleId : ruleIds )
                {
                    if ( isFirst )
                    {
                        isFirst = false;
                    }
                    else
                    {
                        buf.append( " " );
                    }

                    buf.append( ruleId );
                }

                buf.append( " )" );
            }

            prettyPrintNewLine( buf );
        }

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


    private void renderClose( StringBuilder buf )
    {
        if ( ( style.prettyPrint ) &&  ( buf.charAt( buf.length() - 1 ) == '\n' ) )
        {
            buf.deleteCharAt( buf.length() - 1 );
            buf.append( " " );
        }
    
        buf.append( ")" );
    }

}
