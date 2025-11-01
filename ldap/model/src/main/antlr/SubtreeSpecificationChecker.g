header
{
/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *  
 *    https://www.apache.org/licenses/LICENSE-2.0
 *  
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License. 
 *  
 */


package org.apache.directory.api.ldap.model.subtree;

import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.filter.ExprNode;
import org.apache.directory.api.ldap.model.filter.LeafNode;
import org.apache.directory.api.ldap.model.filter.BranchNode;
import org.apache.directory.api.ldap.model.filter.AndNode;
import org.apache.directory.api.ldap.model.filter.OrNode;
import org.apache.directory.api.ldap.model.filter.NotNode;
import org.apache.directory.api.ldap.model.filter.EqualityNode;
import org.apache.directory.api.ldap.model.filter.FilterParser;
import org.apache.directory.api.util.ComponentsMonitor;
import org.apache.directory.api.util.OptionalComponentsMonitor;
import org.apache.directory.api.ldap.model.schema.SchemaManager;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
}


// ----------------------------------------------------------------------------
// parser class definition
// ----------------------------------------------------------------------------

/**
 * The antlr generated subtree specification parser.
 *
 * @see <a href="http://www.faqs.org/rfcs/rfc3672.html">RFC 3672</a>
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
class AntlrSubtreeSpecificationChecker extends Parser;


// ----------------------------------------------------------------------------
// parser options
// ----------------------------------------------------------------------------

options
{
    k = 1;
    defaultErrorHandler = false;
}


// ----------------------------------------------------------------------------
// parser initialization
// ----------------------------------------------------------------------------

{
    private static final Logger LOG = LoggerFactory.getLogger( AntlrSubtreeSpecificationChecker.class );
    
    private ComponentsMonitor subtreeSpecificationComponentsMonitor = null;
    
    /** The SchemaManager */
    private SchemaManager schemaManager;

    /**
     * Initialize the checker
     *
     * @param schemaManager the SchemaManager instance
     */
    public void init( SchemaManager schemaManager )
    {
        this.schemaManager = schemaManager;
    }
    

    private int token2Integer( Token token ) throws RecognitionException
    {
        int i = 0;
        
        try
        {
            i = Integer.parseInt( token.getText());
        }
        catch ( NumberFormatException e )
        {
            throw new RecognitionException( I18n.err( I18n.ERR_13900_INTEGER_TOKEN_NOT_INTEGER, token.getText() ) );
        }
        
        return i;
    }
}


// ----------------------------------------------------------------------------
// parser productions
// ----------------------------------------------------------------------------

wrapperEntryPoint
{
    LOG.debug( "entered wrapperEntryPoint()" );
} :
    subtreeSpecification "end"
    ;

subtreeSpecification
{
    LOG.debug( "entered subtreeSpecification()" );
    subtreeSpecificationComponentsMonitor = new OptionalComponentsMonitor( 
            new String [] { "base", "specificExclusions", "minimum", "maximum", "specificationFilter" } );
}
    :
    OPEN_CURLY ( SP )*
        ( subtreeSpecificationComponent ( SP )*
            ( SEP ( SP )* subtreeSpecificationComponent ( SP )* )* )?
    CLOSE_CURLY
    ;

subtreeSpecificationComponent
{
    LOG.debug( "entered subtreeSpecification()" );
}
    :
    ss_base
    {
        subtreeSpecificationComponentsMonitor.useComponent( "base" );
    }
    | ss_specificExclusions
    {
        subtreeSpecificationComponentsMonitor.useComponent( "specificExclusions" );
    }
    | ss_minimum
    {
        subtreeSpecificationComponentsMonitor.useComponent( "minimum" );
    }
    | ss_maximum
    {
        subtreeSpecificationComponentsMonitor.useComponent( "maximum" );
    }
    | ss_specificationFilter
    {
        subtreeSpecificationComponentsMonitor.useComponent( "specificationFilter" );
    }
    ;
    exception
    catch [IllegalArgumentException e]
    {
        throw new RecognitionException( I18n.err( I18n.ERR_13901_MESSAGE, e.getMessage() ) );
    }

ss_base
{
    LOG.debug( "entered ss_base()" );
}
    :
    ID_base ( SP )+ distinguishedName
    ;

ss_specificExclusions
{
    LOG.debug( "entered ss_specificExclusions()" );
}
    :
    ID_specificExclusions ( SP )+ specificExclusions
    ;

specificExclusions
{
    LOG.debug( "entered specificExclusions()" );
}
    :
    OPEN_CURLY ( SP )*
        ( specificExclusion ( SP )*
            ( SEP ( SP )* specificExclusion ( SP )* )*
        )?
    CLOSE_CURLY
    ;

specificExclusion
{
    LOG.debug( "entered specificExclusion()" );
}
    :
    chopBefore | chopAfter
    ;

chopBefore
{
    LOG.debug( "entered chopBefore()" );
}
    :
    ID_chopBefore ( SP )* COLON ( SP )* distinguishedName
    ;

chopAfter
{
    LOG.debug( "entered chopAfter()" );
}
    :
    ID_chopAfter ( SP )* COLON ( SP )* distinguishedName
    ;

ss_minimum
{
    LOG.debug( "entered ss_minimum()" );
}
    :
    ID_minimum ( SP )+ baseDistance
    ;

ss_maximum
{
    LOG.debug( "entered ss_maximum()" );
}
    :
    ID_maximum ( SP )+ baseDistance
    ;

ss_specificationFilter
{
    LOG.debug( "entered ss_specificationFilter()" );
}
    :
    ID_specificationFilter 
    ( SP )+ 
    (
        ( refinement )
        |
        ( filter )
    )
    ;
    
filter
{
    LOG.debug( "entered filter()" );
}
    :
    ( filterToken:FILTER { FilterParser.parse( filterToken.getText() ); } )
    ;
    exception
    catch [Exception e]
    {
        throw new RecognitionException( I18n.err( I18n.ERR_13902_FILTER_PARSER_FAILED, e.getMessage() ) );
    }

    
distinguishedName
{
    LOG.debug( "entered distinguishedName()" );
}
    :
    token:SAFEUTF8STRING
    {
        new Dn( token.getText() );
        LOG.debug( "recognized a DistinguishedName: " + token.getText() );
    }
    ;
    exception
    catch [Exception e]
    {
        throw new RecognitionException( I18n.err( I18n.ERR_13903_DN_PARSER_FAILED, token.getText(), e.getMessage() ) );
    }

baseDistance
{
    LOG.debug( "entered baseDistance()" );
}
    :
    token:INTEGER
    {
        token2Integer(token);
    }
    ;

oid
{
    LOG.debug( "entered oid()" );
     Token token = null;
}
    :
    { token = LT( 1 ); } // an interesting trick goes here ;-)
    ( DESCR | NUMERICOID )
    {
        LOG.debug( "recognized an oid: " + token.getText() );
    }
    ;

refinement
{
    LOG.debug( "entered refinement()" );
}
    :
    item | and | or | not
    ;

item
{
    LOG.debug( "entered item()" );
}
    :
    ID_item ( SP )* COLON ( SP )* oid
    ;

and
{
    LOG.debug( "entered and()" );
}
    :
    ID_and ( SP )* COLON ( SP )* refinements
    ;

or
{
    LOG.debug( "entered or()" );
}
    :
    ID_or ( SP )* COLON ( SP )* refinements
    ;

not
{
    LOG.debug( "entered not()" );
}
    :
    ID_not ( SP )* COLON ( SP )* refinement
    ;

refinements
{
    LOG.debug( "entered refinements()" );
}
    :
    OPEN_CURLY ( SP )*
    (
        refinement ( SP )*
            ( SEP ( SP )* refinement ( SP )* )*
    )? CLOSE_CURLY
    ;


// ----------------------------------------------------------------------------
// lexer class definition
// ----------------------------------------------------------------------------

/**
 * The parser's primary lexer.
 *
 * @see <a href="http://www.faqs.org/rfcs/rfc3672.html">RFC 3672</a>
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
class AntlrSubtreeSpecificationCheckerLexer extends Lexer;


// ----------------------------------------------------------------------------
// lexer options
// ----------------------------------------------------------------------------

options
{
    k = 2;

    charVocabulary = '\u0001'..'\u0127';
}

tokens
{
    ID_base = "base";
    ID_specificExclusions = "specificExclusions";
    ID_chopBefore = "chopBefore";
    ID_chopAfter = "chopAfter";
    ID_minimum = "minimum";
    ID_maximum = "maximum";
    ID_specificationFilter = "specificationFilter";
    ID_item = "item";
    ID_and = "and";
    ID_or = "or";
    ID_not = "not";
}


//----------------------------------------------------------------------------
// lexer initialization
//----------------------------------------------------------------------------

{
    private static final Logger LOG = LoggerFactory.getLogger( AntlrSubtreeSpecificationCheckerLexer.class );
}


// ----------------------------------------------------------------------------
// attribute description lexer rules from models
// ----------------------------------------------------------------------------

SP : ' ';

COLON : ':' { LOG.debug( "matched COLON(':')" ); } ;

OPEN_CURLY : '{' { LOG.debug( "matched LBRACKET('{')" ); } ;

CLOSE_CURLY : '}' { LOG.debug( "matched RBRACKET('}')" ); } ;

SEP : ',' { LOG.debug( "matched SEP(',')" ); } ;

SAFEUTF8STRING : '"'! ( SAFEUTF8CHAR )* '"'! { LOG.debug( "matched SAFEUTF8CHAR: \"" + getText() + "\"" ); } ;

DESCR : ALPHA ( ALPHA | DIGIT | '-' )* { LOG.debug( "matched DESCR" ); } ;

INTEGER_OR_NUMERICOID
    :
    ( INTEGER DOT ) => NUMERICOID
    {
        $setType( NUMERICOID );
    }
    |
    INTEGER
    {
        $setType( INTEGER );
    }
    ;

protected INTEGER: DIGIT | ( LDIGIT ( DIGIT )+ ) { LOG.debug( "matched INTEGER: " + getText() ); } ;

protected NUMERICOID: INTEGER ( DOT INTEGER )+ { LOG.debug( "matched NUMERICOID: " + getText() ); } ;

protected DOT: '.' ;

protected DIGIT: '0' | LDIGIT ;

protected LDIGIT: '1'..'9' ;

protected ALPHA: 'A'..'Z' | 'a'..'z' ;

// This is all messed up - could not figure out how to get antlr to represent
// the safe UTF-8 character set from RFC 3642 for production SafeUTF8Character

protected SAFEUTF8CHAR:
    '\u0001'..'\u0021' |
    '\u0023'..'\u007F' |
    '\u00c0'..'\u00d6' |
    '\u00d8'..'\u00f6' |
    '\u00f8'..'\u00ff' |
    '\u0100'..'\u1fff' |
    '\u3040'..'\u318f' |
    '\u3300'..'\u337f' |
    '\u3400'..'\u3d2d' |
    '\u4e00'..'\u9fff' |
    '\uf900'..'\ufaff' ;

FILTER : '(' ( ( '&' (SP)* (FILTER)+ ) | ( '|' (SP)* (FILTER)+ ) | ( '!' (SP)* FILTER ) | FILTER_VALUE ) ')' (SP)* ;

protected FILTER_VALUE : (options{greedy=true;}: ~( ')' | '(' | '&' | '|' | '!' ) ( ~(')') )* ) ;
    
