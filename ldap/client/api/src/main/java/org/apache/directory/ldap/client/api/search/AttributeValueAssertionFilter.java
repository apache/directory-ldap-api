
package org.apache.directory.ldap.client.api.search;


class AttributeValueAssertionFilter extends AbstractFilter
{
    private String attribute;
    private String value;
    private Operator operator;
    
    
    private AttributeValueAssertionFilter( String attribute, String value, Operator operator )
    {
        this.attribute = attribute;
        this.value = value;
        this.operator = operator;
    }
    
    
    public static AttributeValueAssertionFilter approximatelyEqual( String attribute, String value ) 
    {
        return new AttributeValueAssertionFilter( attribute, value, Operator.APPROXIMATELY_EQUAL );
    }
    
    
    public static AttributeValueAssertionFilter equal( String attribute, String value ) 
    {
        return new AttributeValueAssertionFilter( attribute, value, Operator.EQUAL );
    }
    
    
    public static AttributeValueAssertionFilter greaterThanOrEqual( String attribute, String value ) 
    {
        return new AttributeValueAssertionFilter( attribute, value, Operator.GREATER_THAN_OR_EQUAL );
    }
    
    
    public static AttributeValueAssertionFilter lessThanOrEqual( String attribute, String value ) 
    {
        return new AttributeValueAssertionFilter( attribute, value, Operator.LESS_THAN_OR_EQUAL );
    }
    

    @Override
    public StringBuilder build( StringBuilder builder )
    {
        return builder.append( "(" ).append( attribute )
                .append( operator.operator() )
                .append( value ).append( ")" );
    }


    public static enum Operator
    {
        APPROXIMATELY_EQUAL("~="),
        EQUAL("="),
        GREATER_THAN_OR_EQUAL(">="),
        LESS_THAN_OR_EQUAL("<=");
        
        private String operator;
        
        private Operator( String operator ) 
        {
            this.operator = operator;
        }
        
        public String operator() 
        {
            return operator;
        }
    }
}