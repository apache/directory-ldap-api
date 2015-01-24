package org.apache.directory.ldap.client.api.search;


class AttributeFilter extends AbstractFilter
{
    private String attribute;
    private Operator operator;


    private AttributeFilter( String attribute, Operator operator )
    {
        this.attribute = attribute;
        this.operator = operator;
    }


    public static AttributeFilter present( String attribute )
    {
        return new AttributeFilter( attribute, Operator.PRESENT );
    }


    @Override
    public StringBuilder build( StringBuilder builder )
    {
        return builder.append( "(" ).append( attribute )
            .append( operator.operator() ).append( ")" );
    }

    public static enum Operator
    {
        PRESENT("=*");

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