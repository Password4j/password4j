package org.password4j;

public class BadParametersException extends IllegalArgumentException
{

    private static final long serialVersionUID = 9204720180786210237L;

    public BadParametersException(String message, Throwable exception)
    {
        super(message, exception);
    }
}
