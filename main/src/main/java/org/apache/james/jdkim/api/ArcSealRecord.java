package org.apache.james.jdkim.api;

public interface ArcSealRecord
{
    CharSequence getInstance();

    CharSequence getCv();

    CharSequence getHashAlgo();

    CharSequence getDToken();

    CharSequence getSelector();

    byte[] getSignature();

    CharSequence getRawSignature();

    Long getSignatureTimestamp();

    void validate();
}
