package org.apache.james.jdkim.tagvalue;

import org.apache.james.jdkim.api.ArcSealRecord;
import org.apache.james.jdkim.api.SignatureRecord;

public class ArcSealSignatureRecordImpl extends SignatureRecordImpl
    implements ArcSealRecord
{

    public ArcSealSignatureRecordImpl(String data)
    {
        super(data);
        validate();
    }

    @Override
    protected void init() {
        mandatoryTags.add("i");
        mandatoryTags.add("s");
        mandatoryTags.add("d");
        mandatoryTags.add("b");
        mandatoryTags.add("cv");
        mandatoryTags.add("a");


        defaults.put("q", "dns/txt");
    }

    @Override
    public void validate() throws IllegalStateException {
        // check mandatory fields
        for (String tag : mandatoryTags) {
            if (getValue(tag) == null)
                throw new IllegalStateException("Missing mandatory tag: " + tag);
        }

        if (containsTag("h"))
        {
            throw new IllegalStateException("Invalid ARC-Seal: contains header tag");
        }
    }
    @Override
    public CharSequence getInstance()
    {
        return getValue("i");
    }

    @Override
    public CharSequence getCv()
    {
        return getValue("cv");
    }

    @Override
    public CharSequence getHashAlgo()
    {
        return super.getHashAlgo();
    }

    @Override
    public CharSequence getDToken()
    {
        return super.getDToken();
    }

    @Override
    public CharSequence getSelector()
    {
        return super.getSelector();
    }

    @Override
    public byte[] getSignature()
    {
        return super.getSignature();
    }

    @Override
    public CharSequence getRawSignature()
    {
        return super.getRawSignature();
    }

    @Override
    public Long getSignatureTimestamp()
    {
        return super.getSignatureTimestamp();
    }

    @Override
    public CharSequence getIdentity()
    {
        return "@" + getDToken();
    }
}
