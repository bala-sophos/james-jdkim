package org.apache.james.jdkim.tagvalue;

import static org.apache.james.jdkim.parser.DKIMQuotedPrintable.dkimQuotedPrintableDecode;

public class ArcMessageSignatureRecordImpl
    extends SignatureRecordImpl
{

    public ArcMessageSignatureRecordImpl(String data)
    {
        super(data);
    }

    @Override
    protected void init() {
        super.init();
        mandatoryTags.remove("v");
    }

    @Override
    public CharSequence getIdentity() {
        return dkimQuotedPrintableDecode("@" + getDToken());
    }
}
