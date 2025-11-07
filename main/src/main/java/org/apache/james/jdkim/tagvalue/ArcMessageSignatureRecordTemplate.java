package org.apache.james.jdkim.tagvalue;

import static org.apache.james.jdkim.parser.DKIMQuotedPrintable.dkimQuotedPrintableDecode;

public class ArcMessageSignatureRecordTemplate extends SignatureRecordTemplate
{

    public ArcMessageSignatureRecordTemplate(String data)
    {
        super(data);
    }

    @Override
    protected void init() {
        super.init();
        mandatoryTags.remove("v");

        //defaults.put("v", "1");
    }

    @Override
    public CharSequence getIdentity() {
        return dkimQuotedPrintableDecode("@" + getDToken());
    }
}
