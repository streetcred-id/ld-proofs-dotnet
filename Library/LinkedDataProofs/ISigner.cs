namespace LinkedDataProofs
{
    public interface ISigner
    {
        byte[] Sign(IVerifyData input);

        bool Verify(byte[] signature, IVerifyData input);
    }
}
