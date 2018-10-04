namespace ncryptf
{
    internal class Internal
    {
        /// <summary>
        /// Constant time byte[] comparison since Sodium.Core does not provide this implementation
        /// </summary>
        /// <param name="a">byte[] a</param>
        /// <param name="b">byte[] a</param>
        /// <returns>Boolean</returns>
        internal static bool memcmp(byte[] a, byte[] b)
        {
            uint diff = (uint)a.Length ^ (uint)b.Length;
            for (int i = 0; i < a.Length && i < b.Length; i++) {
                diff |= (uint)(a[i] ^ b[i]);
            }
            return diff == 0;
        } 
    }
}