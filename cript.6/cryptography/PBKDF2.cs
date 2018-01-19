using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using cript._6.cryptography;

namespace cript._6.cryptography
{
    class PBKDF2
    {
        public static ulong get(byte[] pass, ulong salt, int c)
        {
            int divRem = pass.Length % 8;
            if (divRem != 0)
            {
                Array.Resize(ref pass, pass.Length + divRem);
            }
            return Feistel.Hash(pass, c, salt);
        }
    }
}
