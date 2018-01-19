using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using cript._6.cryptography;
using cript._6.steganography;
using System.Drawing;

namespace cript._6
{
    class UI
    {
        public UI() { }
        
        public Bitmap Fill(Bitmap container, byte[] mess)
        {
            return LSB.Fill(container, mess);
        }

        public byte[] Encript(byte[] mess, int n, ulong key)
        {
            return Feistel.Encript(mess, n, key);
        }

        public Bitmap EncriptAndFill(Bitmap container, byte[] mess, int n, ulong key)
        {
            return LSB.Fill(container, Feistel.Encript(mess, n, key));
        }

        public byte[] Extract(Bitmap container, int lengthInBytes)
        {
            return LSB.ExtractMess(container, lengthInBytes);
        }

        public byte[] Decript(byte[] mess, int n, ulong key)
        {
            return Feistel.Decript(mess, n, key);
        }

        public byte[] ExtractAndDecript(Bitmap container, int lengthInBytes, int n, ulong key)
        {
            return Feistel.Decript(LSB.ExtractMess(container, lengthInBytes), n, key);
        }
    }
}
