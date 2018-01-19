using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using cript._6.cryptography;

namespace cript._6.cryptography
{
    static public class Feistel
    {
        static private ulong salt = ulong.MaxValue - 5687759231;

        static public byte[] Encript(byte[] msgSrc, int n, ulong key)
        {
            int divRem = msgSrc.Length % 8;
            if (divRem != 0)
            {
                Array.Resize(ref msgSrc, msgSrc.Length + (8 - divRem));
            }

            key = PBKDF2.get(BitConverter.GetBytes(key), salt, n);

            uint[] keys = new uint[n];
            for (int i = 0; i < keys.Length; i++)
            {
                keys[i] = KeyGen(key, i);
            }

            byte[] msgEncr = new byte[msgSrc.Length];
            for (int i = 0; i < msgSrc.Length; i += 8)
            {
                uint left = 0;
                uint right = 0;

                left = left | msgSrc[i + 3];                   // Чтение блока
                left |= ((left >> 8) | msgSrc[i + 2]) << 8;
                left |= ((left >> 16) | msgSrc[i + 1]) << 16;
                left |= ((left >> 24) | msgSrc[i]) << 24;

                right = right | msgSrc[i + 7];
                right |= ((right >> 8) | msgSrc[i + 6]) << 8;
                right |= ((right >> 16) | msgSrc[i + 5]) << 16;
                right |= ((right >> 24) | msgSrc[i + 4]) << 24;
                
                uint newRight;

                for (int j = 0; j < n; j++) //  Шифрование
                {
                    //Console.Write("{0}|{1} ", Convert.ToString(left, 16), Convert.ToString(right, 16));
                    newRight = left ^ keys[j];
                    left = F(newRight) ^ right;
                    right = newRight;
                }

                //Console.WriteLine("{0}|{1} ", Convert.ToString(left, 16), Convert.ToString(right, 16));

                msgEncr[i + 3] = (byte)left;            //Запись блока
                msgEncr[i + 2] = (byte)(left >> 8);
                msgEncr[i + 1] = (byte)(left >> 16);
                msgEncr[i] = (byte)(left >> 24);
                msgEncr[i + 7] = (byte)right;
                msgEncr[i + 6] = (byte)(right >> 8);
                msgEncr[i + 5] = (byte)(right >> 16);
                msgEncr[i + 4] = (byte)(right >> 24);
            }
            //Console.WriteLine("===========");
            return msgEncr;
        }

        static public byte[] Decript(byte[] msgEncr, int n, ulong key)
        {
            // Так же как Encode, но в цикле шифрования используются ключи в обратном порядке
            int divRem = msgEncr.Length % 8;
            if (divRem != 0)
            {
                Array.Resize(ref msgEncr, msgEncr.Length + (8 - divRem));
            }

            key = PBKDF2.get(BitConverter.GetBytes(key), salt, n);

            uint[] keys = new uint[n];
            for (int i = 0; i < keys.Length; i++)
            {
                keys[i] = KeyGen(key, i);
            }

            byte[] msgSrc = new byte[msgEncr.Length];
            for (int i = 0; i < msgEncr.Length; i += 8)
            {
                uint left = 0;
                uint right = 0;
                uint newLeft = 0;

                left = left | msgEncr[i + 3];
                left |= ((left >> 8) | msgEncr[i + 2]) << 8;
                left |= ((left >> 16) | msgEncr[i + 1]) << 16;
                left |= ((left >> 24) | msgEncr[i]) << 24;

                right = right | msgEncr[i + 7];
                right |= ((right >> 8) | msgEncr[i + 6]) << 8;
                right |= ((right >> 16) | msgEncr[i + 5]) << 16;
                right |= ((right >> 24) | msgEncr[i + 4]) << 24;

                for (int j = 0; j < n; j++)
                {
                    //Console.Write("{0}|{1} ", Convert.ToString(left, 16), Convert.ToString(right, 16));
                    newLeft = right ^ keys[n - 1 - j];
                    right = F(right) ^ left;
                    left = newLeft;
                }

                //Console.WriteLine("{0}|{1} ", Convert.ToString(left, 16), Convert.ToString(right, 16));

                msgSrc[i + 3] = (byte)left;
                msgSrc[i + 2] = (byte)(left >> 8);
                msgSrc[i + 1] = (byte)(left >> 16);
                msgSrc[i] = (byte)(left >> 24);
                msgSrc[i + 7] = (byte)right;
                msgSrc[i + 6] = (byte)(right >> 8);
                msgSrc[i + 5] = (byte)(right >> 16);
                msgSrc[i + 4] = (byte)(right >> 24);
            }
            //Console.WriteLine("===========");
            return msgSrc;
        }

        static public byte[] EncriptCBC(byte[] msgSrc, int n, ulong key, ulong IV)
        {
            // К алгоритму ECB добавляется еще одна итерация xor, для рандомизации выходных данных.
            // Если передать, например, длинную последовательность нулей, то ECB вернет переодическую последовательность.
            int divRem = msgSrc.Length % 8;
            if (divRem != 0)
            {
                Array.Resize(ref msgSrc, msgSrc.Length + (8 - divRem));
            }

            key = PBKDF2.get(BitConverter.GetBytes(key), salt, n);

            uint[] keys = new uint[n];
            for (int i = 0; i < keys.Length; i++)
            {
                keys[i] = KeyGen(key, i);
            }

            uint left = 0;
            uint right = 0;
            uint newRight;

            byte[] msgEncr = new byte[msgSrc.Length];

            for (int i = 0; i < msgSrc.Length; i += 8)
            {
                left = 0;
                right = 0;

                left = left | msgSrc[i + 3];
                left |= ((left >> 8) | msgSrc[i + 2]) << 8;
                left |= ((left >> 16) | msgSrc[i + 1]) << 16;
                left |= ((left >> 24) | msgSrc[i]) << 24;

                right = right | msgSrc[i + 7];
                right |= ((right >> 8) | msgSrc[i + 6]) << 8;
                right |= ((right >> 16) | msgSrc[i + 5]) << 16;
                right |= ((right >> 24) | msgSrc[i + 4]) << 24;

                if (i == 0) // Добавляем -1-ю итерацию xor с вектором инициализации у первого блока
                {
                    left ^= (uint)(IV >> 32);
                    right ^= (uint)IV;
                }
                else // и с предыдущим блоком у ослальных блоков
                {
                    newRight = 0;

                    newRight |= ((newRight >> 24) | msgEncr[i - 8]) << 24;
                    newRight |= ((newRight >> 16) | msgEncr[i - 8 + 1]) << 16;
                    newRight |= ((newRight >> 8) | msgEncr[i - 8 + 2]) << 8;
                    newRight = newRight | msgEncr[i - 8 + 3];

                    left ^= newRight;
                    newRight = 0;

                    newRight |= ((newRight >> 24) | msgEncr[i - 8 + 4]) << 24;
                    newRight |= ((newRight >> 16) | msgEncr[i - 8 + 5]) << 16;
                    newRight |= ((newRight >> 8) | msgEncr[i - 8 + 6]) << 8;
                    newRight = newRight | msgEncr[i - 8 + 7];                                      
                    
                    right ^= newRight;
                }

                for (int j = 0; j < n; j++)
                {
                    //Console.Write("{0}|{1} ", Convert.ToString(left, 16), Convert.ToString(right, 16));
                    newRight = left ^ keys[j];
                    left = F(newRight) ^ right;
                    right = newRight;
                }

                //Console.WriteLine("{0}|{1} ", Convert.ToString(left, 16), Convert.ToString(right, 16));
                
                msgEncr[i + 3] = (byte)left;
                msgEncr[i + 2] = (byte)(left >> 8);
                msgEncr[i + 1] = (byte)(left >> 16);
                msgEncr[i] = (byte)(left >> 24);
                msgEncr[i + 7] = (byte)right;
                msgEncr[i + 6] = (byte)(right >> 8);
                msgEncr[i + 5] = (byte)(right >> 16);
                msgEncr[i + 4] = (byte)(right >> 24);
            }
            //Console.WriteLine("===========");
            return msgEncr;
        }

        static public byte[] DecriptCBC(byte[] msgEncr, int n, ulong key, ulong IV)
        {
            //Как Decode ECB, но добавляется n+1 -я итерация xor
            int divRem = msgEncr.Length % 8;
            if (divRem != 0)
            {
                Array.Resize(ref msgEncr, msgEncr.Length + (8 - divRem));
            }

            key = PBKDF2.get(BitConverter.GetBytes(key), salt, n);

            uint[] keys = new uint[n];
            for (int i = 0; i < keys.Length; i++)
            {
                keys[i] = KeyGen(key, i);
            }

            uint left = 0;
            uint right = 0;
            uint newLeft = 0;

            byte[] msgSrc = new byte[msgEncr.Length];

            for (int i = 0; i < msgSrc.Length; i += 8)
            {
                left = 0;
                right = 0;

                left = left | msgEncr[i + 3];
                left |= ((left >> 8) | msgEncr[i + 2]) << 8;
                left |= ((left >> 16) | msgEncr[i + 1]) << 16;
                left |= ((left >> 24) | msgEncr[i]) << 24;

                right = right | msgEncr[i + 7];
                right |= ((right >> 8) | msgEncr[i + 6]) << 8;
                right |= ((right >> 16) | msgEncr[i + 5]) << 16;
                right |= ((right >> 24) | msgEncr[i + 4]) << 24;

                for (int j = 0; j < n; j++)
                {
                    //Console.Write("{0}|{1} ", Convert.ToString(left, 16), Convert.ToString(right, 16));
                    newLeft = right ^ keys[n - 1 - j];
                    right = F(right) ^ left;
                    left = newLeft;
                }

                if (i == 0) // Первый блок xor с вектором инициализации
                {
                    left ^= (uint)(IV >> 32);
                    right ^= (uint)IV;
                    msgSrc[i + 3] = (byte)left;
                    msgSrc[i + 2] = (byte)(left >> 8);
                    msgSrc[i + 1] = (byte)(left >> 16);
                    msgSrc[i] = (byte)(left >> 24);
                    msgSrc[i + 7] = (byte)right;
                    msgSrc[i + 6] = (byte)(right >> 8);
                    msgSrc[i + 5] = (byte)(right >> 16);
                    msgSrc[i + 4] = (byte)(right >> 24);
                    continue;
                }

                //Console.WriteLine("{0}|{1} ", Convert.ToString(left, 16), Convert.ToString(right, 16));

                //Все блоки, кроме первого, xor с предыдущим зашифрованным блоком.

                newLeft = 0;

                newLeft = newLeft | msgEncr[i - 8 + 3];
                newLeft |= ((newLeft >> 8) | msgEncr[i - 8 + 2]) << 8;
                newLeft |= ((newLeft >> 16) | msgEncr[i - 8 + 1]) << 16;
                newLeft |= ((newLeft >> 24) | msgEncr[i - 8]) << 24;

                left ^= newLeft;
                newLeft = 0;

                newLeft = newLeft | msgEncr[i - 8 + 7];
                newLeft |= ((newLeft >> 8) | msgEncr[i - 8 + 6]) << 8;
                newLeft |= ((newLeft >> 16) | msgEncr[i - 8 + 5]) << 16;
                newLeft |= ((newLeft >> 24) | msgEncr[i - 8 + 4]) << 24;

                right ^= newLeft;

                msgSrc[i + 3] = (byte)left;
                msgSrc[i + 2] = (byte)(left >> 8);
                msgSrc[i + 1] = (byte)(left >> 16);
                msgSrc[i] = (byte)(left >> 24);
                msgSrc[i + 7] = (byte)right;
                msgSrc[i + 6] = (byte)(right >> 8);
                msgSrc[i + 5] = (byte)(right >> 16);
                msgSrc[i + 4] = (byte)(right >> 24);
            }
            //Console.WriteLine("===========");
            return msgSrc;
        }

        static public ulong Hash(byte[] msgSrc, int n, ulong key)
        {
            // Key используются только для первого блока, для всех последующих ключем является выход предыдущего блока шифрования
            if (msgSrc.Length % 8 != 0)
            {
                return 0;
            }

            uint[] keys = new uint[n];
            for (int i = 0; i < keys.Length; i++)
            {
                keys[i] = KeyGen(key, i);
            }

            uint left = 0;
            uint right = 0;

            for (int i = 0; i < msgSrc.Length; i += 8)
            {
                left = left | msgSrc[i + 3];
                left |= ((left >> 8) | msgSrc[i + 2]) << 8;
                left |= ((left >> 16) | msgSrc[i + 1]) << 16;
                left |= ((left >> 24) | msgSrc[i]) << 24;

                right = right | msgSrc[i + 7];
                right |= ((right >> 8) | msgSrc[i + 6]) << 8;
                right |= ((right >> 16) | msgSrc[i + 5]) << 16;
                right |= ((right >> 24) | msgSrc[i + 4]) << 24;

                uint newRight;

                for (int j = 0; j < n; j++)
                {
                    //Console.Write("{0}|{1} ", Convert.ToString(left, 16), Convert.ToString(right, 16));
                    newRight = left ^ keys[j];
                    left = F(newRight) ^ right;
                    right = newRight;
                }

                //Console.WriteLine("{0}|{1} ", Convert.ToString(left, 16), Convert.ToString(right, 16));

                for (int j = 0; j < keys.Length; j++) // Создание ключей на осонове зашифрованного блока
                {
                    keys[j] = KeyGen((ulong)left << 8 | right, j);
                }
            }
            //Console.WriteLine("===========");
            return (ulong)left << 8 | right;
        }

        static private ulong RShift(ulong number, int n)
        {
            n = n % (sizeof(ulong) * 8);
            return (number >> n) | (number << (sizeof(ulong) * 8 - n));
        }

        static private uint RShift(uint number, int n)
        {
            n = n % (sizeof(uint) * 8);
            return (number >> n) | (number << (sizeof(uint) * 8 - n));
        }

        static private ulong LShift(ulong number, int n)
        {
            n = n % (sizeof(ulong) * 8);
            return (number << n) | (number >> (sizeof(ulong) * 8 - n));
        }

        static private uint LShift(uint number, int n)
        {
            n = n % (sizeof(uint) * 8);
            return (number << n) | (number >> (sizeof(uint) * 8 - n));
        }

        static private uint KeyGen(ulong key, int i)
        {
            return (uint)(LShift(key, i * 3) >> 3);
        }

        static private uint F(uint number)
        {
            return (byte)LShift(number, 6) | (~number + RShift(number, 9) << 16);
        }
    }
}
