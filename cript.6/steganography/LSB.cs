using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Drawing;

namespace cript._6.steganography
{
    static class LSB
    {
        static private int a = 410;
        static private int b = 5830;
        static private int c = 8191; // для задания PseudorandomArr        

        static private int[] PseudorandomArr(int size, int max)
        {
            int[] arr = new int[size];

            arr[0] = a;
            for (int i = 0; i < size - 1; i++)
            {
                arr[i + 1] = (b * arr[i] + a) % c;
            }

            for (int i = 0; i < size; i++) // нормировка
            {
                    arr[i] %= max;                
            }
            return arr;
        }

        static public Bitmap Fill(Bitmap container, byte[] mess)
        {
            byte bitesInByte = 8;

            int divRem = mess.Length % 8;
            if (divRem != 0)
            {
                Array.Resize(ref mess, mess.Length + (8 - divRem));
            }


            int[] indexes = PseudorandomArr(mess.Length * bitesInByte, container.Height * container.Width);

            // Lock the bitmap's bits.  
            Rectangle rect = new Rectangle(0, 0, container.Width, container.Height);
            System.Drawing.Imaging.BitmapData containerData =
                container.LockBits(rect, System.Drawing.Imaging.ImageLockMode.ReadWrite,
                container.PixelFormat);

            // Get the address of the first line.
            IntPtr ptr = containerData.Scan0;

            // Declare an array to hold the bytes of the bitmap.
            int bytes = Math.Abs(containerData.Stride) * container.Height;
            byte[] rgbValues = new byte[bytes];

            // Copy the RGB values into the array.
            System.Runtime.InteropServices.Marshal.Copy(ptr, rgbValues, 0, bytes);

            int j = -1; // указатель на byte в mess
            for (int i = 0; i < indexes.Length; i++)
            {
                if (i % bitesInByte == 0)
                {
                    j++;
                }
                //Console.Write("{0}|", rgbValues[i]);
                rgbValues[i] = (byte)((rgbValues[i] & (byte.MaxValue - 1)) | ((mess[j] >> (i % bitesInByte)) & 1));
                //Console.Write("{0} ", rgbValues[i]);
            }

            // Copy the RGB values back to the bitmap
            System.Runtime.InteropServices.Marshal.Copy(rgbValues, 0, ptr, bytes);

            // Unlock the bits.
            container.UnlockBits(containerData);
            
            return container;
        }

        static public byte[] ExtractMess(Bitmap container, int lengthInBytes)
        {
            byte bitesInByte = 8;

            lengthInBytes += 8 - lengthInBytes % 8;

            byte[] mess = new byte[lengthInBytes];
            int[] indexes = PseudorandomArr(lengthInBytes * bitesInByte, container.Height * container.Width);

            // Lock the bitmap's bits.  
            Rectangle rect = new Rectangle(0, 0, container.Width, container.Height);
            System.Drawing.Imaging.BitmapData containerData =
                container.LockBits(rect, System.Drawing.Imaging.ImageLockMode.ReadWrite,
                container.PixelFormat);

            // Get the address of the first line.
            IntPtr ptr = containerData.Scan0;

            // Declare an array to hold the bytes of the bitmap.
            int bytes = Math.Abs(containerData.Stride) * container.Height;
            byte[] rgbValues = new byte[bytes];

            // Copy the RGB values into the array.
            System.Runtime.InteropServices.Marshal.Copy(ptr, rgbValues, 0, bytes);

            int j = -1; // указатель на byte в mess
            for (int i = 0; i < indexes.Length; i++)
            {
                if (i % bitesInByte == 0)
                {
                    j++;
                }
               // Console.Write("{0} ", rgbValues[i]);
                mess[j] |= (byte)((rgbValues[i] & 1) << (i % bitesInByte)); // чтение информации
            }
            
            // Unlock the bits.
            container.UnlockBits(containerData);

            return mess;
        }

        //static public Bitmap Fill(Bitmap container, byte[] mess)
        //{
        //    byte bitesInByte = 8;

        //    int[] indexes = PseudorandomArr(mess.Length * bitesInByte, container.Height * container.Width);

        //    int j = -1; // указатель на byte в mess
        //    for (int i = 0; i < indexes.Length; i++)
        //    {
        //        if (i % bitesInByte == 0)
        //        {
        //            j++;
        //        }
        //        Color color = container.GetPixel(indexes[i] / container.Width, indexes[i] % container.Width); // в indexes записаны значения, ограниченные сверху container.Height * container.Width
        //                                                                                                      // как будто мы записали матрицу в одну строку
        //                                                                                                      // если мы разделим такие значения на длину строки в матрице, то получим номер строки в целой части и номер элемента в остатке

        //        //b = (color.B & (byte.MaxValue - 1)) | ((mess[j] >> (i % bitesInByte)) & 1); // запись информации
        //        //Color filledColor = Color.FromArgb(color.A, color.R, color.G, (color.B & (byte.MaxValue - 1)) | ((mess[j] >> (i % bitesInByte)) & 1));                
        //        container.SetPixel(indexes[i] / container.Width, indexes[i] % container.Width, Color.FromArgb(color.A, color.R, color.G, (byte)((color.B & (byte.MaxValue - 1)) | ((mess[j] >> (i % bitesInByte)) & 1))));
        //        Console.Write("{0} ", container.GetPixel(indexes[i] / container.Width, indexes[i] % container.Width).B);
        //    }
        //    Console.WriteLine();
        //    return container;
        //}

        //static public byte[] ExtractMess(Bitmap container, int lengthInBytes)
        //{
        //    byte bitesInByte = 8;

        //    byte[] mess = new byte[lengthInBytes];
        //    int[] indexes = PseudorandomArr(lengthInBytes * bitesInByte, container.Height * container.Width);

        //    int j = -1; // указатель на byte в mess
        //    for (int i = 0; i < indexes.Length; i++)
        //    {
        //        if (i % bitesInByte == 0)
        //        {
        //            j++;
        //        }

        //        Color color = container.GetPixel(indexes[i] / container.Width, indexes[i] % container.Width);
        //        Console.Write("{0} ", color.B);
        //        mess[j] |= (byte)((color.B & 1) << (i % bitesInByte)); // чтение информации
        //    }
        //    Console.WriteLine();
        //    return mess;
        //}
    }
}
