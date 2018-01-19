using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Drawing;

namespace cript._6
{
    class Program
    {
        static void Main(string[] args)
        {            
            Encoding encoding = Encoding.Default;
            UI uI = new UI();
            ulong key = ulong.MaxValue - 15687410218;
            int n = 6;

            Console.InputEncoding = encoding;
            Console.OutputEncoding = encoding;

            Console.Write("Your text: ");
            string s = Console.ReadLine();
            byte[] mess = encoding.GetBytes(s);

            //Bitmap fullBitmap = uI.Fill(new Bitmap(@"3.tif", false), mess);
            Bitmap fullBitmap = uI.EncriptAndFill(new Bitmap(@" 3.tif", false), mess, n, key);

            fullBitmap.Save(@" 6.tif", System.Drawing.Imaging.ImageFormat.Tiff);
            Console.WriteLine("New file saved");

            //byte[] extractetMess = uI.Extract(fullBitmap, mess.Length);
            //Bitmap openedBitmap = new Bitmap(@" 6.tif", false);
            //byte[] extractetMess = uI.Extract(openedBitmap , mess.Length);
            byte[] extractetMess = uI.ExtractAndDecript(new Bitmap(@" 6.tif", false), mess.Length, n, key);
            string s1 = encoding.GetString(extractetMess);

            Console.WriteLine("Decripted text: {0}", s1);
            Console.ReadKey();
        }
    }
}