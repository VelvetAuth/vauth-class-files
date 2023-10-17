using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace vProtect.api
{
    public static class messagebox
    {
        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        public static extern int MessageBox(IntPtr hWND, string message, string caption, uint icon);

        public enum icons : long
        {
            exclamation = 0x00000030L,
            warning = 0x00000030L,
            information = 0x00000040L,
            asterisk = 0x00000040L,
            question = 0x00000020L,
            stop = 0x00000010L,
            error = 0x00000010L,
            hand = 0x00000010L
        }

        public static int show(string text, icons ico)
        {
            return MessageBox((IntPtr)0, text, "vAuthentication", (uint)ico);
        }
    }
}
