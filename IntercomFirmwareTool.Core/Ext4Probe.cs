using SharpExt4;
using System.Text;

namespace IntercomFirmwareTool.Core
{
    public static class Ext4Probe
    {
        public static string ReadFile(string imagePath, string fileInsideImage)
        {
            var disk = ExtDisk.Open(imagePath);
            var fs = ExtFileSystem.Open(disk.Partitions[0]);
            var file = fs.OpenFile(fileInsideImage, FileMode.Open, FileAccess.Read);
            var buf = new byte[file.Length];
            file.Read(buf, 0, buf.Length);
            file.Close();
            return Encoding.UTF8.GetString(buf);
        }
    }
}
