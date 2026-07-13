using System.IO;
using System.Windows;

namespace IntercomFirmwareTool.App
{
    /// <summary>
    /// Writes text to the clipboard while opting the payload OUT of Windows
    /// Clipboard History and cloud clipboard sync, so a copied secret (the root
    /// password) is not retained by the OS. Shared by the "Copy password" button
    /// and the masked field's Copy command so both use the same privacy formats.
    /// </summary>
    internal static class SecureClipboard
    {
        public static void SetText(string text)
        {
            // Windows honours these clipboard formats to exclude a payload from
            // monitoring, history and cloud upload; the "Can…" flags take a DWORD 0.
            var data = new DataObject();
            data.SetText(text);
            data.SetData("ExcludeClipboardContentFromMonitorProcessing",
                new MemoryStream(new byte[] { 0, 0, 0, 0 }));
            data.SetData("CanIncludeInClipboardHistory",
                new MemoryStream(new byte[] { 0, 0, 0, 0 }));
            data.SetData("CanUploadToCloudClipboard",
                new MemoryStream(new byte[] { 0, 0, 0, 0 }));
            Clipboard.SetDataObject(data, copy: true);
        }
    }
}
