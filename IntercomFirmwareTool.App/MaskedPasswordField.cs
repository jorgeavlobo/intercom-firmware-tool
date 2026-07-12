using System;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Threading;

namespace IntercomFirmwareTool.App
{
    /// <summary>
    /// Turns a plain <see cref="TextBox"/> into a masked password field that
    /// mimics the behaviour of common sign-in / password forms:
    /// <list type="bullet">
    ///   <item>every character is shown as ● …</item>
    ///   <item>… except the character just typed, which is briefly revealed and
    ///   then re-masked (after a short delay, on the next edit, or when focus
    ///   leaves) — the familiar "reveal last character" behaviour;</item>
    ///   <item>while <see cref="Peek"/> is set (a Show button held down) the
    ///   whole value is shown in clear text.</item>
    /// </list>
    /// The real text is kept in a private buffer; the TextBox only ever displays
    /// the masked (or peeked) representation, so the clear-text password is never
    /// left sitting in the control's Text.
    /// </summary>
    public sealed class MaskedPasswordField
    {
        private const char Mask = '●'; // ●
        private static readonly TimeSpan RevealFor = TimeSpan.FromSeconds(1);

        private readonly TextBox _box;
        private readonly StringBuilder _real = new();
        private readonly DispatcherTimer _timer;
        private int _revealIndex = -1;
        private bool _peek;

        /// <summary>Raised whenever the underlying value changes.</summary>
        public event Action? Changed;

        public MaskedPasswordField(TextBox box)
        {
            _box = box;
            _box.IsUndoEnabled = false; // undo would revert the display and desync _real
            _box.PreviewTextInput += OnPreviewTextInput;
            _box.PreviewKeyDown += OnPreviewKeyDown;
            _box.LostFocus += (_, _) => { StopReveal(); Render(_box.CaretIndex); };
            DataObject.AddPastingHandler(_box, OnPaste);

            _timer = new DispatcherTimer { Interval = RevealFor };
            _timer.Tick += (_, _) => { StopReveal(); Render(_box.CaretIndex); };
        }

        /// <summary>The real (clear-text) value.</summary>
        public string Value
        {
            get => _real.ToString();
            set
            {
                _real.Clear();
                if (!string.IsNullOrEmpty(value)) _real.Append(value);
                StopReveal();
                Render(_real.Length);
            }
        }

        /// <summary>When true, the whole value is shown in clear text.</summary>
        public bool Peek
        {
            get => _peek;
            set { if (_peek == value) return; _peek = value; Render(_box.CaretIndex); }
        }

        private void OnPreviewTextInput(object sender, TextCompositionEventArgs e)
        {
            e.Handled = true; // we manage the Text ourselves
            if (string.IsNullOrEmpty(e.Text)) return;
            int start = ReplaceSelection();
            _real.Insert(start, e.Text);
            int caret = start + e.Text.Length;
            _revealIndex = caret - 1;   // reveal the character just typed
            _timer.Stop();
            _timer.Start();
            Render(caret);
            Changed?.Invoke();
        }

        private void OnPreviewKeyDown(object sender, KeyEventArgs e)
        {
            bool ctrl = (Keyboard.Modifiers & ModifierKeys.Control) != 0;

            if (e.Key == Key.Back)
            {
                e.Handled = true;
                if (_box.SelectionLength > 0) { int s = ReplaceSelection(); Render(s); }
                else if (_box.CaretIndex > 0) { int i = _box.CaretIndex - 1; _real.Remove(i, 1); Render(i); }
                StopReveal();
                Changed?.Invoke();
            }
            else if (e.Key == Key.Delete)
            {
                e.Handled = true;
                if (_box.SelectionLength > 0) { int s = ReplaceSelection(); Render(s); }
                else if (_box.CaretIndex < _real.Length) { int i = _box.CaretIndex; _real.Remove(i, 1); Render(i); }
                StopReveal();
                Changed?.Invoke();
            }
            else if (ctrl && e.Key == Key.X)
            {
                // Handle Cut ourselves (deleting the selection) so it can't
                // desync _real; the clear-text password is not put on the
                // clipboard.
                e.Handled = true;
                if (_box.SelectionLength > 0) { int s = ReplaceSelection(); Render(s); StopReveal(); Changed?.Invoke(); }
            }
            // Arrows / Home / End / Tab / Ctrl+A / Ctrl+C fall through; the caret
            // index maps 1:1 to _real because the display has the same length.
            // (Ctrl+C copies the masked text, not the real password.)
        }

        private void OnPaste(object sender, DataObjectPastingEventArgs e)
        {
            e.CancelCommand(); // insert manually so _real stays in sync
            if (!e.DataObject.GetDataPresent(DataFormats.UnicodeText)) return;
            string text = ((string)e.DataObject.GetData(DataFormats.UnicodeText))
                .Replace("\r", "").Replace("\n", ""); // single line only
            if (text.Length == 0) return;
            int start = ReplaceSelection();
            _real.Insert(start, text);
            StopReveal(); // don't flash a pasted secret
            Render(start + text.Length);
            Changed?.Invoke();
        }

        /// <summary>Removes the current selection from the buffer; returns the new caret index.</summary>
        private int ReplaceSelection()
        {
            int start = _box.SelectionStart;
            int len = _box.SelectionLength;
            if (len > 0 && start >= 0 && start + len <= _real.Length)
                _real.Remove(start, len);
            return start < 0 ? 0 : Math.Min(start, _real.Length);
        }

        private void StopReveal()
        {
            _timer.Stop();
            _revealIndex = -1;
        }

        private void Render(int caret)
        {
            string display;
            if (_peek)
            {
                display = _real.ToString();
            }
            else
            {
                var chars = new char[_real.Length];
                for (int i = 0; i < _real.Length; i++)
                    chars[i] = i == _revealIndex ? _real[i] : Mask;
                display = new string(chars);
            }

            // Setting Text fires TextChanged, but nothing subscribes to it for
            // logic — all edits are driven by the preview handlers above.
            _box.Text = display;
            _box.CaretIndex = caret < 0 ? display.Length : Math.Min(caret, display.Length);
        }
    }
}
