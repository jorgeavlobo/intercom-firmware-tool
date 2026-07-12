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
            // Intercept Cut at the command level so BOTH the keyboard (Ctrl+X)
            // and the context-menu "Cut" go through us and can't edit the
            // display directly (which would desync _real).
            _box.CommandBindings.Add(new CommandBinding(ApplicationCommands.Cut, OnCut, OnCanCut));

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
                if (!string.IsNullOrEmpty(value)) _real.Append(StripNonBmp(value));
                StopReveal();
                Render(_real.Length);
                Changed?.Invoke(); // let subscribers (e.g. the match hint) refresh
            }
        }

        /// <summary>When true, the whole value is shown in clear text.</summary>
        public bool Peek
        {
            get => _peek;
            set
            {
                if (_peek == value) return;
                _peek = value;
                // Turning peek off must mask EVERY character at once — otherwise a
                // char typed while holding Show would linger via the reveal timer.
                if (!value) StopReveal();
                Render(_box.CaretIndex);
            }
        }

        private void OnPreviewTextInput(object sender, TextCompositionEventArgs e)
        {
            e.Handled = true; // we manage the Text ourselves
            if (string.IsNullOrEmpty(e.Text)) return;
            string ins = StripNonBmp(e.Text); // keep every stored char one code unit
            if (ins.Length == 0) return;
            int start = ReplaceSelection();
            _real.Insert(start, ins);
            int caret = start + ins.Length;
            _revealIndex = caret - 1;   // reveal the character just typed
            _timer.Stop();
            _timer.Start();
            Render(caret);
            Changed?.Invoke();
        }

        private void OnPreviewKeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Back)
            {
                e.Handled = true;
                StopReveal(); // mask first, so a still-revealed char can't linger after an adjacent edit
                if (_box.SelectionLength > 0) { int s = ReplaceSelection(); Render(s); }
                else if (_box.CaretIndex > 0) { int i = _box.CaretIndex - 1; _real.Remove(i, 1); Render(i); }
                Changed?.Invoke();
            }
            else if (e.Key == Key.Delete)
            {
                e.Handled = true;
                StopReveal();
                if (_box.SelectionLength > 0) { int s = ReplaceSelection(); Render(s); }
                else if (_box.CaretIndex < _real.Length) { int i = _box.CaretIndex; _real.Remove(i, 1); Render(i); }
                Changed?.Invoke();
            }
            // Cut (Ctrl+X) is handled by the ApplicationCommands.Cut binding.
            // Arrows / Home / End / Tab / Ctrl+A / Ctrl+C fall through; the caret
            // index maps 1:1 to _real because the display has the same length.
            // (Ctrl+C copies the masked text, not the real password.)
        }

        private void OnCanCut(object sender, CanExecuteRoutedEventArgs e)
        {
            e.CanExecute = _box.SelectionLength > 0;
            e.Handled = true;
        }

        private void OnCut(object sender, ExecutedRoutedEventArgs e)
        {
            // Delete the selection from the buffer WITHOUT copying the clear-text
            // password to the clipboard. Reached by both Ctrl+X and context-menu
            // Cut, so the display can never diverge from _real.
            e.Handled = true;
            if (_box.SelectionLength > 0)
            {
                StopReveal();
                int s = ReplaceSelection();
                Render(s);
                Changed?.Invoke();
            }
        }

        private void OnPaste(object sender, DataObjectPastingEventArgs e)
        {
            e.CancelCommand(); // insert manually so _real stays in sync
            if (!e.DataObject.GetDataPresent(DataFormats.UnicodeText)) return;
            // GetData can return null or a non-string even when UnicodeText is
            // reported present; guard the cast so it can't throw.
            if (e.DataObject.GetData(DataFormats.UnicodeText) is not string raw) return;
            string text = StripNonBmp(raw.Replace("\r", "").Replace("\n", "")); // single line, BMP only
            if (text.Length == 0) return;
            int start = ReplaceSelection();
            _real.Insert(start, text);
            StopReveal(); // don't flash a pasted secret
            Render(start + text.Length);
            Changed?.Invoke();
        }

        /// <summary>
        /// Drops any surrogate (non-BMP) code unit so every stored character is a
        /// single UTF-16 code unit. WPF's CaretIndex/SelectionStart count code
        /// units, so this keeps them mapping 1:1 to the buffer — a character can
        /// never be split or half-deleted. Passwords for this tool are plain text.
        /// </summary>
        private static string StripNonBmp(string s)
        {
            bool has = false;
            foreach (char c in s) if (char.IsSurrogate(c)) { has = true; break; }
            if (!has) return s;
            var sb = new StringBuilder(s.Length);
            foreach (char c in s) if (!char.IsSurrogate(c)) sb.Append(c);
            return sb.ToString();
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
