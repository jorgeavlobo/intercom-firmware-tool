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
    /// The real text is kept in a private buffer. The TextBox shows the MASKED
    /// representation by default; the clear-text value is put in the control's
    /// Text only while the user deliberately reveals it (<see cref="Peek"/>, or
    /// the one-character reveal), and is re-masked afterwards.
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
            // Same reason for Delete: the context-menu "Delete" command would edit
            // the mask directly, leaving _real (what Build uses) stale. Route both
            // command forms through our buffer-aware handler. The Delete KEY is
            // already handled in OnPreviewKeyDown (and marked handled there, so it
            // never reaches these command bindings).
            _box.CommandBindings.Add(new CommandBinding(ApplicationCommands.Delete, OnDelete, OnCanDelete));
            _box.CommandBindings.Add(new CommandBinding(EditingCommands.Delete, OnDelete, OnCanDelete));

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

        /// <summary>Handles typed input: stores it in the buffer and briefly reveals the last character.</summary>
        private void OnPreviewTextInput(object sender, TextCompositionEventArgs e)
        {
            e.Handled = true; // we manage the Text ourselves
            if (string.IsNullOrEmpty(e.Text)) return;
            // Silently ignore non-BMP input: passwords here are BMP text, and
            // dropping surrogate-pair input keeps every stored char a single
            // UTF-16 code unit so caret/selection indices map 1:1 to the buffer.
            if (HasSurrogate(e.Text)) return;
            int start = ReplaceSelection();
            _real.Insert(start, e.Text);
            int caret = start + e.Text.Length;
            _revealIndex = caret - 1;   // reveal the character just typed
            _timer.Stop();
            _timer.Start();
            Render(caret);
            Changed?.Invoke();
        }

        /// <summary>Handles the Backspace and Delete keys against the buffer; other keys fall through.</summary>
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
            // (Ctrl+C copies whatever is shown: the mask when concealed, or the
            // real password while the field is revealed — same as any text box.)
        }

        /// <summary>Enables the Cut command only when there is a selection.</summary>
        private void OnCanCut(object sender, CanExecuteRoutedEventArgs e)
        {
            e.CanExecute = _box.SelectionLength > 0;
            e.Handled = true;
        }

        /// <summary>Cut command: removes the selection from the buffer without copying the secret to the clipboard.</summary>
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

        /// <summary>Enables the Delete command when there is a selection or a character to the right of the caret.</summary>
        private void OnCanDelete(object sender, CanExecuteRoutedEventArgs e)
        {
            e.CanExecute = _box.SelectionLength > 0 || _box.CaretIndex < _real.Length;
            e.Handled = true;
        }

        /// <summary>Delete command: removes the selection, or the next character, from the buffer.</summary>
        private void OnDelete(object sender, ExecutedRoutedEventArgs e)
        {
            // Delete the selection, or the character to the right of the caret —
            // from the buffer, keeping the display in sync. Reached by the
            // context-menu "Delete" (the Delete key is handled in OnPreviewKeyDown).
            e.Handled = true;
            StopReveal();
            if (_box.SelectionLength > 0) { int s = ReplaceSelection(); Render(s); Changed?.Invoke(); }
            else if (_box.CaretIndex < _real.Length)
            {
                int i = _box.CaretIndex;
                _real.Remove(i, 1);
                Render(i);
                Changed?.Invoke();
            }
        }

        /// <summary>Paste handler: inserts clipboard text into the buffer manually, rejecting multi-line/non-BMP content.</summary>
        private void OnPaste(object sender, DataObjectPastingEventArgs e)
        {
            e.CancelCommand(); // insert manually so _real stays in sync
            if (!e.DataObject.GetDataPresent(DataFormats.UnicodeText)) return;
            // GetData can return null or a non-string even when UnicodeText is
            // reported present; guard the cast so it can't throw.
            if (e.DataObject.GetData(DataFormats.UnicodeText) is not string raw) return;
            // Trim only CR/LF (a trailing newline from a clipboard copy); keep
            // spaces/tabs, which can be valid password characters.
            string text = raw.Trim('\r', '\n');
            if (text.Length == 0) return;
            // Reject — rather than silently transform — a genuinely multi-line or
            // non-BMP paste, so the stored password matches what the user pasted.
            if (text.IndexOfAny(new[] { '\r', '\n' }) >= 0 || HasSurrogate(text)) return;
            int start = ReplaceSelection();
            _real.Insert(start, text);
            StopReveal(); // don't flash a pasted secret
            Render(start + text.Length);
            Changed?.Invoke();
        }

        /// <summary>
        /// True if the string contains any surrogate (non-BMP) code unit. Such
        /// input is rejected on the user-facing paths so every stored character
        /// stays a single UTF-16 code unit — WPF's CaretIndex/SelectionStart
        /// count code units, so this keeps them mapping 1:1 to the buffer and a
        /// character can never be split or half-deleted.
        /// </summary>
        private static bool HasSurrogate(string s)
        {
            foreach (char c in s) if (char.IsSurrogate(c)) return true;
            return false;
        }

        /// <summary>
        /// Defensive sanitiser for programmatic <see cref="Value"/> assignments
        /// (internal, always plain text): drops any surrogate so the BMP-only
        /// invariant holds even if a caller passes non-BMP text.
        /// </summary>
        private static string StripNonBmp(string s)
        {
            if (!HasSurrogate(s)) return s;
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

        /// <summary>Cancels any active one-character reveal (stops the timer and clears the revealed index).</summary>
        private void StopReveal()
        {
            _timer.Stop();
            _revealIndex = -1;
        }

        /// <summary>
        /// Repaints the TextBox from the buffer: the clear-text value while
        /// <see cref="Peek"/> is set, otherwise the mask with at most the single
        /// briefly-revealed character shown, then restores the caret position.
        /// </summary>
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
