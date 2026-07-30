using System;
using System.Windows;
using System.Windows.Controls;          // ScrollChangedEventArgs
using System.Windows.Media;             // TranslateTransform
using System.Windows.Media.Animation;   // DoubleAnimation, BackEase
using System.Windows.Threading;         // DispatcherTimer

namespace IntercomFirmwareTool.App
{
    /// <summary>
    /// "New options below" scroll cue. The window body scrolls, so a control that is
    /// revealed below the fold (enabling MQTT, opening Advanced, a firmware selection
    /// growing the form…) can go unnoticed — the scrollbar merely shrinks. This shows a
    /// transient, accent pill at the bottom of the scroll area <b>only when content grows
    /// past the fold</b>, gently sliding in to draw the eye; it auto-dismisses after a few
    /// seconds, on any user scroll, or once everything fits. Clicking it smooth-scrolls
    /// down to the new content.
    ///
    /// One <see cref="ScrollViewer.ScrollChanged"/> handler covers every reveal — it keys
    /// off the extent growing (<see cref="ScrollChangedEventArgs.ExtentHeightChange"/>),
    /// so no per-control wiring is needed.
    /// </summary>
    public partial class MainWindow
    {
        private bool _cueArmed;   // ignore the initial layout burst until the window settles
        private bool _cueShown;   // the pill is currently visible (animating in / shown)
        private DispatcherTimer? _scrollCueTimer; // auto-hide countdown
        private DispatcherTimer? _scrollAnim;     // smooth-scroll stepper

        /// <summary>Arm the cue shortly after load, so the first layout pass (which fills
        /// the extent) doesn't fire it — only genuine post-load reveals do.</summary>
        private void ArmScrollCue()
        {
            var t = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(700) };
            t.Tick += (_, _) => { t.Stop(); _cueArmed = true; };
            t.Start();
            Closed += (_, _) => { _scrollCueTimer?.Stop(); _scrollAnim?.Stop(); };
        }

        private void BodyScroll_ScrollChanged(object sender, ScrollChangedEventArgs e)
        {
            if (!_cueArmed) return;
            // ScrollChanged bubbles: ignore events raised by inner scrollers (e.g. the
            // Result console's own ScrollViewer) — only the page scroller drives the cue.
            if (!ReferenceEquals(e.OriginalSource, BodyScroll)) return;

            // A user-driven scroll (no size change) means they're already navigating.
            if (e.ExtentHeightChange == 0 && e.ViewportHeightChange == 0)
            {
                if (e.VerticalChange != 0) HideScrollCue();
                return;
            }

            // Layout changed. Is there still content below the current viewport?
            double below = BodyScroll.ExtentHeight - (BodyScroll.VerticalOffset + BodyScroll.ViewportHeight);
            bool moreBelow = below > 4;

            if (e.ExtentHeightChange > 0 && moreBelow)
                ShowScrollCue();     // new content appeared past the fold → announce it
            else if (!moreBelow)
                HideScrollCue();     // everything fits now / we're at the bottom
        }

        private void ShowScrollCue()
        {
            // (Re)start the auto-hide countdown every time fresh content appears.
            _scrollCueTimer ??= CreateCueTimer();
            _scrollCueTimer.Stop();
            _scrollCueTimer.Start();

            if (_cueShown) return; // already visible; the timer refresh above is enough
            _cueShown = true;

            ScrollCue.Visibility = Visibility.Visible;
            ScrollCue.BeginAnimation(OpacityProperty,
                new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(200)));
            // Slide up with a soft overshoot for a gentle, attention-catching bounce.
            ScrollCueTranslate.BeginAnimation(TranslateTransform.YProperty,
                new DoubleAnimation(14, 0, TimeSpan.FromMilliseconds(320))
                {
                    EasingFunction = new BackEase { Amplitude = 0.5, EasingMode = EasingMode.EaseOut }
                });
            // Assertive live region: announce the new options to a screen reader too, so
            // the cue isn't purely visual.
            AnnounceLiveRegion(ScrollCue);
        }

        private DispatcherTimer CreateCueTimer()
        {
            var t = new DispatcherTimer { Interval = TimeSpan.FromSeconds(4) };
            t.Tick += (_, _) => { t.Stop(); HideScrollCue(); };
            return t;
        }

        private void HideScrollCue()
        {
            _scrollCueTimer?.Stop();
            if (!_cueShown) return;
            _cueShown = false;

            var fade = new DoubleAnimation(1, 0, TimeSpan.FromMilliseconds(200));
            // Collapse only if a fresh Show hasn't re-claimed the pill during the fade.
            fade.Completed += (_, _) => { if (!_cueShown) ScrollCue.Visibility = Visibility.Collapsed; };
            ScrollCue.BeginAnimation(OpacityProperty, fade);
            ScrollCueTranslate.BeginAnimation(TranslateTransform.YProperty,
                new DoubleAnimation(ScrollCueTranslate.Y, 14, TimeSpan.FromMilliseconds(200)));
        }

        private void ScrollCue_Click(object sender, RoutedEventArgs e)
        {
            HideScrollCue();
            // Reveal the next screenful, where the new options begin.
            SmoothScrollTo(BodyScroll.VerticalOffset + BodyScroll.ViewportHeight * 0.9);
        }

        /// <summary>Eased smooth scroll to <paramref name="target"/> (clamped), so the
        /// jump to the new content glides instead of snapping.</summary>
        private void SmoothScrollTo(double target)
        {
            _scrollAnim?.Stop();
            double start = BodyScroll.VerticalOffset;
            target = Math.Max(0, Math.Min(target, BodyScroll.ScrollableHeight));
            if (Math.Abs(target - start) < 1) { BodyScroll.ScrollToVerticalOffset(target); return; }

            double p = 0;
            var timer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(15) };
            _scrollAnim = timer;
            timer.Tick += (_, _) =>
            {
                p += 0.09;
                double t = p >= 1 ? 1 : 1 - Math.Pow(1 - p, 3); // easeOutCubic
                BodyScroll.ScrollToVerticalOffset(start + (target - start) * t);
                if (p >= 1)
                {
                    timer.Stop();
                    if (ReferenceEquals(_scrollAnim, timer)) _scrollAnim = null;
                }
            };
            timer.Start();
        }
    }
}
