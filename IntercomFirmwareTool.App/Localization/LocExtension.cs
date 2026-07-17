using System;
using System.Windows.Data;
using System.Windows.Markup;

namespace IntercomFirmwareTool.App.Localization
{
    /// <summary>
    /// XAML markup extension: <c>{loc:Loc Some_Key}</c>. Produces a one-way binding to
    /// <see cref="LocalizationManager"/>'s indexer (<c>Instance["Some_Key"]</c>), so the
    /// target text updates live whenever the language changes (the manager raises the
    /// indexer's <c>PropertyChanged</c>). Works on any bindable property — Text, Content,
    /// ToolTip, Header, Title, AutomationProperties.Name, etc. A missing key renders as
    /// the key itself, so an untranslated string is obvious rather than blank.
    /// </summary>
    [MarkupExtensionReturnType(typeof(object))]
    public sealed class LocExtension : MarkupExtension
    {
        public string Key { get; set; } = "";

        public LocExtension() { }
        public LocExtension(string key) { Key = key; }

        public override object ProvideValue(IServiceProvider serviceProvider)
        {
            var binding = new Binding($"[{Key}]")
            {
                Source = LocalizationManager.Instance,
                Mode = BindingMode.OneWay,
            };
            return binding.ProvideValue(serviceProvider);
        }
    }
}
