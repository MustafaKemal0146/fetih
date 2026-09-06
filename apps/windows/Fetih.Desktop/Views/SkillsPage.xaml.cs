using System;
using System.Collections.Generic;
using System.Linq;
using Fetih.Desktop.Models;
using Fetih.Desktop.Services;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace Fetih.Desktop.Views;

/// <summary>
/// Yetenek (skill) tarayıcısı. <c>skills/</c>, <c>optional-skills/</c> ve
/// <c>~/.fetih/skills/</c> ağaçlarındaki <c>SKILL.md</c> ön bilgilerini gerçekten
/// okuyup listeler; arama ve kategori süzgeci sunar.
/// Katalog süreç ömrü boyunca bir kez taranıp önbelleğe alınır.
/// </summary>
public sealed partial class SkillsPage : Page
{
    private static SkillScanResult? _cache;

    private IReadOnlyList<SkillInfo> _all = Array.Empty<SkillInfo>();
    private bool _categoryReady;

    public SkillsPage()
    {
        InitializeComponent();
        ApplyLanguage();
        Loaded += OnLoaded;
        Unloaded += OnUnloaded;
    }

    private void ApplyLanguage()
    {
        PageTitleText.Text = Loc.T("skills.title");
        SearchBox.PlaceholderText = Loc.T("skills.search_placeholder");
        RefreshButton.Content = Loc.T("common.reload");
        if (_cache is not null)
        {
            _categoryReady = false;
            BuildCategoryList(_cache);
            SummaryText.Text = BuildSummary(_cache);
        }
        else
        {
            SummaryText.Text = Loc.T("skills.scanning");
        }
    }

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        Loc.LanguageChanged += OnLanguageChanged;
        await LoadAsync(forceRefresh: false);
    }

    private void OnUnloaded(object sender, RoutedEventArgs e)
    {
        Loc.LanguageChanged -= OnLanguageChanged;
    }

    private void OnLanguageChanged()
    {
        ApplyLanguage();
        ApplyFilter();
    }

    private async void RefreshButton_Click(object sender, RoutedEventArgs e)
        => await LoadAsync(forceRefresh: true);

    private async System.Threading.Tasks.Task LoadAsync(bool forceRefresh)
    {
        try
        {
            if (forceRefresh)
            {
                _cache = null;
            }

            if (_cache is null)
            {
                LoadingRing.IsActive = true;
                LoadingRing.Visibility = Visibility.Visible;
                SkillList.Visibility = Visibility.Collapsed;
                EmptyText.Visibility = Visibility.Collapsed;
                RefreshButton.IsEnabled = false;

                _cache = await SkillCatalog.LoadAsync();
            }

            _all = _cache.Skills;

            BuildCategoryList(_cache);
            ApplyFilter();

            SummaryText.Text = BuildSummary(_cache);
        }
        catch (Exception ex)
        {
            App.LogCrash("SkillsPage.LoadAsync", ex, ex.Message);
            SummaryText.Text = "Yetenek kataloğu okunamadı.";
            EmptyText.Text = $"Katalog taranırken hata oluştu:\n{ex.Message}";
            EmptyText.Visibility = Visibility.Visible;
            SkillList.Visibility = Visibility.Collapsed;
        }
        finally
        {
            LoadingRing.IsActive = false;
            LoadingRing.Visibility = Visibility.Collapsed;
            RefreshButton.IsEnabled = true;
        }
    }

    private static string BuildSummary(SkillScanResult result)
    {
        if (FetihPaths.RepositoryRoot is null)
        {
            return "FETİH deposu bulunamadı — yetenekler yalnızca " +
                   $"{FetihPaths.UserSkillsDir} altından okundu ({result.Skills.Count} kayıt).";
        }

        var repoCount = result.Skills.Count(s => s.Source == "skills");
        var optionalCount = result.Skills.Count(s => s.Source == "optional-skills");
        var userCount = result.Skills.Count(s => s.Source == "kullanıcı");

        var text = $"{result.Skills.Count} yetenek · skills/ {repoCount} · " +
                   $"optional-skills/ {optionalCount} · yalnızca kullanıcıda {userCount} " +
                   $"({result.ElapsedMilliseconds} ms)";

        if (result.DuplicatesSkipped > 0)
        {
            // Kurulum depo ağacını ~/.fetih/skills/ altına kopyaladığı için
            // aynı yetenek iki kez görünmesin diye kopyalar atlanır.
            text += $" · {result.DuplicatesSkipped} kurulu kopya atlandı";
        }

        return result.Error is null ? text : $"{text} — uyarı: {result.Error}";
    }

    private void BuildCategoryList(SkillScanResult result)
    {
        if (_categoryReady)
        {
            return;
        }

        var items = new List<string> { Loc.T("skills.all_categories") };
        items.AddRange(result.Categories);

        CategoryBox.ItemsSource = items;
        CategoryBox.SelectedIndex = 0;
        _categoryReady = true;
    }

    private void SearchBox_TextChanged(object sender, TextChangedEventArgs e) => ApplyFilter();

    private void CategoryBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_categoryReady)
        {
            ApplyFilter();
        }
    }

    private void ApplyFilter()
    {
        try
        {
            IEnumerable<SkillInfo> query = _all;

            if (CategoryBox.SelectedIndex > 0 && CategoryBox.SelectedItem is string category)
            {
                query = query.Where(s => s.SubtitleLabel == category);
            }

            var needle = SearchBox.Text?.Trim().ToLowerInvariant();
            if (!string.IsNullOrEmpty(needle))
            {
                // Boşlukla ayrılmış her terim ayrı ayrı eşleşmeli (VE mantığı).
                var terms = needle.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                query = query.Where(s => terms.All(t => s.SearchBlob.Contains(t, StringComparison.Ordinal)));
            }

            var filtered = query.ToList();
            SkillList.ItemsSource = filtered;

            if (filtered.Count == 0)
            {
                SkillList.Visibility = Visibility.Collapsed;
                EmptyText.Text = _all.Count == 0
                    ? "Hiç SKILL.md bulunamadı. Depo kökü çözümlenemediyse uygulamayı " +
                      "depo içindeki apps/windows/Fetih.Desktop klasöründen çalıştırın."
                    : "Bu arama/kategori için sonuç yok.";
                EmptyText.Visibility = Visibility.Visible;
            }
            else
            {
                EmptyText.Visibility = Visibility.Collapsed;
                SkillList.Visibility = Visibility.Visible;
            }
        }
        catch (Exception ex)
        {
            App.LogCrash("SkillsPage.ApplyFilter", ex, ex.Message);
        }
    }
}
