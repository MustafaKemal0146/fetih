using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.Linq;
using Fetih.Desktop.Models;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace Fetih.Desktop.Views;

/// <summary>
/// Bulgu listesi. Faz 1'de backend yok, bu yüzden koleksiyon boştur ve boş
/// durum mesajı gösterilir — ama yapı gerçektir: Masaüstü Köprüsü bağlandığında
/// ajan olayları doğrudan <see cref="Findings"/> koleksiyonuna eklenecek
/// (bkz. docs/windows-app-plani.md, (f) bölümü).
/// </summary>
public sealed partial class FindingsPage : Page
{
    private const string AllSeverities = "Tüm ciddiyet seviyeleri";

    /// <summary>
    /// Süreç genelinde paylaşılan bulgu deposu. Sayfa her açıldığında sıfırlanmasın
    /// diye statik tutulur; köprü katmanı buraya yazacak.
    /// </summary>
    public static ObservableCollection<Finding> Findings { get; } = new();

    private bool _filterReady;

    public FindingsPage()
    {
        InitializeComponent();

        SeverityBox.ItemsSource = new List<string>
        {
            AllSeverities,
            "Kritik",
            "Yüksek",
            "Orta",
            "Düşük",
            "Bilgi",
        };
        SeverityBox.SelectedIndex = 0;
        _filterReady = true;

        Loaded += OnLoaded;
        Unloaded += OnUnloaded;
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        Findings.CollectionChanged += OnFindingsChanged;
        ApplyFilter();
    }

    private void OnUnloaded(object sender, RoutedEventArgs e)
    {
        Findings.CollectionChanged -= OnFindingsChanged;
    }

    private void OnFindingsChanged(object? sender, NotifyCollectionChangedEventArgs e) => ApplyFilter();

    private void SeverityBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_filterReady)
        {
            ApplyFilter();
        }
    }

    private void ApplyFilter()
    {
        try
        {
            IEnumerable<Finding> query = Findings;

            if (SeverityBox.SelectedItem is string severity && severity != AllSeverities)
            {
                query = query.Where(f => f.SeverityLabel == severity);
            }

            var filtered = query
                .OrderByDescending(f => f.Severity)
                .ThenByDescending(f => f.DiscoveredAt)
                .ToList();

            FindingList.ItemsSource = filtered;
            CountText.Text = Findings.Count == 0
                ? string.Empty
                : $"{filtered.Count} / {Findings.Count} bulgu gösteriliyor";

            var hasItems = filtered.Count > 0;
            FindingList.Visibility = hasItems ? Visibility.Visible : Visibility.Collapsed;
            EmptyState.Visibility = hasItems ? Visibility.Collapsed : Visibility.Visible;
        }
        catch (Exception ex)
        {
            App.LogCrash("FindingsPage.ApplyFilter", ex, ex.Message);
        }
    }
}
