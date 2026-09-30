using System;
using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace Fetih.Desktop.Models;

public sealed class ChatSessionInfo : INotifyPropertyChanged
{
    private string _id = "";
    private string _title = "Yeni sohbet";
    private double _updatedAt;

    public string Id
    {
        get => _id;
        set => SetField(ref _id, value);
    }

    public string Title
    {
        get => _title;
        set => SetField(ref _title, value);
    }

    public double UpdatedAt
    {
        get => _updatedAt;
        set
        {
            if (SetField(ref _updatedAt, value))
            {
                OnPropertyChanged(nameof(TimeDisplay));
            }
        }
    }

    public string TimeDisplay
    {
        get
        {
            if (_updatedAt <= 0) return "";
            var dt = DateTimeOffset.FromUnixTimeSeconds((long)_updatedAt).ToLocalTime();
            var now = DateTimeOffset.Now;
            if (dt.Date == now.Date)
            {
                return dt.ToString("HH:mm");
            }
            if (dt.Year == now.Year)
            {
                return dt.ToString("dd MMM HH:mm");
            }
            return dt.ToString("dd.MM.yyyy HH:mm");
        }
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    private bool SetField<T>(ref T field, T value, [CallerMemberName] string? propertyName = null)
    {
        if (Equals(field, value)) return false;
        field = value;
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        return true;
    }

    private void OnPropertyChanged(string propertyName)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}
