using System;

namespace Fetih.Desktop.Services;

/// <summary>
/// UI iş parçacığı yönlendirici soyutlaması.
/// Üretimde WinUI DispatcherQueue, xUnit birim testlerinde senkron sahte (TestSyncDispatcher) kullanılır.
/// </summary>
public interface IUiDispatcher
{
    void Run(Action action);
    bool HasThreadAccess { get; }
}
