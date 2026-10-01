using System;
using Fetih.Desktop.Services;

namespace Fetih.Desktop.Tests;

/// <summary>
/// xUnit testleri için eylemleri senkron çalıştıran IUiDispatcher uygulaması.
/// </summary>
public sealed class TestSyncDispatcher : IUiDispatcher
{
    public void Run(Action action) => action();
    public bool HasThreadAccess => true;
}
