using System;
using Microsoft.UI.Dispatching;

namespace Fetih.Desktop.Services;

/// <summary>
/// WinUI DispatcherQueue uygulayan UI iş parçacığı yönlendiricisi.
/// </summary>
public sealed class WinUiDispatcher : IUiDispatcher
{
    private readonly DispatcherQueue _queue;

    public WinUiDispatcher(DispatcherQueue queue)
    {
        _queue = queue ?? throw new ArgumentNullException(nameof(queue));
    }

    public void Run(Action action)
    {
        if (_queue.HasThreadAccess)
        {
            action();
        }
        else
        {
            _queue.TryEnqueue(() => action());
        }
    }

    public bool HasThreadAccess => _queue.HasThreadAccess;
}
