using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Fetih.Desktop.Setup;
using Xunit;

namespace Fetih.Desktop.Tests;

public class SetupEngineTests
{
    private sealed class FakeStep : SetupStep
    {
        private readonly Func<SetupContext, Task<StepResult>> _exec;
        private readonly bool _skip;
        private readonly List<string>? _rollbackLog;

        public FakeStep(string id, Func<SetupContext, Task<StepResult>> exec,
            bool skip = false, List<string>? rollbackLog = null)
        {
            Id = id;
            _exec = exec;
            _skip = skip;
            _rollbackLog = rollbackLog;
        }

        public override string Id { get; }
        public override string DisplayName => Id;
        public override Task<StepResult> ExecuteAsync(SetupContext ctx, CancellationToken ct) => _exec(ctx);
        public override Task<bool> CanSkipAsync(SetupContext ctx) => Task.FromResult(_skip);
        public override Task RollbackAsync(SetupContext ctx, CancellationToken ct)
        {
            _rollbackLog?.Add(Id);
            return Task.CompletedTask;
        }
    }

    private static SetupPipeline Pipeline(IReadOnlyList<SetupStep> steps, out string journalPath)
    {
        journalPath = Path.Combine(Path.GetTempPath(), $"fetih-journal-{Guid.NewGuid():N}.jsonl");
        return new SetupPipeline(steps, new TransactionJournal(journalPath));
    }

    [Fact]
    public async Task AllStepsSucceed()
    {
        var steps = new SetupStep[]
        {
            new FakeStep("a", _ => Task.FromResult(StepResult.Ok())),
            new FakeStep("b", _ => Task.FromResult(StepResult.Ok())),
        };
        var pipeline = Pipeline(steps, out _);
        var result = await pipeline.RunAsync(new SetupContext(), CancellationToken.None);
        Assert.Equal(PipelineOutcome.Success, result.Outcome);
    }

    [Fact]
    public async Task SkippedStepDoesNotExecute()
    {
        var ran = false;
        var steps = new SetupStep[]
        {
            new FakeStep("skip", _ => { ran = true; return Task.FromResult(StepResult.Ok()); }, skip: true),
        };
        var pipeline = Pipeline(steps, out _);
        var result = await pipeline.RunAsync(new SetupContext(), CancellationToken.None);
        Assert.Equal(PipelineOutcome.Success, result.Outcome);
        Assert.False(ran);
    }

    [Fact]
    public async Task FailureRollsBackCompletedStepsInReverse()
    {
        var order = new List<string>();
        var steps = new SetupStep[]
        {
            new FakeStep("a", _ => Task.FromResult(StepResult.Ok()), rollbackLog: order),
            new FakeStep("b", _ => Task.FromResult(StepResult.Ok()), rollbackLog: order),
            new FakeStep("c", _ => Task.FromResult(StepResult.Fail("patladı")), rollbackLog: order),
        };
        var pipeline = Pipeline(steps, out _);
        var result = await pipeline.RunAsync(new SetupContext(), CancellationToken.None);

        Assert.Equal(PipelineOutcome.Failed, result.Outcome);
        Assert.Equal("c", result.FailedStepId);
        // Yalnızca tamamlananlar (a,b) ters sırada geri alınır; c tamamlanmadı.
        Assert.Equal(new[] { "b", "a" }, order);
    }

    [Fact]
    public async Task ThrownExceptionIsFailureNotCrash()
    {
        var steps = new SetupStep[]
        {
            new FakeStep("boom", _ => throw new InvalidOperationException("x")),
        };
        var pipeline = Pipeline(steps, out _);
        var result = await pipeline.RunAsync(new SetupContext(), CancellationToken.None);
        Assert.Equal(PipelineOutcome.Failed, result.Outcome);
        Assert.Equal("boom", result.FailedStepId);
    }

    [Fact]
    public async Task PreCancelledTokenCancels()
    {
        var steps = new SetupStep[]
        {
            new FakeStep("a", _ => Task.FromResult(StepResult.Ok())),
        };
        var pipeline = Pipeline(steps, out _);
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        var result = await pipeline.RunAsync(new SetupContext(), cts.Token);
        Assert.Equal(PipelineOutcome.Cancelled, result.Outcome);
    }

    [Fact]
    public async Task JournalRecordsEvents()
    {
        var steps = new SetupStep[] { new FakeStep("a", _ => Task.FromResult(StepResult.Ok())) };
        var pipeline = Pipeline(steps, out var journalPath);
        await pipeline.RunAsync(new SetupContext(), CancellationToken.None);

        var journal = new TransactionJournal(journalPath);
        var lines = journal.LoadExisting();
        Assert.Contains(lines, l => l.Contains("pipeline_started"));
        Assert.Contains(lines, l => l.Contains("pipeline_completed"));
        try { File.Delete(journalPath); } catch { }
    }

    // ── SetupRunLock ─────────────────────────────────────────────────────────

    [Fact]
    public void RunLock_SecondAcquireFailsWhileHeld()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"fetih-lock-{Guid.NewGuid():N}");
        try
        {
            Assert.True(SetupRunLock.TryAcquire(dir, out var first));
            using (first)
            {
                Assert.False(SetupRunLock.TryAcquire(dir, out var second));
                Assert.Null(second);
            }
            // Bırakıldıktan sonra yeniden alınabilir.
            Assert.True(SetupRunLock.TryAcquire(dir, out var third));
            third!.Dispose();
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch { }
        }
    }
}
