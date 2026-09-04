using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Fetih.Desktop.Setup;

/// <summary>Bir adımın sonucu.</summary>
public enum StepOutcome
{
    Completed,
    Skipped,
    Failed,
}

/// <summary>Bir adımın çalışma sonucu + isteğe bağlı mesaj.</summary>
public sealed record StepResult(StepOutcome Outcome, string Message = "")
{
    public static StepResult Ok(string message = "") => new(StepOutcome.Completed, message);
    public static StepResult Skip(string reason) => new(StepOutcome.Skipped, reason);
    public static StepResult Fail(string message) => new(StepOutcome.Failed, message);
}

/// <summary>Adımlar arası paylaşılan durum (sihirbaz girdileri + türetilmiş değerler).</summary>
public sealed class SetupContext
{
    /// <summary>Kullanıcının seçtiği sağlayıcı kimliği (ör. <c>groq</c>).</summary>
    public string ProviderId { get; set; } = "";

    /// <summary>Sağlayıcının API anahtarı ortam değişkeni adı (ör. <c>GROQ_API_KEY</c>).</summary>
    public string KeyEnvVar { get; set; } = "";

    /// <summary>Kullanıcının girdiği API anahtarı. <b>Yalnızca .env'e yazılır, asla loglanmaz.</b></summary>
    public string ApiKey { get; set; } = "";

    /// <summary>Seçilen varsayılan model.</summary>
    public string Model { get; set; } = "";

    /// <summary>Adımların biriktirdiği bilgi notları (UI'da gösterilir).</summary>
    public List<string> Notes { get; } = new();
}

/// <summary>
/// Kurulum adımı soyutlaması — OpenClaw'ın <c>SetupStep</c> desenine karşılık
/// (bkz. docs/openclaw-inceleme-notlari.md §5.1). Her adım atlanabilir
/// (<see cref="CanSkipAsync"/>), yürütülebilir ve geri alınabilir
/// (<see cref="RollbackAsync"/>).
/// </summary>
public abstract class SetupStep
{
    public abstract string Id { get; }
    public abstract string DisplayName { get; }

    public abstract Task<StepResult> ExecuteAsync(SetupContext ctx, CancellationToken ct);

    /// <summary>Önkoşul zaten sağlanmışsa adım atlanır (ikinci çalıştırma = onarım modu).</summary>
    public virtual Task<bool> CanSkipAsync(SetupContext ctx) => Task.FromResult(false);

    /// <summary>Bu adımın yan etkisini geri al (varsa).</summary>
    public virtual Task RollbackAsync(SetupContext ctx, CancellationToken ct) => Task.CompletedTask;
}

/// <summary>Pipeline'ın genel sonucu.</summary>
public enum PipelineOutcome
{
    Success,
    Failed,
    Cancelled,
}

public sealed record PipelineResult(PipelineOutcome Outcome, string? FailedStepId, string Message);

/// <summary>Adım ilerlemesini UI'ya bildirir.</summary>
public sealed record StepProgress(int Index, int Total, string StepId, string DisplayName, StepOutcome? Outcome, string Message);

/// <summary>
/// Adım listesini sırayla çalıştırır; her olayı <see cref="TransactionJournal"/>'a
/// yazar. Bir adım başarısız olursa tamamlanan adımları ters sırayla geri alır —
/// yarım kurulum bırakmaz (OpenClaw §5.2).
/// </summary>
public sealed class SetupPipeline
{
    private readonly IReadOnlyList<SetupStep> _steps;
    private readonly TransactionJournal _journal;

    public SetupPipeline(IReadOnlyList<SetupStep> steps, TransactionJournal journal)
    {
        _steps = steps;
        _journal = journal;
    }

    public event Action<StepProgress>? Progress;

    public async Task<PipelineResult> RunAsync(SetupContext ctx, CancellationToken ct)
    {
        _journal.Write("pipeline_started", new() { ["steps"] = _steps.Count });
        var completed = new List<SetupStep>();

        for (var i = 0; i < _steps.Count; i++)
        {
            var step = _steps[i];
            if (ct.IsCancellationRequested)
            {
                await RollbackAsync(ctx, completed).ConfigureAwait(false);
                _journal.Write("pipeline_cancelled", new() { ["at"] = step.Id });
                return new PipelineResult(PipelineOutcome.Cancelled, step.Id, "İptal edildi.");
            }

            Report(i, step, null, "başlıyor…");
            _journal.Write("step_started", new() { ["id"] = step.Id });

            try
            {
                if (await step.CanSkipAsync(ctx).ConfigureAwait(false))
                {
                    _journal.Write("step_skipped", new() { ["id"] = step.Id, ["reason"] = "precondition met" });
                    Report(i, step, StepOutcome.Skipped, "zaten sağlanmış — atlandı");
                    continue;
                }

                var result = await step.ExecuteAsync(ctx, ct).ConfigureAwait(false);

                if (result.Outcome == StepOutcome.Failed)
                {
                    _journal.Write("step_failed", new() { ["id"] = step.Id, ["message"] = result.Message });
                    Report(i, step, StepOutcome.Failed, result.Message);
                    await RollbackAsync(ctx, completed).ConfigureAwait(false);
                    _journal.Write("pipeline_failed", new() { ["failed_step"] = step.Id });
                    return new PipelineResult(PipelineOutcome.Failed, step.Id, result.Message);
                }

                _journal.Write("step_completed", new() { ["id"] = step.Id, ["outcome"] = result.Outcome.ToString() });
                Report(i, step, result.Outcome, result.Message);
                if (result.Outcome == StepOutcome.Completed)
                {
                    completed.Add(step);
                }
            }
            catch (OperationCanceledException)
            {
                await RollbackAsync(ctx, completed).ConfigureAwait(false);
                _journal.Write("pipeline_cancelled", new() { ["at"] = step.Id });
                return new PipelineResult(PipelineOutcome.Cancelled, step.Id, "İptal edildi.");
            }
            catch (Exception ex)
            {
                _journal.Write("step_failed", new() { ["id"] = step.Id, ["message"] = ex.Message });
                Report(i, step, StepOutcome.Failed, ex.Message);
                await RollbackAsync(ctx, completed).ConfigureAwait(false);
                _journal.Write("pipeline_failed", new() { ["failed_step"] = step.Id });
                return new PipelineResult(PipelineOutcome.Failed, step.Id, ex.Message);
            }
        }

        _journal.Write("pipeline_completed", new());
        return new PipelineResult(PipelineOutcome.Success, null, "Kurulum tamamlandı.");
    }

    private async Task RollbackAsync(SetupContext ctx, List<SetupStep> completed)
    {
        for (var i = completed.Count - 1; i >= 0; i--)
        {
            var step = completed[i];
            try
            {
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
                await step.RollbackAsync(ctx, cts.Token).ConfigureAwait(false);
                _journal.Write("rollback", new() { ["id"] = step.Id, ["ok"] = true });
            }
            catch (Exception ex)
            {
                // Geri almanın kendisi başarısız olsa da günlüğe yazıp devam et.
                _journal.Write("rollback", new() { ["id"] = step.Id, ["ok"] = false, ["error"] = ex.Message });
            }
        }
    }

    private void Report(int i, SetupStep step, StepOutcome? outcome, string message)
        => Progress?.Invoke(new StepProgress(i + 1, _steps.Count, step.Id, step.DisplayName, outcome, message));
}
