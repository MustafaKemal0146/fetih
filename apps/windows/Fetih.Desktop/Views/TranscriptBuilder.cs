using System;
using System.Collections.Generic;
using System.Linq;
using Fetih.Desktop.Bridge;
using Fetih.Desktop.Models;
using Fetih.Desktop.Services;

namespace Fetih.Desktop.Views;

public static class TranscriptBuilder
{
    public static List<ChatMessage> Build(IEnumerable<StoredItem> items)
    {
        var messages = new List<ChatMessage>();
        ActivityGroup? currentGroup = null;
        double groupDurationMs = 0;
        bool hasTiming = false;

        void CloseGroup()
        {
            if (currentGroup != null)
            {
                // Boş grup görünmez
                if (currentGroup.Steps.Count == 0)
                {
                    messages.Remove(currentGroup);
                    currentGroup = null;
                    return;
                }

                // Sonuçsuz kalan araçları Cancelled yap
                foreach (var step in currentGroup.Steps)
                {
                    if (step.Role == ChatRole.Tool && step.Status == ToolStatus.Running)
                    {
                        step.Status = ToolStatus.Cancelled;
                    }
                }

                // Eğer gruptaki etiket henüz kilitlenmediyse son düşünceden etiket üret
                if (!currentGroup.IsLabelLocked)
                {
                    var lastThought = currentGroup.Steps.LastOrDefault(s => s.Role == ChatRole.Thought);
                    if (lastThought != null && !string.IsNullOrWhiteSpace(lastThought.Text))
                    {
                        var summary = ActivityLabelBuilder.BuildLabel(lastThought.Text);
                        if (!string.IsNullOrEmpty(summary))
                        {
                            currentGroup.Label = summary;
                        }
                    }
                    currentGroup.IsLabelLocked = true;
                }

                TimeSpan? elapsed = hasTiming && groupDurationMs >= 1000
                    ? TimeSpan.FromMilliseconds(groupDurationMs)
                    : null;

                currentGroup.Complete(false, elapsed);
                currentGroup = null;
                groupDurationMs = 0;
                hasTiming = false;
            }
        }

        ActivityGroup EnsureGroup()
        {
            if (currentGroup == null)
            {
                currentGroup = new ActivityGroup();
                messages.Add(currentGroup);
                groupDurationMs = 0;
                hasTiming = false;
            }
            return currentGroup;
        }

        foreach (var item in items)
        {
            switch (item.Kind)
            {
                case "user":
                    CloseGroup();
                    messages.Add(new ChatMessage(ChatRole.User, item.Text ?? ""));
                    break;

                case "assistant":
                    CloseGroup();
                    messages.Add(new ChatMessage(ChatRole.Agent, item.Text ?? ""));
                    break;

                case "thought":
                    var g = EnsureGroup();
                    var thought = new ChatMessage(ChatRole.Thought, item.Text ?? "")
                    {
                        ParentGroup = g
                    };
                    g.Steps.Add(thought);

                    if (item.DurationMs.HasValue)
                    {
                        groupDurationMs += item.DurationMs.Value;
                        hasTiming = true;
                    }
                    else if (item.TsStart.HasValue && item.TsEnd.HasValue)
                    {
                        groupDurationMs += (item.TsEnd.Value - item.TsStart.Value) * 1000.0;
                        hasTiming = true;
                    }

                    g.UpdateThoughtText(thought.Text, isClosing: false);
                    break;

                case "tool_call":
                    var tg = EnsureGroup();
                    var (title, formattedInput) = ToolFormatter.FormatInput(item.Name ?? "", item.Args);
                    var tool = new ChatMessage(ChatRole.Tool)
                    {
                        ToolCallId = item.CallId,
                        ToolName = item.Name ?? "",
                        ToolTitle = title,
                        ToolInput = formattedInput,
                        Status = ToolStatus.Running,
                        ParentGroup = tg
                    };
                    tg.Steps.Add(tool);
                    tg.SetToolRunning(item.Name ?? "");
                    break;

                case "tool_result":
                    var rg = EnsureGroup();
                    var match = rg.Steps.LastOrDefault(s => s.Role == ChatRole.Tool && (s.ToolCallId == item.CallId || string.IsNullOrEmpty(item.CallId)));
                    if (match != null)
                    {
                        var (status, formattedOutput) = ToolFormatter.FormatResult(item.Result);
                        match.ToolOutput = formattedOutput;
                        match.Status = status;

                        if (item.DurationMs.HasValue)
                        {
                            groupDurationMs += item.DurationMs.Value;
                            hasTiming = true;
                            var sec = item.DurationMs.Value / 1000.0;
                            var secUnit = Loc.T("Unit_Sec") ?? Loc.T("unit.sec");
                            match.Duration = sec < 1 ? $"{item.DurationMs.Value:0} ms" : $"{sec:0.1} {secUnit}";
                        }
                    }
                    rg.Refresh();
                    break;

                case "error":
                    CloseGroup();
                    var err = new ChatMessage(ChatRole.System, item.Text ?? "")
                    {
                        Status = ToolStatus.Error
                    };
                    messages.Add(err);
                    break;
            }
        }

        CloseGroup();
        return messages;
    }
}
