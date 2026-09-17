using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Fetih.Desktop.Bridge;

/// <summary>
/// Alt süreçleri bir Windows Job Object içine alarak "ebeveyn ölürse çocuk da
/// ölür" güvencesini işletim sistemine devreden ince sarmalayıcı.
///
/// <para><b>Neden gerekli:</b> <see cref="Process.Kill(bool)"/> yalnızca
/// ÇAĞRILDIĞINDA iş görür. Ebeveyn süreç çökerse, Görev Yöneticisi'nden
/// sonlandırılırsa ya da kapanış yolunda beklenmedik bir hata olursa
/// <c>Stop()</c> hiç çalışmaz ve python köprü süreci yetim kalır; her
/// aç-kapa döngüsü arkasında kalıcı bir süreç (ve onlarca MB bellek) bırakır.
/// <c>JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE</c> ile kurulmuş bir iş nesnesi bu
/// boşluğu kapatır: iş nesnesinin SON tutamacı kapandığında — ki bu, ebeveyn
/// nasıl ölürse ölsün sonlandırma sırasında çekirdek tarafından yapılır —
/// işin içindeki TÜM süreçler öldürülür.</para>
///
/// <para><b>Hata felsefesi:</b> bu sınıf bir GÜVENCE katmanıdır, çökme sebebi
/// olmamalıdır. Hiçbir metot istisna fırlatmaz. Bir adım başarısız olursa
/// (örneğin uygulama, kopmayı yasaklayan başka bir iş nesnesinin içinde
/// başlatılmışsa <c>AssignProcessToJobObject</c> reddeder) sessizce
/// <c>null</c>/<c>false</c> döner ve çağıran taraftaki
/// <c>Kill(entireProcessTree: true)</c> yolu tek başına çalışmaya devam eder.</para>
///
/// <para>Kaynak sızıntısı yoktur: <see cref="Dispose"/> birden çok kez
/// çağrılabilir ve kurulumun her başarısız adımı tutamacı kapatır.</para>
/// </summary>
internal sealed class ChildProcessGuard : IDisposable
{
    // ── Win32 sabitleri ─────────────────────────────────────────────────────

    /// <summary><c>JOBOBJECTINFOCLASS.JobObjectExtendedLimitInformation</c>.</summary>
    private const int JobObjectExtendedLimitInformation = 9;

    /// <summary>İş nesnesinin son tutamacı kapanınca içindeki süreçleri öldür.</summary>
    private const uint JobObjectLimitKillOnJobClose = 0x00002000;

    // ── Yerel imzalar ───────────────────────────────────────────────────────

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateJobObjectW(IntPtr lpJobAttributes, string? lpName);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetInformationJobObject(
        IntPtr hJob, int jobObjectInformationClass, IntPtr lpJobObjectInformation, uint cbJobObjectInformationLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AssignProcessToJobObject(IntPtr hJob, IntPtr hProcess);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    // ── Yerel yapılar ───────────────────────────────────────────────────────

    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectBasicLimitInformation
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IoCounters
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectExtendedLimitInfo
    {
        public JobObjectBasicLimitInformation BasicLimitInformation;
        public IoCounters IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    // ── Durum ───────────────────────────────────────────────────────────────

    private IntPtr _jobHandle;

    private ChildProcessGuard(IntPtr jobHandle) => _jobHandle = jobHandle;

    /// <summary>İş nesnesi hâlâ ayakta mı (tutamacı açık mı)?</summary>
    public bool IsActive => _jobHandle != IntPtr.Zero;

    /// <summary>
    /// Öldürme-üzerine-kapanma bayraklı, isimsiz bir iş nesnesi oluşturur.
    /// Başarısız olursa <c>null</c> döner (istisna fırlatmaz).
    /// </summary>
    public static ChildProcessGuard? TryCreate()
    {
        IntPtr job = IntPtr.Zero;
        IntPtr buffer = IntPtr.Zero;
        try
        {
            job = CreateJobObjectW(IntPtr.Zero, null);
            if (job == IntPtr.Zero)
            {
                return null;
            }

            var info = new JobObjectExtendedLimitInfo
            {
                BasicLimitInformation = new JobObjectBasicLimitInformation
                {
                    LimitFlags = JobObjectLimitKillOnJobClose,
                },
            };

            var size = Marshal.SizeOf<JobObjectExtendedLimitInfo>();
            buffer = Marshal.AllocHGlobal(size);
            Marshal.StructureToPtr(info, buffer, fDeleteOld: false);

            if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, buffer, (uint)size))
            {
                // Bayrak yazılamadıysa iş nesnesi işe yaramaz: tutamacı bırak.
                CloseHandle(job);
                return null;
            }

            return new ChildProcessGuard(job);
        }
        catch
        {
            if (job != IntPtr.Zero)
            {
                try { CloseHandle(job); } catch { }
            }
            return null;
        }
        finally
        {
            if (buffer != IntPtr.Zero)
            {
                try { Marshal.FreeHGlobal(buffer); } catch { }
            }
        }
    }

    /// <summary>
    /// Süreci iş nesnesine atar. Süreç zaten kopması yasak başka bir işin
    /// içindeyse ya da tutamaç alınamıyorsa <c>false</c> döner; bu bir hata
    /// değildir, yalnızca bu güvence katmanının devre dışı kaldığı anlamına
    /// gelir.
    /// </summary>
    public bool TryAssign(Process process)
    {
        if (_jobHandle == IntPtr.Zero || process is null)
        {
            return false;
        }

        try
        {
            if (!AssignProcessToJobObject(_jobHandle, process.Handle))
            {
                return false;
            }
            return true;
        }
        catch
        {
            // Süreç bu arada kapanmış olabilir; sessizce vazgeç.
            return false;
        }
    }

    /// <summary>
    /// İş nesnesinin tutamacını kapatır. Son tutamaç kapandığı anda işin
    /// içindeki TÜM süreçler işletim sistemi tarafından sonlandırılır
    /// (<c>KILL_ON_JOB_CLOSE</c>). Birden çok kez çağrılabilir.
    /// </summary>
    public void Dispose()
    {
        var handle = System.Threading.Interlocked.Exchange(ref _jobHandle, IntPtr.Zero);
        if (handle == IntPtr.Zero)
        {
            return;
        }

        try { CloseHandle(handle); } catch { }
    }
}
