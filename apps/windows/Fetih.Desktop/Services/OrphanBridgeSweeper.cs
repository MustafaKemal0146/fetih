using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace Fetih.Desktop.Services;

/// <summary>
/// Açılışta, ÖNCEKİ oturumlardan yetim kalmış Masaüstü Köprüsü süreçlerini bulup
/// kapatır.
///
/// <para>Süreç koruması (bkz. <c>Bridge/BridgeProcess.cs</c> + iş nesnesi) ve
/// pencere kapanış temizliği bundan sonrasını kapsar; bu süpürme YALNIZCA daha
/// eski sürümlerin ya da daha önce çökmüş oturumların makinede bıraktığı
/// kalıntıları toplar.</para>
///
/// <para><b>Güvenlik sözleşmesi:</b> bu kod bir süreç ÖLDÜRÜR, dolayısıyla
/// koşulları kasıtlı olarak dardır. Bir süreç yalnızca AŞAĞIDAKİLERİN TAMAMI
/// doğruysa kapatılır:</para>
/// <list type="number">
///   <item><description>Görüntü adı <c>python.exe</c>.</description></item>
///   <item><description>Komut satırı <c>fetih_desktop_bridge</c> içeriyor
///   (başka bir python işi asla hedef olmaz).</description></item>
///   <item><description>Ebeveyn süreci artık yaşamıyor — yani yetim.</description></item>
///   <item><description>Kendi PID'imiz ya da ŞU AN kendi başlattığımız köprünün
///   PID'i değil (<c>protectedPids</c> + ebeveyn canlılığı denetimi).</description></item>
///   <item><description>Ek daraltma: bizden önce başlamış (bu oturumun işi
///   olamaz).</description></item>
/// </list>
///
/// <para>Koşullardan herhangi biri DOĞRULANAMIYORSA (komut satırı okunamadı,
/// erişim reddedildi, bit genişliği uyuşmuyor, ebeveyn PID'i okunamadı) süreç
/// öldürülmez: yanlış bir süreci kapatmaktansa kalıntıyı bırakmak yeğdir.</para>
///
/// <para>Hiçbir metot istisna fırlatmaz; hata uygulamanın açılışını
/// durdurmamalıdır.</para>
/// </summary>
internal static class OrphanBridgeSweeper
{
    /// <summary>Köprü sürecinin komut satırında geçen modül adı.</summary>
    private const string BridgeMarker = "fetih_desktop_bridge";

    /// <summary>Köprüyü başlatan yürütülebilirin görüntü adı.</summary>
    private const string PythonImageName = "python";

    /// <summary>Öldürme sonrası çıkışı bekleme süresi (ms).</summary>
    private const int ExitWaitMs = 5000;

    /// <summary>Komut satırı için okunacak azami bayt (şüpheli şişkinlikleri ele).</summary>
    private const int MaxCommandLineBytes = 0x8000;

    /// <summary>
    /// Süpürmeyi arka planda başlatır; sonucu beklemez ve asla istisna fırlatmaz.
    /// Açılış yolundan (bkz. <c>App.OnLaunched</c>) çağrılır.
    /// </summary>
    /// <param name="protectedPids">
    /// Bu oturuma ait olduğu bilinen, asla kapatılmayacak PID'ler (ör. şu an
    /// bağlı olunan köprü süreci). Kendi PID'imiz her durumda korunur.
    /// </param>
    public static void SweepInBackground(IReadOnlyCollection<int>? protectedPids = null)
    {
        try
        {
            _ = Task.Run(() => Sweep(protectedPids));
        }
        catch
        {
            // İş parçacığı kuyruğu kapalıysa (kapanış anı) süpürme atlanır.
        }
    }

    /// <summary>
    /// Yetim köprü süreçlerini senkron olarak kapatır ve kapatılan süreç
    /// sayısını döndürür. Hiçbir koşulda istisna fırlatmaz.
    /// </summary>
    public static int Sweep(IReadOnlyCollection<int>? protectedPids = null)
    {
        var killed = 0;
        try
        {
            if (!OperatingSystem.IsWindows())
            {
                return 0;
            }

            var selfPid = Environment.ProcessId;
            var protectedSet = new HashSet<int> { selfPid };
            if (protectedPids is not null)
            {
                foreach (var pid in protectedPids)
                {
                    protectedSet.Add(pid);
                }
            }

            var selfStart = TryGetStartTime(selfPid);

            Process[] candidates;
            try
            {
                candidates = Process.GetProcessesByName(PythonImageName);
            }
            catch
            {
                return 0;
            }

            foreach (var proc in candidates)
            {
                try
                {
                    if (IsOrphanBridge(proc, protectedSet, selfStart))
                    {
                        Kill(proc);
                        killed++;
                    }
                }
                catch
                {
                    // Tek bir süreçle ilgili beklenmedik hata süpürmeyi durdurmasın.
                }
                finally
                {
                    try { proc.Dispose(); } catch { }
                }
            }
        }
        catch
        {
            // Süpürme bir kolaylıktır; başarısızlığı uygulamayı etkilemez.
        }

        return killed;
    }

    /// <summary>
    /// Sürecin yetim bir köprü olup olmadığını, yukarıdaki beş koşulun TAMAMI
    /// doğrulanarak belirler. Doğrulanamayan her durumda <c>false</c> döner.
    /// </summary>
    private static bool IsOrphanBridge(
        Process proc, HashSet<int> protectedPids, DateTime? selfStart)
    {
        int pid;
        try
        {
            pid = proc.Id;
        }
        catch
        {
            return false;
        }

        if (pid <= 0 || protectedPids.Contains(pid))
        {
            return false;
        }

        var query = QueryProcess(pid);
        if (query is null)
        {
            return false;
        }
        var info = query.Value;

        // (3) Ebeveyn yaşıyor mu? Yaşıyorsa bu süreç yetim değildir; ayrıca
        // kendi başlattığımız köprü de tam olarak bu koşulla korunur.
        var parentPid = info.ParentPid;
        if (parentPid <= 0 || parentPid == Environment.ProcessId)
        {
            return false;
        }
        if (IsProcessAlive(parentPid))
        {
            return false;
        }

        // (2) Komut satırı köprü modülünü içermeli.
        var commandLine = info.CommandLine;
        if (string.IsNullOrEmpty(commandLine) ||
            commandLine.IndexOf(BridgeMarker, StringComparison.OrdinalIgnoreCase) < 0)
        {
            return false;
        }

        // (5) Ek daraltma: bu oturumda başlamış bir süreç olamaz. İki taraftan
        // biri bilinmiyorsa bu koşul uygulanmaz (kalan koşullar zaten dar).
        var start = TryGetStartTime(pid);
        if (start is { } s && selfStart is { } mine && s > mine)
        {
            return false;
        }

        return true;
    }

    private static void Kill(Process proc)
    {
        try
        {
            proc.Kill(entireProcessTree: true);
            proc.WaitForExit(ExitWaitMs);
        }
        catch
        {
            // Süreç bu arada kendiliğinden kapanmış olabilir.
        }
    }

    /// <summary>PID yaşıyor mu? (Yeniden kullanılmış PID de "yaşıyor" sayılır — güvenli yön.)</summary>
    private static bool IsProcessAlive(int pid)
    {
        try
        {
            using var p = Process.GetProcessById(pid);
            return !p.HasExited;
        }
        catch
        {
            return false;
        }
    }

    private static DateTime? TryGetStartTime(int pid)
    {
        try
        {
            if (pid == Environment.ProcessId)
            {
                using var self = Process.GetCurrentProcess();
                return self.StartTime;
            }
            using var p = Process.GetProcessById(pid);
            return p.StartTime;
        }
        catch
        {
            return null;
        }
    }

    // ── Süreç sorgusu (komut satırı + ebeveyn PID) ──────────────────────────

    private readonly record struct ProcessQuery(int ParentPid, string? CommandLine);

    /// <summary>
    /// Bir sürecin ebeveyn PID'ini ve komut satırını okur. Okunamayan her durumda
    /// <c>null</c> döner; çağıran taraf bu durumda süreci kapatmaz.
    /// </summary>
    private static ProcessQuery? QueryProcess(int pid)
    {
        IntPtr handle = IntPtr.Zero;
        try
        {
            handle = Native.OpenProcess(
                Native.ProcessQueryInformation | Native.ProcessVmRead, false, pid);
            if (handle == IntPtr.Zero)
            {
                return null;
            }

            // Hedefin bit genişliği bizimkinden farklıysa (WOW64) PEB yerleşimi
            // de farklıdır; yanlış yorumlayıp yanlış süreci öldürmektense
            // dokunmamayı seçiyoruz.
            if (Native.IsWow64Process(handle, out var targetIsWow64))
            {
                var weAre32Bit = !Environment.Is64BitProcess;
                if (targetIsWow64 != weAre32Bit)
                {
                    return null;
                }
            }

            var basic = new Native.ProcessBasicInformation();
            var size = Marshal.SizeOf<Native.ProcessBasicInformation>();
            var status = Native.NtQueryInformationProcess(
                handle, Native.ProcessBasicInformationClass, ref basic, size, out _);
            if (status < 0 || basic.PebBaseAddress == IntPtr.Zero)
            {
                return null;
            }

            var parentPid = unchecked((int)basic.InheritedFromUniqueProcessId.ToInt64());
            var commandLine = TryReadCommandLine(handle, basic.PebBaseAddress);
            return new ProcessQuery(parentPid, commandLine);
        }
        catch
        {
            return null;
        }
        finally
        {
            if (handle != IntPtr.Zero)
            {
                try { Native.CloseHandle(handle); } catch { }
            }
        }
    }

    /// <summary>
    /// PEB → <c>RTL_USER_PROCESS_PARAMETERS</c> → <c>CommandLine</c> (UNICODE_STRING)
    /// zincirini okuyarak hedef sürecin komut satırını döndürür. Windows'un
    /// belgelenmiş bir "uzak sürecin komut satırı" API'si olmadığı için bu yol
    /// kullanılır; okuma başarısız olursa <c>null</c> döner ve süreç atlanır.
    /// </summary>
    private static string? TryReadCommandLine(IntPtr processHandle, IntPtr pebAddress)
    {
        // 64 bit ile 32 bit yerleşimleri farklıdır (mimari uyuşmazlığı
        // QueryProcess içinde zaten elenmiştir).
        var is64 = IntPtr.Size == 8;
        var parametersOffset = is64 ? 0x20 : 0x10;      // PEB.ProcessParameters
        var commandLineOffset = is64 ? 0x70 : 0x40;     // RTL_USER_PROCESS_PARAMETERS.CommandLine
        var bufferOffset = is64 ? 8 : 4;                // UNICODE_STRING.Buffer

        var parameters = ReadPointer(processHandle, pebAddress + parametersOffset);
        if (parameters == IntPtr.Zero)
        {
            return null;
        }

        var unicodeString = parameters + commandLineOffset;
        int lengthBytes = ReadUInt16(processHandle, unicodeString);
        if (lengthBytes < 2 || lengthBytes > MaxCommandLineBytes)
        {
            return null;
        }

        var buffer = ReadPointer(processHandle, unicodeString + bufferOffset);
        if (buffer == IntPtr.Zero)
        {
            return null;
        }

        var bytes = new byte[lengthBytes];
        if (!Native.ReadProcessMemory(processHandle, buffer, bytes, (IntPtr)bytes.Length, out var read) ||
            read.ToInt64() < lengthBytes)
        {
            return null;
        }

        return Encoding.Unicode.GetString(bytes);
    }

    private static IntPtr ReadPointer(IntPtr processHandle, IntPtr address)
    {
        var bytes = new byte[IntPtr.Size];
        if (!Native.ReadProcessMemory(processHandle, address, bytes, (IntPtr)bytes.Length, out var read) ||
            read.ToInt64() < bytes.Length)
        {
            return IntPtr.Zero;
        }
        return IntPtr.Size == 8
            ? new IntPtr(BitConverter.ToInt64(bytes, 0))
            : new IntPtr(BitConverter.ToInt32(bytes, 0));
    }

    private static ushort ReadUInt16(IntPtr processHandle, IntPtr address)
    {
        var bytes = new byte[2];
        if (!Native.ReadProcessMemory(processHandle, address, bytes, (IntPtr)2, out var read) ||
            read.ToInt64() < 2)
        {
            return 0;
        }
        return BitConverter.ToUInt16(bytes, 0);
    }

    // ── Win32 / NT ──────────────────────────────────────────────────────────

    private static class Native
    {
        internal const int ProcessBasicInformationClass = 0;
        internal const uint ProcessQueryInformation = 0x0400;
        internal const uint ProcessVmRead = 0x0010;

        [StructLayout(LayoutKind.Sequential)]
        internal struct ProcessBasicInformation
        {
            public IntPtr ExitStatus;
            public IntPtr PebBaseAddress;
            public IntPtr AffinityMask;
            public IntPtr BasePriority;
            public IntPtr UniqueProcessId;
            public IntPtr InheritedFromUniqueProcessId;
        }

        [DllImport("ntdll.dll")]
        internal static extern int NtQueryInformationProcess(
            IntPtr processHandle,
            int processInformationClass,
            ref ProcessBasicInformation processInformation,
            int processInformationLength,
            out int returnLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern IntPtr OpenProcess(uint desiredAccess, bool inheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool ReadProcessMemory(
            IntPtr process, IntPtr baseAddress, byte[] buffer, IntPtr size, out IntPtr bytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool IsWow64Process(IntPtr process, out bool isWow64);
    }
}
