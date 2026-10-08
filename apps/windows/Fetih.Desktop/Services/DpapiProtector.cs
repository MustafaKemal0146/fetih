using System;
using System.Security.Cryptography;

namespace Fetih.Desktop.Services;

/// <summary>
/// Windows DPAPI (<see cref="ProtectedData"/>) tabanlı protector:
/// veriyi <b>mevcut kullanıcıya</b> bağlı olarak şifreler, yalnızca aynı
/// Windows hesabı çözebilir. Anahtar yönetimi işletim sistemine aittir.
/// </summary>
public sealed class DpapiProtector : ICredentialProtector
{
    // Ek bütünlük için entropi (gizli değil; DPAPI zaten kullanıcıya bağlar).
    private static readonly byte[] Entropy = Encoding().GetBytes("FETIH.Desktop.Credentials.v1");

    private static System.Text.Encoding Encoding() => System.Text.Encoding.UTF8;

    public byte[] Protect(byte[] data)
        => ProtectedData.Protect(data, Entropy, DataProtectionScope.CurrentUser);

    public byte[] Unprotect(byte[] data)
        => ProtectedData.Unprotect(data, Entropy, DataProtectionScope.CurrentUser);
}
