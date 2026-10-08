namespace Fetih.Desktop.Services;

/// <summary>
/// Gizli veriyi kullanıcıya bağlı olarak şifreleyip çözen soyutlama.
/// Üretimde <see cref="DpapiProtector"/> (Windows DPAPI) kullanılır; saf
/// olduğu için <see cref="CredentialStore"/> mantığı sahte bir uygulamayla
/// çapraz-platform test edilebilir.
/// </summary>
public interface ICredentialProtector
{
    /// <summary>Düz baytları şifreli baytlara çevirir.</summary>
    byte[] Protect(byte[] data);

    /// <summary>Şifreli baytları düz baytlara çözer.</summary>
    byte[] Unprotect(byte[] data);
}
