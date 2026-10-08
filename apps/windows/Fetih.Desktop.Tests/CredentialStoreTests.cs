using System;
using System.IO;
using System.Text;
using Fetih.Desktop.Services;
using Xunit;

namespace Fetih.Desktop.Tests;

public class CredentialStoreTests
{
    // Tersine çeviren basit, geri döndürülebilir protector (DPAPI yerine test için).
    private sealed class ReverseProtector : ICredentialProtector
    {
        public byte[] Protect(byte[] data)
        {
            var c = (byte[])data.Clone();
            Array.Reverse(c);
            return c;
        }

        public byte[] Unprotect(byte[] data) => Protect(data);
    }

    private static string TempPath() =>
        Path.Combine(Path.GetTempPath(), $"fetih-creds-{Guid.NewGuid():N}", "creds.dat");

    [Fact]
    public void SetGet_RoundTrips()
    {
        var path = TempPath();
        try
        {
            var store = new CredentialStore(path, new ReverseProtector());
            store.Set("GROQ_API_KEY", "sk-secret-123");
            Assert.Equal("sk-secret-123", store.Get("GROQ_API_KEY"));
            Assert.Null(store.Get("YOK"));
        }
        finally { Cleanup(path); }
    }

    [Fact]
    public void PersistsAcrossInstances()
    {
        var path = TempPath();
        try
        {
            new CredentialStore(path, new ReverseProtector()).Set("K", "v1");
            var store2 = new CredentialStore(path, new ReverseProtector());
            Assert.Equal("v1", store2.Get("K"));
        }
        finally { Cleanup(path); }
    }

    [Fact]
    public void OnDisk_IsNotPlaintext()
    {
        var path = TempPath();
        try
        {
            new CredentialStore(path, new ReverseProtector()).Set("API", "cok-gizli-deger");
            var raw = Encoding.UTF8.GetString(File.ReadAllBytes(path));
            Assert.DoesNotContain("cok-gizli-deger", raw);
        }
        finally { Cleanup(path); }
    }

    [Fact]
    public void Remove_And_EmptyValueDeletes()
    {
        var path = TempPath();
        try
        {
            var store = new CredentialStore(path, new ReverseProtector());
            store.Set("A", "1");
            store.Set("B", "2");
            store.Remove("A");
            Assert.Null(store.Get("A"));
            Assert.Equal("2", store.Get("B"));
            store.Set("B", "");           // boş değer → sil
            Assert.Null(store.Get("B"));
        }
        finally { Cleanup(path); }
    }

    [Fact]
    public void CorruptFile_StartsEmpty()
    {
        var path = TempPath();
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, "bu gecerli bir sifreli blob degil");
            var store = new CredentialStore(path, new ReverseProtector());
            Assert.Empty(store.Names); // çözülemeyen dosya → boş başla, çökme yok
        }
        finally { Cleanup(path); }
    }

    private static void Cleanup(string path)
    {
        try { Directory.Delete(Path.GetDirectoryName(path)!, recursive: true); } catch { }
    }
}
