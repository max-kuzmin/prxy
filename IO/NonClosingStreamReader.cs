using System.Text;

namespace Prxy.IO;

public sealed class NonClosingStreamReader : IDisposable
{
    private readonly Stream _stream;
    private readonly Encoding _encoding;
    private readonly byte[] _byteBuffer;

    public NonClosingStreamReader(Stream stream, Encoding encoding)
    {
        _stream = stream;
        _encoding = encoding;
        _byteBuffer = new byte[1];
    }

    public async Task<string?> ReadLineAsync(CancellationToken cancellationToken)
    {
        var lineBytes = new List<byte>();
        while (true)
        {
            var read = await _stream.ReadAsync(_byteBuffer.AsMemory(0, 1), cancellationToken);
            if (read == 0)
            {
                if (lineBytes.Count == 0)
                    return null;
                break;
            }

            var b = _byteBuffer[0];
            if (b == '\n')
            {
                if (lineBytes.Count > 0 && lineBytes[^1] == '\r')
                    lineBytes.RemoveAt(lineBytes.Count - 1);
                break;
            }

            lineBytes.Add(b);
        }

        return _encoding.GetString(lineBytes.ToArray());
    }

    public void Dispose()
    {
    }
}

