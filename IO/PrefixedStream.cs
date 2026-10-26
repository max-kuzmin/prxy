namespace Prxy.IO;

public sealed class PrefixedStream : Stream
{
    private readonly Stream _underlyingStream;
    private readonly byte[] _prefix;
    private readonly bool _leaveOpen;
    private int _prefixOffset;

    public PrefixedStream(Stream underlyingStream, byte[] prefix, int prefixLength, bool leaveOpen)
    {
        _underlyingStream = underlyingStream;
        _prefix = new byte[prefixLength];
        Array.Copy(prefix, 0, _prefix, 0, prefixLength);
        _prefixOffset = 0;
        _leaveOpen = leaveOpen;
    }

    public PrefixedStream(Stream underlyingStream, byte[] prefix, int prefixLength)
        : this(underlyingStream, prefix, prefixLength, false)
    {
    }

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => _underlyingStream.CanWrite;
    public override long Length => throw new NotSupportedException();
    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken)
    {
        if (_prefixOffset < _prefix.Length)
        {
            var available = _prefix.Length - _prefixOffset;
            var toCopy = Math.Min(available, buffer.Length);
            _prefix.AsMemory(_prefixOffset, toCopy).CopyTo(buffer);
            _prefixOffset += toCopy;
            return toCopy;
        }

        return await _underlyingStream.ReadAsync(buffer, cancellationToken);
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        if (_prefixOffset < _prefix.Length)
        {
            var available = _prefix.Length - _prefixOffset;
            var toCopy = Math.Min(available, count);
            Array.Copy(_prefix, _prefixOffset, buffer, offset, toCopy);
            _prefixOffset += toCopy;
            return toCopy;
        }

        return _underlyingStream.Read(buffer, offset, count);
    }

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        _underlyingStream.WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken) =>
        _underlyingStream.WriteAsync(buffer, cancellationToken);

    public override void Write(byte[] buffer, int offset, int count) =>
        _underlyingStream.Write(buffer, offset, count);

    public override Task FlushAsync(CancellationToken cancellationToken) =>
        _underlyingStream.FlushAsync(cancellationToken);

    public override void Flush() => _underlyingStream.Flush();
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing && !_leaveOpen)
            _underlyingStream.Dispose();
        base.Dispose(disposing);
    }
}

