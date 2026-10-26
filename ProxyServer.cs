using System.Buffers.Binary;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using Prxy.IO;
using Prxy.Models;

namespace Prxy;

public sealed class ProxyServer
{
    private readonly IPAddress _bindAddress;
    private readonly int _port;
    private readonly bool _log;
    private readonly bool _insecure;
    private readonly TimeSpan _timeout;
    private readonly UpstreamProxy? _upstreamProxy;
    private readonly AuthCredentials? _auth;

    public ProxyServer(IPAddress bindAddress, int port, string? upstream, AuthCredentials? auth, bool log, bool insecure, TimeSpan timeout)
    {
        _bindAddress = bindAddress;
        _port = port;
        _log = log;
        _insecure = insecure;
        _timeout = timeout;
        _auth = auth;
        if (!string.IsNullOrWhiteSpace(upstream))
            _upstreamProxy = ParseForwardUrl(upstream);
    }

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        var listener = new TcpListener(_bindAddress, _port);
        listener.Start();

        cancellationToken.Register(() => listener.Stop());

        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                var clientSocket = await listener.AcceptSocketAsync(cancellationToken);
                _ = HandleConnectionAsync(clientSocket, cancellationToken);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception)
            {
                if (cancellationToken.IsCancellationRequested)
                    break;
            }
        }
    }

    private async Task HandleConnectionAsync(Socket clientSocket, CancellationToken cancellationToken)
    {
        using (clientSocket)
        {
            ConfigureSocket(clientSocket);
            using var rawStream = new NetworkStream(clientSocket, true);
            using var clientStream = new CountingWriterStream(rawStream);
            using var handshakeCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            handshakeCts.CancelAfter(_timeout);

            var peekBuffer = new byte[1024];
            var bytesRead = 0;
            try
            {
                bytesRead = await clientStream.ReadAsync(peekBuffer.AsMemory(0, peekBuffer.Length), handshakeCts.Token);
            }
            catch
            {
                return;
            }

            if (bytesRead == 0)
                return;

            var firstByte = peekBuffer[0];
            if (firstByte == 0x05)
                await HandleSocks5Async(clientStream, peekBuffer, bytesRead, cancellationToken);
            else if (firstByte == 0x04)
            {
                using var combinedStream = new PrefixedStream(clientStream, peekBuffer, bytesRead, true);
                await HandleSocks4Async(combinedStream, clientStream, cancellationToken);
            }
            else if (firstByte == 0x16 && bytesRead >= 3 && peekBuffer[1] == 0x03)
            {
                using var combinedStream = new PrefixedStream(clientStream, peekBuffer, bytesRead, true);
                await HandleHttpsSniAsync(combinedStream, clientStream, peekBuffer, bytesRead, cancellationToken);
            }
            else
            {
                using var combinedStream = new PrefixedStream(clientStream, peekBuffer, bytesRead, true);
                await HandleHttpAsync(combinedStream, clientStream, cancellationToken);
            }
        }
    }

    private async Task HandleSocks5Async(CountingWriterStream clientStream, byte[] peekBuffer, int bytesRead, CancellationToken cancellationToken)
    {
        using var handshakeCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        handshakeCts.CancelAfter(_timeout);

        var nmethods = bytesRead > 1 ? peekBuffer[1] : clientStream.ReadByte();
        if (nmethods < 0)
            return;

        var greetingLength = 2 + nmethods;
        if (bytesRead < greetingLength)
        {
            var missing = greetingLength - bytesRead;
            var missingBuf = new byte[missing];
            await ReadExactAsync(clientStream, missingBuf, missing, handshakeCts.Token);
        }

        Stream requestStream = clientStream;
        PrefixedStream? extraStream = null;

        if (_auth != null)
        {
            await clientStream.WriteAsync(new byte[] { 0x05, 0x02 }, handshakeCts.Token);

            var authHeader = new byte[2];
            await ReadExactAsync(clientStream, authHeader, 2, handshakeCts.Token);
            if (authHeader[0] != 0x01)
            {
                await clientStream.WriteAsync(new byte[] { 0x01, 0xFF }, cancellationToken);
                LogRequest("SOCKS5", "socks5://client", "407", clientStream.BytesWritten);
                return;
            }

            var ulen = authHeader[1];
            var ubuf = new byte[ulen];
            await ReadExactAsync(clientStream, ubuf, ulen, handshakeCts.Token);
            var username = Encoding.UTF8.GetString(ubuf);

            var plenBuf = new byte[1];
            await ReadExactAsync(clientStream, plenBuf, 1, handshakeCts.Token);
            var plen = plenBuf[0];
            var pbuf = new byte[plen];
            await ReadExactAsync(clientStream, pbuf, plen, handshakeCts.Token);
            var password = Encoding.UTF8.GetString(pbuf);

            if (username != _auth.Username || password != _auth.Password)
            {
                await clientStream.WriteAsync(new byte[] { 0x01, 0xFF }, cancellationToken);
                LogRequest("SOCKS5", "socks5://client", "407", clientStream.BytesWritten);
                return;
            }

            await clientStream.WriteAsync(new byte[] { 0x01, 0x00 }, handshakeCts.Token);
        }
        else
        {
            await clientStream.WriteAsync(new byte[] { 0x05, 0x00 }, handshakeCts.Token);
            if (bytesRead > greetingLength)
            {
                var extraCount = bytesRead - greetingLength;
                var extraBytes = new byte[extraCount];
                Array.Copy(peekBuffer, greetingLength, extraBytes, 0, extraCount);
                extraStream = new PrefixedStream(clientStream, extraBytes, extraCount, true);
                requestStream = extraStream;
            }
        }

        try
        {
            var header = new byte[4];
            await ReadExactAsync(requestStream, header, 4, handshakeCts.Token);

            var cmd = header[1];
            if (cmd != 0x01)
            {
                await clientStream.WriteAsync(new byte[] { 0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0 }, cancellationToken);
                return;
            }

            var atyp = header[3];
            string targetHost;
            if (atyp == 0x01)
            {
                var ipBuf = new byte[4];
                await ReadExactAsync(requestStream, ipBuf, 4, handshakeCts.Token);
                targetHost = new IPAddress(ipBuf).ToString();
            }
            else if (atyp == 0x03)
            {
                var lenBuf = new byte[1];
                await ReadExactAsync(requestStream, lenBuf, 1, handshakeCts.Token);
                var len = lenBuf[0];
                var domainBuf = new byte[len];
                await ReadExactAsync(requestStream, domainBuf, len, handshakeCts.Token);
                targetHost = Encoding.ASCII.GetString(domainBuf);
            }
            else if (atyp == 0x04)
            {
                var ipBuf = new byte[16];
                await ReadExactAsync(requestStream, ipBuf, 16, handshakeCts.Token);
                targetHost = new IPAddress(ipBuf).ToString();
            }
            else
            {
                await clientStream.WriteAsync(new byte[] { 0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0 }, cancellationToken);
                return;
            }

            var portBuf = new byte[2];
            await ReadExactAsync(requestStream, portBuf, 2, handshakeCts.Token);
            var targetPort = BinaryPrimitives.ReadUInt16BigEndian(portBuf);

            var url = $"socks5://{targetHost}:{targetPort}";
            Stream? upstreamStream = null;
            try
            {
                upstreamStream = await ConnectUpstreamAsync(targetHost, targetPort, cancellationToken);
                await clientStream.WriteAsync(new byte[] { 0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0 }, cancellationToken);
                await RelayBidirectionalAsync(requestStream, upstreamStream, _timeout, cancellationToken);
                LogRequest("SOCKS5", url, "200", clientStream.BytesWritten);
            }
            catch (Exception)
            {
                LogRequest("SOCKS5", url, "503", clientStream.BytesWritten);
                try
                {
                    await clientStream.WriteAsync(new byte[] { 0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0 }, cancellationToken);
                }
                catch
                {
                }
            }
            finally
            {
                upstreamStream?.Dispose();
            }
        }
        finally
        {
            extraStream?.Dispose();
        }
    }

    private async Task HandleSocks4Async(Stream inputCombinedStream, CountingWriterStream clientStream, CancellationToken cancellationToken)
    {
        using var handshakeCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        handshakeCts.CancelAfter(_timeout);

        var header = new byte[8];
        await ReadExactAsync(inputCombinedStream, header, 8, handshakeCts.Token);

        var cd = header[1];
        if (cd != 0x01)
        {
            await clientStream.WriteAsync(new byte[] { 0x00, 0x5B, 0, 0, 0, 0, 0, 0 }, cancellationToken);
            return;
        }

        var port = BinaryPrimitives.ReadUInt16BigEndian(header.AsSpan(2, 2));
        var ipBytes = header.AsSpan(4, 4);
        var isSocks4A = ipBytes[0] == 0 && ipBytes[1] == 0 && ipBytes[2] == 0 && ipBytes[3] != 0;

        var userIdBytes = new List<byte>();
        while (true)
        {
            var b = inputCombinedStream.ReadByte();
            if (b <= 0)
                break;
            userIdBytes.Add((byte)b);
        }

        if (_auth != null)
        {
            var username = Encoding.UTF8.GetString(userIdBytes.ToArray());
            if (username != _auth.Username)
            {
                await clientStream.WriteAsync(new byte[] { 0x00, 0x5B, 0, 0, 0, 0, 0, 0 }, cancellationToken);
                LogRequest("SOCKS4", "socks4://client", "407", clientStream.BytesWritten);
                return;
            }
        }

        string targetHost;
        if (isSocks4A)
        {
            var domainBytes = new List<byte>();
            while (true)
            {
                var b = inputCombinedStream.ReadByte();
                if (b <= 0)
                    break;
                domainBytes.Add((byte)b);
            }
            targetHost = Encoding.ASCII.GetString(domainBytes.ToArray());
        }
        else
            targetHost = new IPAddress(ipBytes).ToString();

        var url = $"socks4://{targetHost}:{port}";
        Stream? upstreamStream = null;
        try
        {
            upstreamStream = await ConnectUpstreamAsync(targetHost, port, cancellationToken);
            await clientStream.WriteAsync(new byte[] { 0x00, 0x5A, 0, 0, 0, 0, 0, 0 }, cancellationToken);
            await RelayBidirectionalAsync(inputCombinedStream, upstreamStream, _timeout, cancellationToken);
            LogRequest("SOCKS4", url, "200", clientStream.BytesWritten);
        }
        catch (Exception)
        {
            LogRequest("SOCKS4", url, "503", clientStream.BytesWritten);
            try
            {
                await clientStream.WriteAsync(new byte[] { 0x00, 0x5B, 0, 0, 0, 0, 0, 0 }, cancellationToken);
            }
            catch
            {
            }
        }
        finally
        {
            upstreamStream?.Dispose();
        }
    }

    private async Task HandleHttpsSniAsync(Stream inputCombinedStream, CountingWriterStream clientStream, byte[] initialBuffer, int initialCount, CancellationToken cancellationToken)
    {
        var sni = ExtractSni(initialBuffer, initialCount);
        if (string.IsNullOrWhiteSpace(sni))
        {
            await HandleHttpAsync(inputCombinedStream, clientStream, cancellationToken);
            return;
        }

        var url = $"https://{sni}:443";
        Stream? upstreamStream = null;
        try
        {
            upstreamStream = await ConnectUpstreamAsync(sni, 443, cancellationToken);
            await RelayBidirectionalAsync(inputCombinedStream, upstreamStream, _timeout, cancellationToken);
            LogRequest("TLS-SNI", url, "200", clientStream.BytesWritten);
        }
        catch (Exception)
        {
            LogRequest("TLS-SNI", url, "503", clientStream.BytesWritten);
        }
        finally
        {
            upstreamStream?.Dispose();
        }
    }

    private async Task HandleHttpAsync(Stream inputCombinedStream, CountingWriterStream clientStream, CancellationToken cancellationToken)
    {
        using var handshakeCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        handshakeCts.CancelAfter(_timeout);

        using var reader = new NonClosingStreamReader(inputCombinedStream, Encoding.ASCII);
        var requestLine = await reader.ReadLineAsync(handshakeCts.Token);
        if (string.IsNullOrWhiteSpace(requestLine))
            return;

        var lineParts = requestLine.Split(' ');
        if (lineParts.Length < 3)
            return;

        var method = lineParts[0];
        var target = lineParts[1];
        var version = lineParts[2];

        var headers = new List<string>();
        string? hostHeader = null;
        string? proxyAuthHeader = null;

        while (true)
        {
            var headerLine = await reader.ReadLineAsync(handshakeCts.Token);
            if (string.IsNullOrEmpty(headerLine))
                break;

            if (headerLine.StartsWith("Host:", StringComparison.OrdinalIgnoreCase))
                hostHeader = headerLine["Host:".Length..].Trim();
            else if (headerLine.StartsWith("Proxy-Authorization:", StringComparison.OrdinalIgnoreCase))
                proxyAuthHeader = headerLine["Proxy-Authorization:".Length..].Trim();

            if (!headerLine.StartsWith("Proxy-Connection:", StringComparison.OrdinalIgnoreCase) &&
                !headerLine.StartsWith("Proxy-Authorization:", StringComparison.OrdinalIgnoreCase))
                headers.Add(headerLine);
        }

        if (_auth != null)
        {
            var authenticated = false;
            if (!string.IsNullOrEmpty(proxyAuthHeader) && proxyAuthHeader.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    var raw = Convert.FromBase64String(proxyAuthHeader["Basic ".Length..].Trim());
                    var creds = Encoding.UTF8.GetString(raw).Split(':');
                    if (creds.Length >= 2 && creds[0] == _auth.Username && creds[1] == _auth.Password)
                        authenticated = true;
                }
                catch
                {
                }
            }

            if (!authenticated)
            {
                var unauthorizedResponse = Encoding.ASCII.GetBytes("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Prxy\"\r\nContent-Length: 12\r\n\r\nUnauthorized");
                await clientStream.WriteAsync(unauthorizedResponse, cancellationToken);
                LogRequest(method, target, "407", clientStream.BytesWritten);
                return;
            }
        }

        if (string.Equals(method, "CONNECT", StringComparison.OrdinalIgnoreCase))
        {
            var hostPort = target.Split(':');
            var host = hostPort[0];
            var port = hostPort.Length > 1 && int.TryParse(hostPort[1], out var p) ? p : 443;
            var url = $"https://{host}:{port}";

            Stream? upstreamStream = null;
            try
            {
                upstreamStream = await ConnectUpstreamAsync(host, port, cancellationToken);
                var okResponse = Encoding.ASCII.GetBytes("HTTP/1.1 200 Connection Established\r\n\r\n");
                await clientStream.WriteAsync(okResponse, cancellationToken);
                await RelayBidirectionalAsync(inputCombinedStream, upstreamStream, _timeout, cancellationToken);
                LogRequest("CONNECT", url, "200", clientStream.BytesWritten);
            }
            catch (Exception)
            {
                LogRequest("CONNECT", url, "503", clientStream.BytesWritten);
                var errorResponse = Encoding.ASCII.GetBytes("HTTP/1.1 503 Service Unavailable\r\n\r\n");
                try
                {
                    await clientStream.WriteAsync(errorResponse, cancellationToken);
                }
                catch
                {
                }
            }
            finally
            {
                upstreamStream?.Dispose();
            }
        }
        else
        {
            string host;
            int port;
            string pathAndQuery;

            if (Uri.TryCreate(target, UriKind.Absolute, out var uri))
            {
                host = uri.Host;
                port = uri.Port > 0 ? uri.Port : 80;
                pathAndQuery = uri.PathAndQuery;
            }
            else
            {
                host = hostHeader ?? "localhost";
                var parts = host.Split(':');
                host = parts[0];
                port = parts.Length > 1 && int.TryParse(parts[1], out var p) ? p : 80;
                pathAndQuery = target;
            }

            var requestUrl = $"http://{host}:{port}{pathAndQuery}";
            Stream? upstreamStream = null;
            try
            {
                upstreamStream = await ConnectUpstreamAsync(host, port, cancellationToken);

                var sb = new StringBuilder();
                sb.Append($"{method} {pathAndQuery} {version}\r\n");
                for (var i = 0; i < headers.Count; i++)
                    sb.Append($"{headers[i]}\r\n");
                sb.Append("\r\n");

                var headerBytes = Encoding.ASCII.GetBytes(sb.ToString());
                await upstreamStream.WriteAsync(headerBytes, cancellationToken);

                await RelayBidirectionalAsync(inputCombinedStream, upstreamStream, _timeout, cancellationToken);
                LogRequest(method, requestUrl, "200", clientStream.BytesWritten);
            }
            catch (Exception)
            {
                LogRequest(method, requestUrl, "503", clientStream.BytesWritten);
                var errorResponse = Encoding.ASCII.GetBytes("HTTP/1.1 503 Service Unavailable\r\n\r\n");
                try
                {
                    await clientStream.WriteAsync(errorResponse, cancellationToken);
                }
                catch
                {
                }
            }
            finally
            {
                upstreamStream?.Dispose();
            }
        }
    }

    private async Task<Stream> ConnectUpstreamAsync(string targetHost, int targetPort, CancellationToken cancellationToken)
    {
        using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        connectCts.CancelAfter(_timeout);

        if (_upstreamProxy == null)
        {
            var tcpClient = new TcpClient();
            ConfigureSocket(tcpClient.Client);
            await tcpClient.ConnectAsync(targetHost, targetPort, connectCts.Token);
            return tcpClient.GetStream();
        }

        var proxyTcp = new TcpClient();
        ConfigureSocket(proxyTcp.Client);
        await proxyTcp.ConnectAsync(_upstreamProxy.Host, _upstreamProxy.Port, connectCts.Token);
        var baseStream = proxyTcp.GetStream();

        if (string.Equals(_upstreamProxy.Scheme, "socks5", StringComparison.OrdinalIgnoreCase))
            return await UpstreamSocks5ConnectAsync(baseStream, _upstreamProxy, targetHost, targetPort, connectCts.Token);

        if (string.Equals(_upstreamProxy.Scheme, "socks4", StringComparison.OrdinalIgnoreCase))
            return await UpstreamSocks4ConnectAsync(baseStream, targetHost, targetPort, connectCts.Token);

        if (string.Equals(_upstreamProxy.Scheme, "https", StringComparison.OrdinalIgnoreCase))
        {
            var sslOptions = new SslClientAuthenticationOptions
            {
                TargetHost = _upstreamProxy.Host,
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13
            };
            if (_insecure)
            {
                sslOptions.RemoteCertificateValidationCallback = (sender, cert, chain, errors) => true;
                sslOptions.CertificateRevocationCheckMode = System.Security.Cryptography.X509Certificates.X509RevocationMode.NoCheck;
            }
            var sslStream = new SslStream(baseStream, false, _insecure ? (sender, cert, chain, errors) => true : null);
            await sslStream.AuthenticateAsClientAsync(sslOptions, connectCts.Token);
            return await UpstreamHttpConnectAsync(sslStream, _upstreamProxy, targetHost, targetPort, connectCts.Token);
        }

        return await UpstreamHttpConnectAsync(baseStream, _upstreamProxy, targetHost, targetPort, connectCts.Token);
    }

    private static async Task<Stream> UpstreamSocks5ConnectAsync(Stream stream, UpstreamProxy proxy, string targetHost, int targetPort, CancellationToken cancellationToken)
    {
        var hasAuth = !string.IsNullOrEmpty(proxy.Username);
        if (hasAuth)
            await stream.WriteAsync(new byte[] { 0x05, 0x02, 0x00, 0x02 }, cancellationToken);
        else
            await stream.WriteAsync(new byte[] { 0x05, 0x01, 0x00 }, cancellationToken);

        var methodResponse = new byte[2];
        await ReadExactAsync(stream, methodResponse, 2, cancellationToken);

        if (methodResponse[1] == 0x02 && hasAuth)
        {
            var userBytes = Encoding.UTF8.GetBytes(proxy.Username!);
            var passBytes = Encoding.UTF8.GetBytes(proxy.Password ?? string.Empty);
            var authReq = new byte[3 + userBytes.Length + passBytes.Length];
            authReq[0] = 0x01;
            authReq[1] = (byte)userBytes.Length;
            Array.Copy(userBytes, 0, authReq, 2, userBytes.Length);
            authReq[2 + userBytes.Length] = (byte)passBytes.Length;
            Array.Copy(passBytes, 0, authReq, 3 + userBytes.Length, passBytes.Length);

            await stream.WriteAsync(authReq, cancellationToken);
            var authResp = new byte[2];
            await ReadExactAsync(stream, authResp, 2, cancellationToken);
            if (authResp[1] != 0x00)
                throw new InvalidOperationException("SOCKS5 upstream authentication failed.");
        }
        else if (methodResponse[1] != 0x00)
            throw new InvalidOperationException("SOCKS5 upstream unsupported authentication method.");

        var hostBytes = Encoding.ASCII.GetBytes(targetHost);
        var request = new byte[7 + hostBytes.Length];
        request[0] = 0x05;
        request[1] = 0x01;
        request[2] = 0x00;
        request[3] = 0x03;
        request[4] = (byte)hostBytes.Length;
        Array.Copy(hostBytes, 0, request, 5, hostBytes.Length);
        BinaryPrimitives.WriteUInt16BigEndian(request.AsSpan(5 + hostBytes.Length, 2), (ushort)targetPort);

        await stream.WriteAsync(request, cancellationToken);

        var respHeader = new byte[4];
        await ReadExactAsync(stream, respHeader, 4, cancellationToken);
        if (respHeader[1] != 0x00)
            throw new InvalidOperationException($"SOCKS5 upstream connect failed: {respHeader[1]}.");

        var atyp = respHeader[3];
        if (atyp == 0x01)
        {
            var buf = new byte[6];
            await ReadExactAsync(stream, buf, 6, cancellationToken);
        }
        else if (atyp == 0x03)
        {
            var len = stream.ReadByte();
            var buf = new byte[len + 2];
            await ReadExactAsync(stream, buf, len + 2, cancellationToken);
        }
        else if (atyp == 0x04)
        {
            var buf = new byte[18];
            await ReadExactAsync(stream, buf, 18, cancellationToken);
        }

        return stream;
    }

    private static async Task<Stream> UpstreamSocks4ConnectAsync(Stream stream, string targetHost, int targetPort, CancellationToken cancellationToken)
    {
        var domainBytes = Encoding.ASCII.GetBytes(targetHost);
        var req = new byte[9 + domainBytes.Length + 1];
        req[0] = 0x04;
        req[1] = 0x01;
        BinaryPrimitives.WriteUInt16BigEndian(req.AsSpan(2, 2), (ushort)targetPort);
        req[4] = 0;
        req[5] = 0;
        req[6] = 0;
        req[7] = 1;
        req[8] = 0;
        Array.Copy(domainBytes, 0, req, 9, domainBytes.Length);
        req[^1] = 0;

        await stream.WriteAsync(req, cancellationToken);

        var resp = new byte[8];
        await ReadExactAsync(stream, resp, 8, cancellationToken);
        if (resp[1] != 0x5A)
            throw new InvalidOperationException($"SOCKS4 upstream connect failed: {resp[1]}.");

        return stream;
    }

    private static async Task<Stream> UpstreamHttpConnectAsync(Stream stream, UpstreamProxy proxy, string targetHost, int targetPort, CancellationToken cancellationToken)
    {
        var sb = new StringBuilder();
        sb.Append($"CONNECT {targetHost}:{targetPort} HTTP/1.1\r\n");
        sb.Append($"Host: {targetHost}:{targetPort}\r\n");
        if (!string.IsNullOrEmpty(proxy.Username))
        {
            var creds = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{proxy.Username}:{proxy.Password}"));
            sb.Append($"Proxy-Authorization: Basic {creds}\r\n");
        }
        sb.Append("\r\n");

        var connectBytes = Encoding.ASCII.GetBytes(sb.ToString());
        await stream.WriteAsync(connectBytes, cancellationToken);

        using var reader = new NonClosingStreamReader(stream, Encoding.ASCII);
        var responseLine = await reader.ReadLineAsync(cancellationToken);
        if (string.IsNullOrWhiteSpace(responseLine) || !responseLine.Contains(" 200 "))
            throw new InvalidOperationException($"HTTP upstream CONNECT failed: {responseLine}.");

        while (true)
        {
            var line = await reader.ReadLineAsync(cancellationToken);
            if (string.IsNullOrEmpty(line))
                break;
        }

        return stream;
    }

    private static string? ExtractSni(byte[] buffer, int length)
    {
        try
        {
            if (length < 43 || buffer[0] != 0x16)
                return null;

            var handshakeType = buffer[5];
            if (handshakeType != 0x01)
                return null;

            var pos = 43;
            if (pos >= length)
                return null;

            var sessionIdLen = buffer[pos++];
            pos += sessionIdLen;
            if (pos + 2 > length)
                return null;

            var cipherSuitesLen = BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(pos, 2));
            pos += 2 + cipherSuitesLen;
            if (pos >= length)
                return null;

            var compressionMethodsLen = buffer[pos++];
            pos += compressionMethodsLen;
            if (pos + 2 > length)
                return null;

            var extensionsLen = BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(pos, 2));
            pos += 2;

            var extensionsEnd = Math.Min(length, pos + extensionsLen);
            while (pos + 4 <= extensionsEnd)
            {
                var extType = BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(pos, 2));
                var extLen = BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(pos + 2, 2));
                pos += 4;

                if (extType == 0x0000 && pos + extLen <= extensionsEnd)
                {
                    var listLen = BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(pos, 2));
                    var serverNamePos = pos + 2;
                    if (serverNamePos + 3 <= pos + extLen)
                    {
                        var nameType = buffer[serverNamePos];
                        if (nameType == 0)
                        {
                            var nameLen = BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(serverNamePos + 1, 2));
                            if (serverNamePos + 3 + nameLen <= pos + extLen)
                                return Encoding.ASCII.GetString(buffer, serverNamePos + 3, nameLen);
                        }
                    }
                }

                pos += extLen;
            }
        }
        catch
        {
        }

        return null;
    }

    private static async Task RelayBidirectionalAsync(Stream clientStream, Stream upstreamStream, TimeSpan idleTimeout, CancellationToken cancellationToken)
    {
        using var sessionCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        long lastActivity = Environment.TickCount64;
        var timeoutMs = (long)idleTimeout.TotalMilliseconds;

        void OnActivity() => Interlocked.Exchange(ref lastActivity, Environment.TickCount64);

        _ = Task.Run(async () =>
        {
            var checkInterval = Math.Min(1000, Math.Max(100, (int)(timeoutMs / 4)));
            while (!sessionCts.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(checkInterval, sessionCts.Token);
                }
                catch
                {
                    break;
                }

                if (Environment.TickCount64 - Interlocked.Read(ref lastActivity) >= timeoutMs)
                {
                    sessionCts.Cancel();
                    break;
                }
            }
        }, sessionCts.Token);

        var clientToUpstream = RelayDirectionAsync(clientStream, upstreamStream, OnActivity, sessionCts.Token);
        var upstreamToClient = RelayDirectionAsync(upstreamStream, clientStream, OnActivity, sessionCts.Token);

        var completedFirst = await Task.WhenAny(clientToUpstream, upstreamToClient);
        if (completedFirst == upstreamToClient)
            sessionCts.Cancel();
        else
        {
            try
            {
                await upstreamToClient;
            }
            catch
            {
            }
            sessionCts.Cancel();
        }

        try
        {
            await Task.WhenAll(clientToUpstream, upstreamToClient);
        }
        catch
        {
        }
    }

    private static async Task RelayDirectionAsync(Stream source, Stream destination, Action onActivity, CancellationToken cancellationToken)
    {
        var buffer = new byte[81920];
        while (!cancellationToken.IsCancellationRequested)
        {
            int bytesRead;
            try
            {
                bytesRead = await source.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken);
            }
            catch
            {
                break;
            }

            if (bytesRead == 0)
                break;

            onActivity();

            try
            {
                await destination.WriteAsync(buffer.AsMemory(0, bytesRead), cancellationToken);
            }
            catch
            {
                break;
            }

            onActivity();
        }
    }

    private static async Task ReadExactAsync(Stream stream, Memory<byte> buffer, int totalBytes, CancellationToken cancellationToken)
    {
        var readTotal = 0;
        while (readTotal < totalBytes)
        {
            var read = await stream.ReadAsync(buffer[readTotal..totalBytes], cancellationToken);
            if (read == 0)
                throw new EndOfStreamException();
            readTotal += read;
        }
    }

    private static void ConfigureSocket(Socket socket)
    {
        socket.NoDelay = true;
        socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
        socket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveTime, 30);
        socket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveInterval, 5);
        socket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveRetryCount, 5);
    }

    private static UpstreamProxy ParseForwardUrl(string forwardUrl)
    {
        var uri = new Uri(forwardUrl);
        var scheme = uri.Scheme.ToLowerInvariant();
        var host = uri.Host;
        var port = uri.Port > 0 ? uri.Port : (scheme == "https" ? 443 : 80);
        string? username = null;
        string? password = null;

        if (!string.IsNullOrEmpty(uri.UserInfo))
        {
            var parts = uri.UserInfo.Split(':');
            username = Uri.UnescapeDataString(parts[0]);
            if (parts.Length > 1)
                password = Uri.UnescapeDataString(parts[1]);
        }

        return new UpstreamProxy(scheme, host, port, username, password);
    }

    private static string FormatBytes(long bytes)
    {
        if (bytes < 1024)
            return $"{bytes} B";
        if (bytes < 1024 * 1024)
            return $"{(double)bytes / 1024:F1} KB";
        return $"{(double)bytes / (1024 * 1024):F2} MB";
    }

    private void LogRequest(string method, string url, string status, long bytes)
    {
        if (_log)
            Console.WriteLine($"[{method}] {url} -> {status} ({FormatBytes(bytes)})");
    }
}
