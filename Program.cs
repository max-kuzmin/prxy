using System.Net;
using Prxy.Models;

namespace Prxy;

public sealed class Program
{
    public static async Task<int> Main(string[] args)
    {
        var port = 8889;
        var bindAddress = IPAddress.Any;
        var timeoutSeconds = 60;
        var upstream = (string?)null;
        var auth = (AuthCredentials?)null;
        var log = false;
        var insecure = false;

        for (var i = 0; i < args.Length; i++)
        {
            var arg = args[i];
            if (string.Equals(arg, "--help", StringComparison.OrdinalIgnoreCase) || string.Equals(arg, "-h", StringComparison.OrdinalIgnoreCase))
            {
                PrintUsage();
                return 0;
            }
            else if (string.Equals(arg, "--log", StringComparison.OrdinalIgnoreCase))
                log = true;
            else if (string.Equals(arg, "--insecure", StringComparison.OrdinalIgnoreCase))
                insecure = true;
            else if (string.Equals(arg, "--port", StringComparison.OrdinalIgnoreCase))
            {
                if (i + 1 >= args.Length || !int.TryParse(args[++i], out var portVal) || portVal <= 0 || portVal > 65535)
                {
                    Console.Error.WriteLine("Error: Invalid or missing value for --port. Must be between 1 and 65535.");
                    PrintUsage();
                    return 1;
                }
                port = portVal;
            }
            else if (string.Equals(arg, "--bind", StringComparison.OrdinalIgnoreCase))
            {
                if (i + 1 >= args.Length || !IPAddress.TryParse(args[++i], out var ip))
                {
                    Console.Error.WriteLine("Error: Invalid or missing value for --bind. Must be a valid IP address.");
                    PrintUsage();
                    return 1;
                }
                bindAddress = ip;
            }
            else if (string.Equals(arg, "--auth", StringComparison.OrdinalIgnoreCase))
            {
                if (i + 1 >= args.Length || string.IsNullOrWhiteSpace(args[++i]))
                {
                    Console.Error.WriteLine("Error: Missing value for --auth.");
                    PrintUsage();
                    return 1;
                }
                var authParts = args[i].Split(':');
                if (authParts.Length < 2)
                {
                    Console.Error.WriteLine("Error: Invalid format for --auth. Must be 'username:password'.");
                    PrintUsage();
                    return 1;
                }
                auth = new AuthCredentials(authParts[0], authParts[1]);
            }
            else if (string.Equals(arg, "--upstream", StringComparison.OrdinalIgnoreCase))
            {
                if (i + 1 >= args.Length || string.IsNullOrWhiteSpace(args[++i]))
                {
                    Console.Error.WriteLine("Error: Missing value for --upstream.");
                    PrintUsage();
                    return 1;
                }
                upstream = args[i];
            }
            else if (string.Equals(arg, "--timeout", StringComparison.OrdinalIgnoreCase))
            {
                if (i + 1 >= args.Length || !int.TryParse(args[++i], out var timeoutVal) || timeoutVal <= 0)
                {
                    Console.Error.WriteLine("Error: Invalid or missing value for --timeout. Must be a positive integer.");
                    PrintUsage();
                    return 1;
                }
                timeoutSeconds = timeoutVal;
            }
            else
            {
                Console.Error.WriteLine($"Error: Unrecognized option '{arg}'.");
                PrintUsage();
                return 1;
            }
        }

        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (sender, eventArgs) =>
        {
            eventArgs.Cancel = true;
            cts.Cancel();
        };

        var server = new ProxyServer(bindAddress, port, upstream, auth, log, insecure, TimeSpan.FromSeconds(timeoutSeconds));
        await server.RunAsync(cts.Token);
        return 0;
    }

    private static void PrintUsage()
    {
        Console.WriteLine("Prxy - Multi-Protocol Proxy Server");
        Console.WriteLine();
        Console.WriteLine("Usage:");
        Console.WriteLine("  Prxy [options]");
        Console.WriteLine();
        Console.WriteLine("Options:");
        Console.WriteLine("  --port <number>       Port where proxy will listen (default: 8889)");
        Console.WriteLine("  --bind <address>      IP address to bind to (default: 0.0.0.0)");
        Console.WriteLine("  --auth <user:pass>    Require incoming client authentication (Basic for HTTP, RFC 1929 for SOCKS5)");
        Console.WriteLine("  --upstream <url>      Upstream proxy URL (accepts http, https, socks4, socks5)");
        Console.WriteLine("                        e.g. http://user:pass@host:port or socks5://host:port");
        Console.WriteLine("  --log                 Log requests (method, target URL, response status, payload size)");
        Console.WriteLine("  --insecure            Ignore all TLS/SSL certificate and validation errors");
        Console.WriteLine("  --timeout <seconds>   Connection and operation timeout in seconds (default: 60)");
        Console.WriteLine("  --help, -h            Show this help information");
        Console.WriteLine();
        Console.WriteLine("Examples:");
        Console.WriteLine("  Prxy");
        Console.WriteLine("  Prxy --port 8889 --log");
        Console.WriteLine("  Prxy --bind 127.0.0.1 --port 8889");
        Console.WriteLine("  Prxy --auth myuser:mypassword --log");
        Console.WriteLine("  Prxy --upstream \"http://user:pass@host:port\" --log --timeout 30");
    }
}
