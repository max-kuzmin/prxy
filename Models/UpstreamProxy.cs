namespace Prxy.Models;

public sealed record UpstreamProxy(string Scheme, string Host, int Port, string? Username, string? Password);

