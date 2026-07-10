
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;

var portSpec = args.Length > 0 ? args[0] : PromptForPortSpec();

if (!TryParsePorts(portSpec, out var ports, out var parseError))
{
	Console.Error.WriteLine($"Invalid port specification: {parseError}");
	Environment.ExitCode = 1;
	return;
}

if (ports.Count < 2)
{
	Console.Error.WriteLine("Provide at least two ports so scan detection is meaningful.");
	Environment.ExitCode = 1;
	return;
}

var detector = new PortScanDetector(ports, TimeSpan.FromSeconds(30));
var cts = new CancellationTokenSource();

ConsoleCancelEventHandler cancelKeyPressHandler = (_, eventArgs) =>
{
	eventArgs.Cancel = true;
	TryCancel(cts);
};

EventHandler processExitHandler = (_, _) => TryCancel(cts);

Console.CancelKeyPress += cancelKeyPressHandler;
AppDomain.CurrentDomain.ProcessExit += processExitHandler;

List<PortListener> listeners = [];

try
{
	foreach (var port in ports)
	{
		try
		{
			var listener = new PortListener(port, detector);
			await listener.StartAsync(cts.Token);
			listeners.Add(listener);
		}
		catch (SocketException ex) when (ex.SocketErrorCode == SocketError.AccessDenied)
		{
			Console.Error.WriteLine($"Failed to bind port {port} due to insufficient privileges.");
			Console.Error.WriteLine("On Linux, ports below 1024 usually require root or CAP_NET_BIND_SERVICE.");
			Console.Error.WriteLine($"Details: {ex.Message}");
			Environment.ExitCode = 1;
			return;
		}
		catch (SocketException ex) when (ex.SocketErrorCode == SocketError.AddressAlreadyInUse)
		{
			Console.Error.WriteLine($"Failed to bind port {port} because it is already in use.");
			Console.Error.WriteLine($"Details: {ex.Message}");
			Environment.ExitCode = 1;
			return;
		}
	}

	Console.WriteLine("Port scan monitor started.");
	Console.WriteLine($"Monitoring {ports.Count} port(s): {string.Join(", ", ports)}");
	Console.WriteLine("Detection rule: one source IP reaches every monitored port within 30 seconds.");
	Console.WriteLine("Press Ctrl+C to stop.");
	Console.WriteLine();

	await Task.Delay(Timeout.Infinite, cts.Token);
}
catch (OperationCanceledException)
{
}
finally
{
	AppDomain.CurrentDomain.ProcessExit -= processExitHandler;
	Console.CancelKeyPress -= cancelKeyPressHandler;

	foreach (var listener in listeners)
	{
		listener.Dispose();
	}

	cts.Dispose();
}

return;

static void TryCancel(CancellationTokenSource cancellationTokenSource)
{
	try
	{
		if (!cancellationTokenSource.IsCancellationRequested)
		{
			cancellationTokenSource.Cancel();
		}
	}
	catch (ObjectDisposedException)
	{
	}
}

static string PromptForPortSpec()
{
	Console.Write("Enter ports to monitor (examples: 10-54 or 22,25,53,80,443): ");
	return Console.ReadLine()?.Trim() ?? string.Empty;
}

static bool TryParsePorts(string input, out List<int> ports, out string error)
{
	ports = [];
	error = string.Empty;

	if (string.IsNullOrWhiteSpace(input))
	{
		error = "the port list is empty";
		return false;
	}

	var uniquePorts = new SortedSet<int>();
	var segments = input.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

	foreach (var segment in segments)
	{
		if (segment.Contains('-', StringComparison.Ordinal))
		{
			var bounds = segment.Split('-', StringSplitOptions.TrimEntries);
			if (bounds.Length != 2 || !int.TryParse(bounds[0], out var start) || !int.TryParse(bounds[1], out var end))
			{
				error = $"'{segment}' is not a valid range";
				return false;
			}

			if (!IsValidPort(start) || !IsValidPort(end))
			{
				error = $"'{segment}' contains a port outside 1-65535";
				return false;
			}

			if (start > end)
			{
				error = $"range '{segment}' must be ascending";
				return false;
			}

			for (var port = start; port <= end; port++)
			{
				uniquePorts.Add(port);
			}

			continue;
		}

		if (!int.TryParse(segment, out var singlePort) || !IsValidPort(singlePort))
		{
			error = $"'{segment}' is not a valid port";
			return false;
		}

		uniquePorts.Add(singlePort);
	}

	ports = [.. uniquePorts];
	return true;
}

static bool IsValidPort(int port) => port is >= 1 and <= 65535;

internal sealed class PortListener : IDisposable
{
	private readonly int _port;
	private readonly TcpListener _listener;
	private readonly PortScanDetector _detector;

	public PortListener(int port, PortScanDetector detector)
	{
		_port = port;
		_detector = detector;
		_listener = new TcpListener(IPAddress.Any, port);
	}

	public Task StartAsync(CancellationToken cancellationToken)
	{
		_listener.Start();
		_ = AcceptLoopAsync(cancellationToken);
		return Task.CompletedTask;
	}

	public void Dispose()
	{
		_listener.Stop();
	}

	private async Task AcceptLoopAsync(CancellationToken cancellationToken)
	{
		while (!cancellationToken.IsCancellationRequested)
		{
			TcpClient? client = null;

			try
			{
				client = await _listener.AcceptTcpClientAsync(cancellationToken);

				if (client.Client.RemoteEndPoint is IPEndPoint remoteEndPoint)
				{
					_detector.RecordAttempt(remoteEndPoint.Address, _port, DateTimeOffset.UtcNow);
				}
			}
			catch (OperationCanceledException)
			{
				break;
			}
			catch (ObjectDisposedException) when (cancellationToken.IsCancellationRequested)
			{
				break;
			}
			catch (SocketException) when (cancellationToken.IsCancellationRequested)
			{
				break;
			}
			catch (SocketException ex)
			{
				Console.Error.WriteLine($"Listener error on port {_port}: {ex.Message}");
			}
			finally
			{
				client?.Dispose();
			}
		}
	}
}

internal sealed class PortScanDetector
{
	private readonly IReadOnlySet<int> _monitoredPorts;
	private readonly TimeSpan _window;
	private readonly ConcurrentDictionary<string, ScanState> _stateByAddress = new();
	private int _recordCount;

	public PortScanDetector(IReadOnlyCollection<int> monitoredPorts, TimeSpan window)
	{
		_monitoredPorts = monitoredPorts.ToHashSet();
		_window = window;
	}

	public void RecordAttempt(IPAddress sourceAddress, int port, DateTimeOffset timestamp)
	{
		if (Interlocked.Increment(ref _recordCount) % 256 == 0)
		{
			CleanupExpiredStates(timestamp);
		}

		var state = _stateByAddress.GetOrAdd(sourceAddress.ToString(), _ => new ScanState());
		ScanAlert? alert = null;

		lock (state.SyncRoot)
		{
			state.LastActivity = timestamp;
			PruneExpired(state, timestamp);
			var wasComplete = state.LastSeenByPort.Count == _monitoredPorts.Count;

			state.LastSeenByPort[port] = timestamp;
			PruneExpired(state, timestamp);

			if (!wasComplete && state.LastSeenByPort.Count == _monitoredPorts.Count)
			{
				var firstSeen = state.LastSeenByPort.Values.Min();
				var lastSeen = state.LastSeenByPort.Values.Max();
				alert = new ScanAlert(sourceAddress.ToString(), [.. state.LastSeenByPort.Keys.Order()], firstSeen, lastSeen);
			}
		}

		if (alert is not null)
		{
			WriteAlert(alert);
		}
	}

	private void PruneExpired(ScanState state, DateTimeOffset now)
	{
		var expiryCutoff = now - _window;
		foreach (var entry in state.LastSeenByPort.ToArray())
		{
			if (entry.Value < expiryCutoff)
			{
				state.LastSeenByPort.Remove(entry.Key);
			}
		}
	}

	private void CleanupExpiredStates(DateTimeOffset now)
	{
		var expiryCutoff = now - _window;

		foreach (var entry in _stateByAddress)
		{
			var state = entry.Value;
			var shouldRemove = false;

			lock (state.SyncRoot)
			{
				PruneExpired(state, now);
				shouldRemove = state.LastSeenByPort.Count == 0 && state.LastActivity < expiryCutoff;
			}

			if (shouldRemove)
			{
				_stateByAddress.TryRemove(entry.Key, out _);
			}
		}
	}

	private static void WriteAlert(ScanAlert alert)
	{
		var previousColor = Console.ForegroundColor;
		Console.ForegroundColor = ConsoleColor.Red;
		Console.WriteLine($"[{DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss}] Port scan detected");
		Console.ForegroundColor = previousColor;
		Console.WriteLine($"  Source IP : {alert.SourceAddress}");
		Console.WriteLine($"  Ports     : {string.Join(", ", alert.Ports)}");
		Console.WriteLine($"  First hit : {alert.FirstSeen:O}");
		Console.WriteLine($"  Last hit  : {alert.LastSeen:O}");
		Console.WriteLine($"  Duration  : {(alert.LastSeen - alert.FirstSeen).TotalSeconds:F1} seconds");
		Console.WriteLine();
	}

	private sealed class ScanState
	{
		public object SyncRoot { get; } = new();

		public Dictionary<int, DateTimeOffset> LastSeenByPort { get; } = [];

		public DateTimeOffset LastActivity { get; set; } = DateTimeOffset.MinValue;
	}

	private sealed record ScanAlert(string SourceAddress, List<int> Ports, DateTimeOffset FirstSeen, DateTimeOffset LastSeen);
}