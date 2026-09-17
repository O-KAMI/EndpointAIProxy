using Sf.EndpointAI.Client.Core.Configuration;

namespace Sf.EndpointAI.UnitTests;

public sealed class CcSwitchModeDetectorTests
{
    [Fact]
    public void Detects_local_proxy_per_app_without_requiring_listener_to_be_running()
    {
        var inspection = CreateInspection(new CcSwitchProxyConfigInspection(
            "claude",
            ProxyEnabled: true,
            Enabled: true,
            "127.0.0.1",
            15721,
            LiveTakeoverActive: true,
            HasLiveBackup: true));

        var result = CcSwitchModeDetector.Detect(
            "claude",
            inspection,
            new Uri("http://127.0.0.1:15721"));

        Assert.Equal(CcSwitchOperatingMode.LocalProxy, result.Mode);
        Assert.Equal(new Uri("http://127.0.0.1:15721"), result.ListenerOrigin);
    }

    [Fact]
    public void Accepts_codex_v1_listener_base()
    {
        var inspection = CreateInspection(new CcSwitchProxyConfigInspection(
            "codex",
            ProxyEnabled: true,
            Enabled: true,
            "0.0.0.0",
            15721,
            LiveTakeoverActive: true,
            HasLiveBackup: true));

        var result = CcSwitchModeDetector.Detect(
            "codex",
            inspection,
            new Uri("http://127.0.0.1:15721/v1"));

        Assert.Equal(CcSwitchOperatingMode.LocalProxy, result.Mode);
    }

    [Theory]
    [InlineData(false, "http://127.0.0.1:15721", true)]
    [InlineData(true, "https://api.anthropic.com", true)]
    [InlineData(true, "https://api.anthropic.com", false)]
    public void Contradictory_takeover_evidence_is_inconsistent(
        bool enabled,
        string liveBaseUrl,
        bool hasBackup)
    {
        var inspection = CreateInspection(new CcSwitchProxyConfigInspection(
            "claude",
            ProxyEnabled: enabled,
            Enabled: enabled,
            "127.0.0.1",
            15721,
            LiveTakeoverActive: enabled,
            HasLiveBackup: hasBackup));

        var result = CcSwitchModeDetector.Detect("claude", inspection, new Uri(liveBaseUrl));

        Assert.Equal(CcSwitchOperatingMode.Inconsistent, result.Mode);
        Assert.Equal("CCSWITCH_PROXY_STATE_INCONSISTENT", result.ErrorCode);
    }

    [Theory]
    [InlineData(false, false, false)]
    [InlineData(false, false, true)]
    [InlineData(false, true, false)]
    [InlineData(false, true, true)]
    [InlineData(true, false, false)]
    [InlineData(true, false, true)]
    [InlineData(true, true, false)]
    [InlineData(true, true, true)]
    public void Ordinary_mode_uses_per_app_enabled_and_live_config_only(
        bool proxyEnabled,
        bool liveTakeoverActive,
        bool hasBackup)
    {
        var inspection = CreateInspection(new CcSwitchProxyConfigInspection(
            "codex",
            proxyEnabled,
            Enabled: false,
            "127.0.0.1",
            15721,
            liveTakeoverActive,
            hasBackup));

        var result = CcSwitchModeDetector.Detect(
            "codex",
            inspection,
            new Uri("https://api.openai.com/v1"));

        Assert.Equal(CcSwitchOperatingMode.Ordinary, result.Mode);
        Assert.Equal(
            hasBackup ? "CCSWITCH_STALE_LIVE_BACKUP_IGNORED" : null,
            result.ErrorCode);
        Assert.Equal(proxyEnabled, result.Evidence!.ProxyEnabled);
        Assert.False(result.Evidence.AppEnabled);
        Assert.Equal(liveTakeoverActive, result.Evidence.LiveTakeoverActive);
        Assert.False(result.Evidence.LivePointsToListener);
        Assert.Equal(hasBackup, result.Evidence.HasLiveBackup);
    }

    [Fact]
    public void One_apps_listener_does_not_override_another_apps_ordinary_mode()
    {
        var inspection = new CcSwitchDatabaseInspection(
            11,
            new HashSet<string>(StringComparer.OrdinalIgnoreCase),
            [],
            [],
            new Dictionary<string, CcSwitchProxyConfigInspection>(StringComparer.Ordinal)
            {
                ["claude"] = new("claude", true, true, "127.0.0.1", 15721, true, true),
                ["codex"] = new("codex", true, false, "127.0.0.1", 15721, true, true),
            },
            ProxySchemaSupported: true,
            EndpointSchemaSupported: true);

        var claude = CcSwitchModeDetector.Detect(
            "claude",
            inspection,
            new Uri("http://127.0.0.1:15721"));
        var codex = CcSwitchModeDetector.Detect(
            "codex",
            inspection,
            new Uri("https://api.openai.com/v1"));

        Assert.Equal(CcSwitchOperatingMode.LocalProxy, claude.Mode);
        Assert.Equal(CcSwitchOperatingMode.Ordinary, codex.Mode);
        Assert.Equal("CCSWITCH_STALE_LIVE_BACKUP_IGNORED", codex.ErrorCode);
    }

    [Fact]
    public void Missing_legacy_proxy_table_is_ordinary()
    {
        var inspection = new CcSwitchDatabaseInspection(
            5,
            new HashSet<string>(StringComparer.OrdinalIgnoreCase),
            [],
            [],
            new Dictionary<string, CcSwitchProxyConfigInspection>(StringComparer.Ordinal),
            ProxySchemaSupported: true,
            EndpointSchemaSupported: true);

        var result = CcSwitchModeDetector.Detect(
            "claude",
            inspection,
            new Uri("https://api.anthropic.com"));

        Assert.Equal(CcSwitchOperatingMode.Ordinary, result.Mode);
    }

    [Fact]
    public void Unsupported_schema_blocks_mutation()
    {
        var inspection = CreateInspection(
            new CcSwitchProxyConfigInspection("claude", false, false, "127.0.0.1", 15721, false, false),
            proxySchemaSupported: false);

        var result = CcSwitchModeDetector.Detect(
            "claude",
            inspection,
            new Uri("https://api.anthropic.com"));

        Assert.Equal(CcSwitchOperatingMode.Unsupported, result.Mode);
        Assert.Equal("CCSWITCH_SCHEMA_UNSUPPORTED", result.ErrorCode);
    }

    [Fact]
    public void Mode_state_reports_per_app_and_mixed_manager_state()
    {
        var state = new CcSwitchModeState();
        state.Update(
            "S-1-5-21-mixed",
            [
                new CcSwitchAppModeStatus("claude", CcSwitchOperatingMode.Ordinary, null, null, null),
                new CcSwitchAppModeStatus(
                    "codex",
                    CcSwitchOperatingMode.LocalProxy,
                    new Uri("http://127.0.0.1:15721"),
                    true,
                    null),
            ]);

        Assert.Equal("ordinary", state.GetReportedMode("S-1-5-21-mixed", "claude"));
        Assert.Equal("local-proxy", state.GetReportedMode("S-1-5-21-mixed", "codex"));
        Assert.Equal("mixed", state.GetReportedMode("S-1-5-21-mixed"));
    }

    private static CcSwitchDatabaseInspection CreateInspection(
        CcSwitchProxyConfigInspection config,
        bool proxySchemaSupported = true) =>
        new(
            11,
            new HashSet<string>(StringComparer.OrdinalIgnoreCase),
            [],
            [],
            new Dictionary<string, CcSwitchProxyConfigInspection>(StringComparer.Ordinal)
            {
                [config.AppType] = config,
            },
            proxySchemaSupported,
            EndpointSchemaSupported: true);
}
