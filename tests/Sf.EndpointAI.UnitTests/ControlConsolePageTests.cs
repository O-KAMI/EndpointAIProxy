using System.Reflection;
using Sf.EndpointAI.ControlServer;

namespace Sf.EndpointAI.UnitTests;

public sealed class ControlConsolePageTests
{
    private static readonly string Html = ReadConsoleHtml();

    [Fact]
    public void Login_list_and_detail_are_separate_views()
    {
        Assert.Contains("id=\"authView\"", Html, StringComparison.Ordinal);
        Assert.Contains("id=\"appShell\" class=\"hidden\"", Html, StringComparison.Ordinal);
        Assert.Contains("id=\"listView\"", Html, StringComparison.Ordinal);
        Assert.Contains("id=\"detailView\" class=\"hidden\"", Html, StringComparison.Ordinal);
        Assert.Contains("function showLogin", Html, StringComparison.Ordinal);
        Assert.Contains("function showList", Html, StringComparison.Ordinal);
        Assert.Contains("function showDetailView", Html, StringComparison.Ordinal);
        Assert.DoesNotContain("已连接", Html, StringComparison.Ordinal);
    }

    [Fact]
    public void Authentication_failures_restore_the_login_view()
    {
        Assert.Contains("r.status===401||r.status===403", Html, StringComparison.Ordinal);
        Assert.Contains("showLogin('登录已失效，请重新登录。')", Html, StringComparison.Ordinal);
        Assert.Contains("sessionStorage.setItem('sf-admin-token'", Html, StringComparison.Ordinal);
        Assert.Contains("sessionStorage.setItem('sf-admin-actor'", Html, StringComparison.Ordinal);
    }

    [Fact]
    public void Detail_uses_a_relationship_matrix_instead_of_raw_json()
    {
        Assert.Contains("Agent 与模型代理关系", Html, StringComparison.Ordinal);
        Assert.Contains("原始目标 Base URL", Html, StringComparison.Ordinal);
        Assert.Contains("实际配置 / 代理 Base URL", Html, StringComparison.Ordinal);
        Assert.Contains("真实请求结果", Html, StringComparison.Ordinal);
        Assert.Contains("返回终端列表", Html, StringComparison.Ordinal);
        Assert.Contains("未启用配置", Html, StringComparison.Ordinal);
        Assert.DoesNotContain("<pre", Html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("JSON.stringify({runtime", Html, StringComparison.Ordinal);
    }

    [Fact]
    public void Endpoint_groups_use_stable_configuration_identity_and_exclude_cc_switch_agents()
    {
        Assert.Contains("endpoint.userSid+'|'+endpoint.agentFamily", Html, StringComparison.Ordinal);
        Assert.Contains("function logicalEndpointKey", Html, StringComparison.Ordinal);
        Assert.Contains("function mergeEndpointObservations", Html, StringComparison.Ordinal);
        Assert.Contains("function confirmedAgents", Html, StringComparison.Ordinal);
        Assert.Contains("!isCcSwitchAgent(agent)&&!isSuspectedAgent(agent)", Html, StringComparison.Ordinal);
        Assert.Contains("ccSwitchProvider:'CC Switch Provider'", Html, StringComparison.Ordinal);
        Assert.Contains("ccSwitchEndpoint:'CC Switch Endpoint'", Html, StringComparison.Ordinal);
        Assert.DoesNotContain("standalone.push", Html, StringComparison.Ordinal);
    }

    [Fact]
    public void Models_are_grouped_once_with_provider_endpoint_relationships()
    {
        Assert.Contains("function groupModels", Html, StringComparison.Ordinal);
        Assert.Contains("model-cluster-title", Html, StringComparison.Ordinal);
        Assert.Contains("↳ CC Switch Endpoint", Html, StringComparison.Ordinal);
        Assert.Contains("个配置关系", Html, StringComparison.Ordinal);
        Assert.Contains("inactive-configs", Html, StringComparison.Ordinal);
        Assert.Contains("endpoint.isCurrent", Html, StringComparison.Ordinal);
    }

    [Fact]
    public void Detail_auto_refreshes_without_overlapping_and_stops_outside_the_visible_detail_view()
    {
        Assert.Contains("DetailRefreshIntervalMilliseconds=15000", Html, StringComparison.Ordinal);
        Assert.Contains("detailFetchInFlight", Html, StringComparison.Ordinal);
        Assert.Contains("startDetailAutoRefresh", Html, StringComparison.Ordinal);
        Assert.Contains("stopDetailAutoRefresh", Html, StringComparison.Ordinal);
        Assert.Contains("document.addEventListener('visibilitychange'", Html, StringComparison.Ordinal);
        Assert.Contains("document.visibilityState==='visible'", Html, StringComparison.Ordinal);
        Assert.Contains("数据采集时间", Html, StringComparison.Ordinal);
        Assert.Contains("页面刷新时间", Html, StringComparison.Ordinal);
        Assert.Contains("数据已陈旧", Html, StringComparison.Ordinal);
    }

    [Fact]
    public void Existing_search_filter_refresh_and_remote_commands_remain_available()
    {
        Assert.Contains("id=\"search\"", Html, StringComparison.Ordinal);
        Assert.Contains("id=\"state\"", Html, StringComparison.Ordinal);
        Assert.Contains("id=\"refreshList\"", Html, StringComparison.Ordinal);
        Assert.Contains("createCommand('disableProxy')", Html, StringComparison.Ordinal);
        Assert.Contains("createCommand('enableProxy')", Html, StringComparison.Ordinal);
    }

    [Fact]
    public void Command_creation_is_confirmed_by_id_and_displays_lifecycle_and_audit_fields()
    {
        Assert.Contains("commandCreateInFlight", Html, StringComparison.Ordinal);
        Assert.Contains("created?.commandId", Html, StringComparison.Ordinal);
        Assert.Contains("confirmedCommand=commands.find", Html, StringComparison.Ordinal);
        Assert.Contains("命令已创建并确认，Command ID", Html, StringComparison.Ordinal);
        Assert.Contains("命令创建结果未确认", Html, StringComparison.Ordinal);
        Assert.Contains("/admin/v1/audit?deviceId=", Html, StringComparison.Ordinal);
        Assert.Contains("投递时间", Html, StringComparison.Ordinal);
        Assert.Contains("开始时间", Html, StringComparison.Ordinal);
        Assert.Contains("完成时间", Html, StringComparison.Ordinal);
        Assert.Contains("结果码", Html, StringComparison.Ordinal);
        Assert.Contains("投递次数", Html, StringComparison.Ordinal);
        Assert.Contains("命令审计", Html, StringComparison.Ordinal);
    }

    [Fact]
    public void Allowlist_editor_loads_saves_and_can_submit_an_explicit_empty_list()
    {
        Assert.Contains("id=\"allowlistHeading\"", Html, StringComparison.Ordinal);
        Assert.Contains("id=\"allowlistInput\"", Html, StringComparison.Ordinal);
        Assert.Contains("id=\"saveAllowlist\"", Html, StringComparison.Ordinal);
        Assert.Contains("api('/admin/v1/policy')", Html, StringComparison.Ordinal);
        Assert.Contains("allowlistedBaseUrls:allowlistDraft", Html, StringComparison.Ordinal);
        Assert.Contains("currentPolicy.allowlistedBaseUrls===null", Html, StringComparison.Ordinal);
        Assert.Contains("策略已被其他管理员更新", Html, StringComparison.Ordinal);
        Assert.DoesNotContain("CCR 不可删除", Html, StringComparison.Ordinal);
    }

    private static string ReadConsoleHtml()
    {
        var pageType = typeof(ControlStore).Assembly.GetType(
            "Sf.EndpointAI.ControlServer.ControlConsolePage",
            throwOnError: true)!;
        var htmlField = pageType.GetField(
            "Html",
            BindingFlags.Public | BindingFlags.Static);

        return Assert.IsType<string>(htmlField?.GetRawConstantValue());
    }
}
