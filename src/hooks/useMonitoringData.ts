import { useCallback, useEffect, useState } from "react";
import type {
  Alert,
  AppUsageEntry,
  EventEnvelope,
  InstalledProgram,
  PerformanceStats,
  ResponseActionRecord,
  ResponsePolicy,
  ProcessMetric,
  ProcessNode,
  ResponseActionType,
  SensorHealth,
  StartupProcess
} from "../types";
import type { RefreshSpeed } from "../components/ProcessTable";
import {
  addKnownProgram,
  deleteAlert,
  deleteAllAlerts,
  getActiveAlerts,
  getAppUsageHistory,
  getEventTimeline,
  getInstalledPrograms,
  getPerformanceStats,
  getProcessMetrics,
  getProcessTree,
  getResponseActions,
  getResponsePolicy,
  getSensorHealth,
  getStartupProcesses,
  runResponseAction,
  setResponsePolicy
} from "../lib/api";

const refreshIntervals: Record<RefreshSpeed, number> = {
  very_low: 10000,
  low: 5000,
  normal: 2500,
  fast: 1000
};

export function useMonitoringData(options: {
  processRefreshPaused: boolean;
  refreshSpeed: RefreshSpeed;
}) {
  const { processRefreshPaused, refreshSpeed } = options;
  const [processTree, setProcessTree] = useState<ProcessNode[]>([]);
  const [processMetrics, setProcessMetrics] = useState<ProcessMetric[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [programs, setPrograms] = useState<InstalledProgram[]>([]);
  const [startupProcesses, setStartupProcesses] = useState<StartupProcess[]>([]);
  const [appUsageHistory, setAppUsageHistory] = useState<AppUsageEntry[]>([]);
  const [eventTimeline, setEventTimeline] = useState<EventEnvelope[]>([]);
  const [sensorHealth, setSensorHealth] = useState<SensorHealth[]>([]);
  const [performanceStats, setPerformanceStats] = useState<PerformanceStats>({
    loop_last_ms: 0,
    loop_avg_ms: 0,
    loop_p95_ms: 0,
    total_events: 0,
    event_store_size: 0,
    tracked_processes: 0
  });
  const [responsePolicy, setResponsePolicyState] = useState<ResponsePolicy>({
    mode: "audit",
    auto_constrain_threshold: 95,
    safe_mode: true,
    allow_terminate: false,
    cooldown_seconds: 180
  });
  const [responseActions, setResponseActions] = useState<ResponseActionRecord[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  const refresh = useCallback(async (includeProcesses: boolean) => {
    if (includeProcesses) {
      const [tree, metrics] = await Promise.all([getProcessTree(), getProcessMetrics()]);
      setProcessTree(tree);
      setProcessMetrics(metrics);
    }

    const [activeAlerts, installed, startup, history, timeline, health, perf, policy, actions] = await Promise.all([
      getActiveAlerts(),
      getInstalledPrograms(),
      getStartupProcesses(),
      getAppUsageHistory(),
      getEventTimeline({ limit: 250 }),
      getSensorHealth(),
      getPerformanceStats(),
      getResponsePolicy(),
      getResponseActions(200)
    ]);
    setAlerts(activeAlerts);
    setPrograms(installed);
    setStartupProcesses(startup);
    setAppUsageHistory(history);
    setEventTimeline(timeline);
    setSensorHealth(health);
    setPerformanceStats(perf);
    setResponsePolicyState(policy);
    setResponseActions(actions);
    setLastUpdated(new Date());
  }, []);

  useEffect(() => {
    let mounted = true;

    const run = async () => {
      try {
        await refresh(!processRefreshPaused);
      } finally {
        if (mounted) {
          setIsLoading(false);
        }
      }
    };

    run();
    const timer = window.setInterval(run, refreshIntervals[refreshSpeed]);
    return () => {
      mounted = false;
      window.clearInterval(timer);
    };
  }, [refresh, processRefreshPaused, refreshSpeed]);

  const onDeleteAlert = useCallback(async (alertId: string) => {
    setAlerts((prev) => prev.filter((item) => item.id !== alertId));
    await deleteAlert(alertId);
    const active = await getActiveAlerts();
    setAlerts(active);
  }, []);

  const onDeleteAllAlerts = useCallback(async () => {
    setAlerts([]);
    await deleteAllAlerts();
    const active = await getActiveAlerts();
    setAlerts(active);
  }, []);

  const onAddKnownProgram = useCallback(
    async (program: InstalledProgram, label: string) => {
      const changed = await addKnownProgram({
        executablePath: program.executable_path,
        installLocation: program.install_location,
        name: program.name,
        label
      });
      if (changed) {
        await refresh(true);
      }
    },
    [refresh]
  );

  const onSetResponsePolicy = useCallback(async (policy: ResponsePolicy) => {
    await setResponsePolicy(policy);
    const latest = await getResponsePolicy();
    setResponsePolicyState(latest);
  }, []);

  const onRunResponseAction = useCallback(
    async (payload: { pid: number; actionType: ResponseActionType; reason?: string }) => {
      await runResponseAction(payload);
      const [actions, activeAlerts] = await Promise.all([
        getResponseActions(200),
        getActiveAlerts()
      ]);
      setResponseActions(actions);
      setAlerts(activeAlerts);
    },
    []
  );

  return {
    processTree,
    processMetrics,
    alerts,
    programs,
    startupProcesses,
    appUsageHistory,
    eventTimeline,
    sensorHealth,
    performanceStats,
    responsePolicy,
    responseActions,
    isLoading,
    lastUpdated,
    refresh,
    onDeleteAlert,
    onDeleteAllAlerts,
    onAddKnownProgram,
    onSetResponsePolicy,
    onRunResponseAction
  };
}
