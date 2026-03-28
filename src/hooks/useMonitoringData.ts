import { useCallback, useEffect, useRef, useState } from "react";
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

const operationalRefreshIntervalMs = 5000;
const inventoryRefreshIntervalMs = 60000;

export function useMonitoringData(options: {
  processRefreshPaused: boolean;
  refreshSpeed: RefreshSpeed;
}) {
  const { processRefreshPaused, refreshSpeed } = options;
  const hasInitialized = useRef(false);
  const snapshotRefreshInFlight = useRef(false);
  const operationalRefreshInFlight = useRef(false);
  const inventoryRefreshInFlight = useRef(false);
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

  const refreshProcessSnapshot = useCallback(async () => {
    if (snapshotRefreshInFlight.current) {
      return;
    }

    snapshotRefreshInFlight.current = true;
    try {
      const [tree, metrics] = await Promise.all([getProcessTree(), getProcessMetrics()]);
      setProcessTree(tree);
      setProcessMetrics(metrics);
      setLastUpdated(new Date());
    } finally {
      snapshotRefreshInFlight.current = false;
    }
  }, []);

  const refreshOperationalData = useCallback(async () => {
    if (operationalRefreshInFlight.current) {
      return;
    }

    operationalRefreshInFlight.current = true;
    try {
      const [activeAlerts, history, timeline, health, perf, actions] = await Promise.all([
        getActiveAlerts(),
        getAppUsageHistory(),
        getEventTimeline({ limit: 250 }),
        getSensorHealth(),
        getPerformanceStats(),
        getResponseActions(200)
      ]);
      setAlerts(activeAlerts);
      setAppUsageHistory(history);
      setEventTimeline(timeline);
      setSensorHealth(health);
      setPerformanceStats(perf);
      setResponseActions(actions);
      setLastUpdated(new Date());
    } finally {
      operationalRefreshInFlight.current = false;
    }
  }, []);

  const refreshInventoryData = useCallback(async () => {
    if (inventoryRefreshInFlight.current) {
      return;
    }

    inventoryRefreshInFlight.current = true;
    try {
      const [installed, startup] = await Promise.all([
        getInstalledPrograms(),
        getStartupProcesses()
      ]);
      setPrograms(installed);
      setStartupProcesses(startup);
    } finally {
      inventoryRefreshInFlight.current = false;
    }
  }, []);

  const refreshResponsePolicy = useCallback(async () => {
    const policy = await getResponsePolicy();
    setResponsePolicyState(policy);
  }, []);

  const refresh = useCallback(
    async (includeProcesses: boolean) => {
      const tasks: Promise<void>[] = [refreshOperationalData()];
      if (includeProcesses) {
        tasks.push(refreshProcessSnapshot());
      }
      await Promise.all(tasks);
    },
    [refreshOperationalData, refreshProcessSnapshot]
  );

  useEffect(() => {
    if (hasInitialized.current) {
      return;
    }

    hasInitialized.current = true;
    let cancelled = false;

    const loadInitialData = async () => {
      try {
        const tasks: Promise<void>[] = [
          refreshOperationalData(),
          refreshInventoryData(),
          refreshResponsePolicy()
        ];
        if (!processRefreshPaused) {
          tasks.push(refreshProcessSnapshot());
        }
        await Promise.all(tasks);
      } finally {
        if (!cancelled) {
          setIsLoading(false);
        }
      }
    };

    loadInitialData();

    return () => {
      cancelled = true;
    };
  }, [
    processRefreshPaused,
    refreshInventoryData,
    refreshOperationalData,
    refreshProcessSnapshot,
    refreshResponsePolicy
  ]);

  useEffect(() => {
    if (processRefreshPaused) {
      return;
    }

    let cancelled = false;
    let timer: number | undefined;

    const schedule = () => {
      timer = window.setTimeout(async () => {
        await refreshProcessSnapshot();
        if (!cancelled) {
          schedule();
        }
      }, refreshIntervals[refreshSpeed]);
    };

    schedule();

    return () => {
      cancelled = true;
      if (timer !== undefined) {
        window.clearTimeout(timer);
      }
    };
  }, [processRefreshPaused, refreshProcessSnapshot, refreshSpeed]);

  useEffect(() => {
    let cancelled = false;
    let timer: number | undefined;

    const schedule = () => {
      timer = window.setTimeout(async () => {
        await refreshOperationalData();
        if (!cancelled) {
          schedule();
        }
      }, operationalRefreshIntervalMs);
    };

    schedule();

    return () => {
      cancelled = true;
      if (timer !== undefined) {
        window.clearTimeout(timer);
      }
    };
  }, [refreshOperationalData]);

  useEffect(() => {
    let cancelled = false;
    let timer: number | undefined;

    const schedule = () => {
      timer = window.setTimeout(async () => {
        await refreshInventoryData();
        if (!cancelled) {
          schedule();
        }
      }, inventoryRefreshIntervalMs);
    };

    schedule();

    return () => {
      cancelled = true;
      if (timer !== undefined) {
        window.clearTimeout(timer);
      }
    };
  }, [refreshInventoryData]);

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
        await refreshInventoryData();
      }
    },
    [refreshInventoryData]
  );

  const onSetResponsePolicy = useCallback(async (policy: ResponsePolicy) => {
    await setResponsePolicy(policy);
    await refreshResponsePolicy();
  }, [refreshResponsePolicy]);

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
