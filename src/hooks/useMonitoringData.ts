import { useCallback, useEffect, useState } from "react";
import type {
  Alert,
  AppUsageEntry,
  InstalledProgram,
  ProcessMetric,
  ProcessNode,
  StartupProcess
} from "../types";
import type { RefreshSpeed } from "../components/ProcessTable";
import {
  addKnownProgram,
  deleteAlert,
  deleteAllAlerts,
  getActiveAlerts,
  getAppUsageHistory,
  getInstalledPrograms,
  getProcessMetrics,
  getProcessTree,
  getStartupProcesses
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
  const [isLoading, setIsLoading] = useState(true);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  const refresh = useCallback(async (includeProcesses: boolean) => {
    if (includeProcesses) {
      const [tree, metrics] = await Promise.all([getProcessTree(), getProcessMetrics()]);
      setProcessTree(tree);
      setProcessMetrics(metrics);
    }

    const [activeAlerts, installed, startup, history] = await Promise.all([
      getActiveAlerts(),
      getInstalledPrograms(),
      getStartupProcesses(),
      getAppUsageHistory()
    ]);
    setAlerts(activeAlerts);
    setPrograms(installed);
    setStartupProcesses(startup);
    setAppUsageHistory(history);
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

  return {
    processTree,
    processMetrics,
    alerts,
    programs,
    startupProcesses,
    appUsageHistory,
    isLoading,
    lastUpdated,
    refresh,
    onDeleteAlert,
    onDeleteAllAlerts,
    onAddKnownProgram
  };
}
