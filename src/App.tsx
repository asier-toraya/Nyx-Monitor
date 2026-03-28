import {
  Suspense,
  lazy,
  useCallback,
  useEffect,
  useMemo,
  useState,
  type ReactNode
} from "react";
import { AlertsPanel } from "./components/AlertsPanel";
import nyxLogo from "./assets/nyx-logo.svg";
import { ProcessDetailsDialog } from "./components/ProcessDetailsDialog";
import { StatCard } from "./components/StatCard";
import type { RefreshSpeed } from "./components/ProcessTable";
import {
  getFileSha256,
  openProcessFolderByPid,
  openPathInExplorer,
  openUrlInBrowser,
  setDetectionProfile,
  setProcessTrustOverride
} from "./lib/api";
import { buildVirusTotalSearchUrl } from "./lib/externalLinks";
import { formatPercent } from "./lib/format";
import { useMonitoringData } from "./hooks/useMonitoringData";
import type { DetectionProfile, ProcessMetric, TrustLevel } from "./types";

type Tab =
  | "overview"
  | "processes"
  | "timeline"
  | "health"
  | "response"
  | "threats"
  | "alerts"
  | "programs"
  | "startup"
  | "history";

type ThemeMode = "dark" | "light";

type TabConfig = {
  id: Tab;
  label: string;
  hint: string;
  heading?: string;
};

const tabs: TabConfig[] = [
  { id: "overview", label: "Overview", hint: "Pulse and usage", heading: "System Pulse" },
  { id: "processes", label: "Processes", hint: "Live process intelligence" },
  { id: "timeline", label: "Timeline", hint: "Event stream and evidence" },
  { id: "health", label: "Health", hint: "Sensors and performance" },
  { id: "response", label: "Response", hint: "Policy and actions" },
  { id: "threats", label: "Threats", hint: "Risk-ranked entities" },
  { id: "alerts", label: "Alerts", hint: "Operational incidents" },
  { id: "programs", label: "Installed", hint: "Software inventory" },
  { id: "startup", label: "Startup", hint: "Boot-time entries" },
  { id: "history", label: "History", hint: "Usage timeline" }
];

const profileOptions: DetectionProfile[] = ["conservative", "balanced", "aggressive"];

const UsageChart = lazy(() =>
  import("./components/UsageChart").then((module) => ({ default: module.UsageChart }))
);
const ProcessTree = lazy(() =>
  import("./components/ProcessTree").then((module) => ({ default: module.ProcessTree }))
);
const ProcessTable = lazy(() =>
  import("./components/ProcessTable").then((module) => ({ default: module.ProcessTable }))
);
const ThreatsTable = lazy(() =>
  import("./components/ThreatsTable").then((module) => ({ default: module.ThreatsTable }))
);
const InstalledProgramsTable = lazy(() =>
  import("./components/InstalledProgramsTable").then((module) => ({
    default: module.InstalledProgramsTable
  }))
);
const StartupProcessesTable = lazy(() =>
  import("./components/StartupProcessesTable").then((module) => ({
    default: module.StartupProcessesTable
  }))
);
const AppUsageHistoryTable = lazy(() =>
  import("./components/AppUsageHistoryTable").then((module) => ({
    default: module.AppUsageHistoryTable
  }))
);
const EventTimelineTable = lazy(() =>
  import("./components/EventTimelineTable").then((module) => ({
    default: module.EventTimelineTable
  }))
);
const HealthPanel = lazy(() =>
  import("./components/HealthPanel").then((module) => ({
    default: module.HealthPanel
  }))
);
const ResponsePanel = lazy(() =>
  import("./components/ResponsePanel").then((module) => ({
    default: module.ResponsePanel
  }))
);

function TabSection({
  children,
  className = "single"
}: {
  children: ReactNode;
  className?: string;
}) {
  return <section className={className}>{children}</section>;
}

function LazyTabSection({
  children,
  fallback,
  className = "single"
}: {
  children: ReactNode;
  fallback: string;
  className?: string;
}) {
  return (
    <TabSection className={className}>
      <Suspense fallback={<p className="loading">{fallback}</p>}>{children}</Suspense>
    </TabSection>
  );
}

export default function App() {
  const [activeTab, setActiveTab] = useState<Tab>("overview");
  const [profile, setProfile] = useState<DetectionProfile>("conservative");
  const [theme, setTheme] = useState<ThemeMode>(() => {
    const preferred = localStorage.getItem("nyx-monitor-theme");
    return preferred === "light" ? "light" : "dark";
  });
  const [processRefreshPaused, setProcessRefreshPaused] = useState(false);
  const [refreshSpeed, setRefreshSpeed] = useState<RefreshSpeed>("normal");
  const [selectedProcess, setSelectedProcess] = useState<ProcessMetric | null>(null);
  const [selectedProcessHash, setSelectedProcessHash] = useState("");
  const [isHashLoading, setIsHashLoading] = useState(false);

  const {
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
  } = useMonitoringData({
    processRefreshPaused,
    refreshSpeed
  });

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem("nyx-monitor-theme", theme);
  }, [theme]);

  const totalCpu = useMemo(
    () => processMetrics.reduce((acc, item) => acc + item.cpu_pct, 0),
    [processMetrics]
  );
  const topCpu = useMemo(
    () => [...processMetrics].sort((a, b) => b.cpu_pct - a.cpu_pct)[0],
    [processMetrics]
  );
  const suspiciousCount = useMemo(
    () => processMetrics.filter((item) => item.suspicion.level === "suspicious").length,
    [processMetrics]
  );
  const processByPid = useMemo(() => {
    return new Map<number, ProcessMetric>(processMetrics.map((item) => [item.pid, item]));
  }, [processMetrics]);
  const activeTabConfig = useMemo(() => {
    return tabs.find((tab) => tab.id === activeTab) ?? tabs[0];
  }, [activeTab]);
  const selectedParentProcess = useMemo(() => {
    if (!selectedProcess?.ppid) {
      return null;
    }

    return processByPid.get(selectedProcess.ppid) ?? null;
  }, [selectedProcess, processByPid]);
  const selectedParentInfo = useMemo(() => {
    if (!selectedProcess?.ppid) {
      return null;
    }

    return {
      pid: selectedProcess.ppid,
      name: selectedParentProcess?.name,
      exe_path: selectedParentProcess?.exe_path
    };
  }, [selectedProcess, selectedParentProcess]);
  const overviewAlerts = useMemo(() => alerts.slice(0, 5), [alerts]);

  useEffect(() => {
    if (!selectedProcess) {
      return;
    }

    const refreshed = processByPid.get(selectedProcess.pid);
    if (refreshed) {
      setSelectedProcess(refreshed);
    }
  }, [processByPid, selectedProcess?.pid]);

  const onProfileChange = useCallback(async (nextProfile: DetectionProfile) => {
    setProfile(nextProfile);
    await setDetectionProfile(nextProfile);
  }, []);

  const onOpenPath = useCallback(async (path?: string) => {
    if (!path) {
      return;
    }

    await openPathInExplorer(path);
  }, []);

  const onOpenExternalUrl = useCallback(async (url: string) => {
    if (!url) {
      return;
    }

    const opened = await openUrlInBrowser(url);
    if (!opened) {
      window.open(url, "_blank", "noopener,noreferrer");
    }
  }, []);

  const openProcessDialog = useCallback(
    (processItem: { pid: number }) => {
      const processDetails = processByPid.get(processItem.pid) ?? null;
      setSelectedProcess(processDetails);
      setSelectedProcessHash("");
    },
    [processByPid]
  );

  const closeProcessDialog = useCallback(() => {
    setSelectedProcess(null);
    setSelectedProcessHash("");
    setIsHashLoading(false);
  }, []);

  const saveProcessTrust = useCallback(
    async (payload: { trustLevel: TrustLevel; label?: string }) => {
      if (!selectedProcess) {
        return;
      }

      await setProcessTrustOverride({
        path: selectedProcess.exe_path,
        name: selectedProcess.name,
        trustLevel: payload.trustLevel,
        label: payload.label
      });
      setSelectedProcess((previous) =>
        previous
          ? {
              ...previous,
              trust_level: payload.trustLevel,
              trust_label: payload.label
            }
          : previous
      );
      await refresh(true);
    },
    [refresh, selectedProcess]
  );

  const calculateProcessHash = useCallback(async () => {
    if (!selectedProcess?.exe_path) {
      setSelectedProcessHash("");
      return;
    }

    setIsHashLoading(true);
    try {
      const hash = await getFileSha256(selectedProcess.exe_path);
      setSelectedProcessHash(hash ?? "");
    } catch (error) {
      console.error("Failed to calculate process hash", error);
      setSelectedProcessHash("");
    } finally {
      setIsHashLoading(false);
    }
  }, [selectedProcess]);

  const searchSelectedProcessInVirusTotal = useCallback(async () => {
    if (!selectedProcess) {
      return;
    }

    const query = selectedProcessHash || selectedProcess.name;
    await onOpenExternalUrl(buildVirusTotalSearchUrl(query));
  }, [selectedProcess, selectedProcessHash, onOpenExternalUrl]);

  const searchSelectedProcessInGoogle = useCallback(async () => {
    if (!selectedProcess) {
      return;
    }

    await onOpenExternalUrl(
      `https://www.google.com/search?q=${encodeURIComponent(`${selectedProcess.name} process`)}`
    );
  }, [selectedProcess, onOpenExternalUrl]);

  const openSelectedProcessPath = useCallback(async () => {
    if (!selectedProcess?.exe_path) {
      return;
    }

    await onOpenPath(selectedProcess.exe_path);
  }, [selectedProcess, onOpenPath]);

  const openSelectedParentPath = useCallback(async () => {
    if (!selectedParentInfo?.pid) {
      return;
    }

    await openProcessFolderByPid(selectedParentInfo.pid);
  }, [selectedParentInfo]);

  const toggleTheme = useCallback(() => {
    setTheme((previous) => (previous === "dark" ? "light" : "dark"));
  }, []);

  const toggleProcessRefresh = useCallback(() => {
    setProcessRefreshPaused((previous) => !previous);
  }, []);

  const renderOverviewTab = () => {
    return (
      <TabSection className="grid">
        <StatCard
          title="Running Processes"
          value={`${processMetrics.length}`}
          hint="Current process count"
        />
        <StatCard
          title="Active Alerts"
          value={`${alerts.length}`}
          hint="Incidents pending review"
          tone={alerts.length > 0 ? "warn" : "neutral"}
        />
        <StatCard
          title="Suspicious Processes"
          value={`${suspiciousCount}`}
          hint="Processes tagged as suspicious"
          tone={suspiciousCount > 0 ? "critical" : "neutral"}
        />
        <StatCard
          title="Top CPU Process"
          value={topCpu ? topCpu.name : "-"}
          hint={topCpu ? `Current load ${formatPercent(topCpu.cpu_pct)}` : "No process data"}
        />
        <Suspense fallback={<p className="loading">Rendering chart...</p>}>
          <UsageChart metrics={processMetrics} />
        </Suspense>
        <AlertsPanel
          alerts={overviewAlerts}
          onDelete={onDeleteAlert}
          onDeleteAll={onDeleteAllAlerts}
        />
      </TabSection>
    );
  };

  const renderActiveTabContent = () => {
    switch (activeTab) {
      case "overview":
        return renderOverviewTab();
      case "processes":
        return (
          <LazyTabSection
            className="split split--processes"
            fallback="Loading process intelligence modules..."
          >
            <ProcessTree
              tree={processTree}
              onProcessClick={openProcessDialog}
              onOpenExternalUrl={onOpenExternalUrl}
            />
            <ProcessTable
              metrics={processMetrics}
              paused={processRefreshPaused}
              speed={refreshSpeed}
              onTogglePause={toggleProcessRefresh}
              onSpeedChange={setRefreshSpeed}
              onProcessClick={openProcessDialog}
              onOpenExternalUrl={onOpenExternalUrl}
            />
          </LazyTabSection>
        );
      case "threats":
        return (
          <LazyTabSection fallback="Loading threat matrix...">
            <ThreatsTable metrics={processMetrics} onProcessClick={openProcessDialog} />
          </LazyTabSection>
        );
      case "timeline":
        return (
          <LazyTabSection fallback="Loading event timeline...">
            <EventTimelineTable events={eventTimeline} />
          </LazyTabSection>
        );
      case "health":
        return (
          <LazyTabSection fallback="Loading sensor health...">
            <HealthPanel sensors={sensorHealth} performance={performanceStats} />
          </LazyTabSection>
        );
      case "response":
        return (
          <LazyTabSection fallback="Loading response controls...">
            <ResponsePanel
              policy={responsePolicy}
              actions={responseActions}
              processes={processMetrics}
              onSavePolicy={onSetResponsePolicy}
              onRunAction={onRunResponseAction}
            />
          </LazyTabSection>
        );
      case "alerts":
        return (
          <TabSection>
            <AlertsPanel
              alerts={alerts}
              onDelete={onDeleteAlert}
              onDeleteAll={onDeleteAllAlerts}
            />
          </TabSection>
        );
      case "programs":
        return (
          <LazyTabSection fallback="Loading software inventory...">
            <InstalledProgramsTable
              programs={programs}
              onOpenPath={onOpenPath}
              onAddKnownProgram={onAddKnownProgram}
              onOpenExternalUrl={onOpenExternalUrl}
            />
          </LazyTabSection>
        );
      case "startup":
        return (
          <LazyTabSection fallback="Loading startup map...">
            <StartupProcessesTable processes={startupProcesses} onOpenPath={onOpenPath} />
          </LazyTabSection>
        );
      case "history":
        return (
          <LazyTabSection fallback="Loading usage history...">
            <AppUsageHistoryTable entries={appUsageHistory} onOpenPath={onOpenPath} />
          </LazyTabSection>
        );
    }
  };

  return (
    <div className="app-shell">
      <aside className="nav-rail">
        <div className="brand-block">
          <div className="brand-mark" aria-hidden>
            <img src={nyxLogo} alt="" />
          </div>
          <div>
            <p className="brand-kicker">Security Telemetry</p>
            <h1>Nyx Monitor</h1>
          </div>
        </div>

        <nav className="rail-tabs" aria-label="Main navigation tabs">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              className={`rail-tab ${activeTab === tab.id ? "rail-tab--active" : ""}`}
              onClick={() => setActiveTab(tab.id)}
            >
              <span>{tab.label}</span>
              <small>{tab.hint}</small>
            </button>
          ))}
        </nav>

        <div className="rail-footnote">
          <p>Profile</p>
          <select
            value={profile}
            onChange={(event) => onProfileChange(event.target.value as DetectionProfile)}
          >
            {profileOptions.map((option) => (
              <option key={option} value={option}>
                {option.charAt(0).toUpperCase() + option.slice(1)}
              </option>
            ))}
          </select>
        </div>
      </aside>

      <main className="workspace">
        <header className="command-deck">
          <div>
            <p className="eyebrow">Operational Command Deck</p>
            <h2>{activeTabConfig.heading ?? activeTabConfig.label}</h2>
            <p className="subtitle">
              Real-time visibility over running processes, trust posture, and suspicious behavior
              analysis.
            </p>
          </div>
          <div className="command-deck__meta">
            <p>
              {lastUpdated
                ? `Updated ${lastUpdated.toLocaleTimeString()}`
                : "Synchronizing telemetry..."}
            </p>
            <button className="btn btn--small" onClick={toggleTheme}>
              {theme === "dark" ? "Switch to light" : "Switch to dark"}
            </button>
          </div>
        </header>

        <section className="signal-strip" aria-label="Quick health status">
          <div className="signal-chip">
            <span>Processes</span>
            <strong>{processMetrics.length}</strong>
          </div>
          <div className="signal-chip signal-chip--warn">
            <span>Alerts</span>
            <strong>{alerts.length}</strong>
          </div>
          <div className="signal-chip signal-chip--critical">
            <span>Suspicious</span>
            <strong>{suspiciousCount}</strong>
          </div>
          <div className="signal-chip">
            <span>Total CPU</span>
            <strong>{formatPercent(totalCpu)}</strong>
          </div>
        </section>

        {isLoading ? <p className="loading">Collecting live telemetry...</p> : null}
        {renderActiveTabContent()}
      </main>

      <ProcessDetailsDialog
        process={selectedProcess}
        parentInfo={selectedParentInfo}
        hashValue={selectedProcessHash}
        isHashLoading={isHashLoading}
        onClose={closeProcessDialog}
        onSaveTrust={saveProcessTrust}
        onCalculateHash={calculateProcessHash}
        onSearchVirusTotal={searchSelectedProcessInVirusTotal}
        onSearchGoogle={searchSelectedProcessInGoogle}
        onOpenPath={openSelectedProcessPath}
        onOpenParentPath={openSelectedParentPath}
      />
    </div>
  );
}
